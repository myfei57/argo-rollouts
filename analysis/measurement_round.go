package analysis

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-rollouts/metric"
	"github.com/argoproj/argo-rollouts/metric/measurementround"
	"github.com/argoproj/argo-rollouts/metricproviders"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	logutil "github.com/argoproj/argo-rollouts/utils/log"
	metricutil "github.com/argoproj/argo-rollouts/utils/metric"
	timeutil "github.com/argoproj/argo-rollouts/utils/time"
)

// prepareMeasurementRound restores the latest still-open round (so resumes, retries and
// controller restarts replay the same fixed evaluation time) or opens a new round with a
// fresh cut point. Rounds built for a different spec digest or rollout revision are
// invalidated and cannot advance the current analysis.
func (c *Controller) prepareMeasurementRound(run *v1alpha1.AnalysisRun, cfg measurementround.Config) (*measurementround.Round, error) {
	resolvedMetrics, err := getResolvedMetricsWithoutSecrets(run.Spec.Metrics, run.Spec.Args)
	if err != nil {
		return nil, err
	}
	digest, err := measurementround.SpecDigest(resolvedMetrics)
	if err != nil {
		return nil, err
	}
	revision := run.Annotations[measurementround.RevisionAnnotationKey]
	required := make([]string, 0, len(resolvedMetrics))
	for _, m := range resolvedMetrics {
		required = append(required, m.Name)
	}

	if rc, seed, ok := measurementround.LatestOpenRound(run); ok {
		restored := measurementround.RestoreRound(rc, required, cfg, seed...)
		if advanceErr := restored.Advanceable(digest, revision); advanceErr != nil {
			logutil.WithAnalysisRun(run).WithFields(rc.SafeFields()).
				Warnf("Discarding measurement round that cannot advance the current analysis: %v", advanceErr)
			invalidateStaleRound(run, rc.ID, advanceErr)
		} else {
			logutil.WithAnalysisRun(run).WithFields(rc.SafeFields()).
				Info("Resuming measurement round at its fixed evaluation time")
			return restored, nil
		}
	}

	// The cut point is fixed once, before any parallel query is issued.
	return measurementround.NewRound(cfg, run, resolvedMetrics, timeutil.Now())
}

// runRoundMeasurement executes one task through the round protocol. Providers lacking the
// FixedTimeProvider capability fail explicitly with ErrFixedTimeUnsupported instead of
// silently querying wall-clock now.
func runRoundMeasurement(ctx context.Context, run *v1alpha1.AnalysisRun, t metricTask, provider metric.Provider, round *measurementround.Round, terminating bool, logger *log.Entry) v1alpha1.Measurement {
	rc := round.RoundContext
	identity := roundIdentityFor(rc, t.metric)

	baseMeasurement := func() v1alpha1.Measurement {
		if t.incompleteMeasurement != nil {
			return *t.incompleteMeasurement
		}
		startedAt := timeutil.MetaNow()
		return v1alpha1.Measurement{StartedAt: &startedAt}
	}

	fixedTimeProvider, ok := provider.(metric.FixedTimeProvider)
	if !ok {
		m := metricutil.MarkMeasurementError(baseMeasurement(), measurementround.ErrFixedTimeUnsupported)
		// Record the explicit failure so the round accounts for the metric confirmation.
		if _, observeErr := round.Observe(measurementround.Observation{
			MetricName: t.metric.Name,
			Identity:   identity,
			Status:     measurementround.MetricStatusFailed,
			Message:    m.Message,
			Bytes:      measurementBytes(m),
		}); observeErr != nil {
			logger.WithError(observeErr).Warn("failed to record unsupported-provider observation")
		}
		return stampRoundMetadata(m, round, identity)
	}

	if t.incompleteMeasurement != nil && terminating {
		logger.Infof("Terminating in-progress measurement")
		return provider.Terminate(run, t.metric, *t.incompleteMeasurement)
	}

	var produced v1alpha1.Measurement
	obs, runErr := round.Run(ctx, t.metric.Name, identity, func(ctx context.Context) (measurementround.Result, error) {
		// Resume and retry both re-issue the query against the same fixed evaluation time.
		produced = fixedTimeProvider.RunAt(ctx, run, t.metric, rc)
		result := measurementround.Result{
			Bytes:   measurementBytes(produced),
			Message: produced.Message,
		}
		if raw := produced.Metadata[measurementround.MetadataKeySampleStart]; raw != "" {
			if ts, parseErr := time.Parse(time.RFC3339Nano, raw); parseErr == nil {
				result.SampleStart = ts
			}
		}
		if raw := produced.Metadata[measurementround.MetadataKeySampleEnd]; raw != "" {
			if ts, parseErr := time.Parse(time.RFC3339Nano, raw); parseErr == nil {
				result.SampleEnd = ts
			}
		}
		if raw := produced.Metadata[measurementround.MetadataKeySampleStep]; raw != "" {
			if d, parseErr := time.ParseDuration(raw); parseErr == nil {
				result.SampleStep = d
			}
		}
		status := measurementround.MetricStatus(produced.Metadata[measurementround.MetadataKeyMetricStatus])
		if produced.Phase == v1alpha1.AnalysisPhaseError {
			if status == "" {
				status = measurementround.MetricStatusFailed
			}
			result.Status = status
			return result, errors.New(produced.Message)
		}
		result.Status = status
		return result, nil
	})

	if runErr != nil {
		if errors.Is(runErr, measurementround.ErrDuplicateResponse) && t.incompleteMeasurement != nil {
			// A terminal response for this round identity was already recorded; keep it.
			return *t.incompleteMeasurement
		}
		m := baseMeasurement()
		if errors.Is(runErr, measurementround.ErrRoundCancelled) {
			// The query never started because the round was cancelled.
			m.Phase = v1alpha1.AnalysisPhaseError
			m.Message = runErr.Error()
			finishedAt := timeutil.MetaNow()
			m.FinishedAt = &finishedAt
		} else {
			m = metricutil.MarkMeasurementError(m, runErr)
		}
		return stampRoundMetadata(m, round, identity)
	}

	// The recorded observation is authoritative: the byte budget may have downgraded the
	// result to a failure after the provider returned successfully.
	if obs.Status == measurementround.MetricStatusFailed && produced.Phase != v1alpha1.AnalysisPhaseError {
		produced = metricutil.MarkMeasurementError(produced, errors.New(obs.Message))
	}
	produced.Metadata = mergeRoundMetadata(produced.Metadata, round.MetadataFor(obs))
	return produced
}

// roundIdentityFor derives the per-metric response identity, binding the round, metric name,
// provider type and the concrete resolved query together.
func roundIdentityFor(rc measurementround.RoundContext, m v1alpha1.Metric) string {
	query := ""
	if m.Provider.Prometheus != nil {
		query = m.Provider.Prometheus.Query
	}
	return rc.Identity(m.Name, metricproviders.Type(m)+"|"+query)
}

// measurementBytes estimates the persisted size of a measurement including its metadata.
func measurementBytes(m v1alpha1.Measurement) int {
	n := len(m.Value) + len(m.Message) + len(m.Phase)
	for k, v := range m.Metadata {
		n += len(k) + len(v)
	}
	return n
}

func stampRoundMetadata(m v1alpha1.Measurement, round *measurementround.Round, identity string) v1alpha1.Measurement {
	if m.Metadata == nil {
		m.Metadata = map[string]string{}
	}
	for k, v := range round.RoundContext.Metadata() {
		m.Metadata[k] = v
	}
	m.Metadata[measurementround.MetadataKeyIdentity] = identity
	if m.Metadata[measurementround.MetadataKeyMetricStatus] == "" {
		m.Metadata[measurementround.MetadataKeyMetricStatus] = string(measurementround.MetricStatusFailed)
	}
	return m
}

func mergeRoundMetadata(existing map[string]string, roundMetadata map[string]string) map[string]string {
	if existing == nil {
		existing = map[string]string{}
	}
	for k, v := range roundMetadata {
		existing[k] = v
	}
	return existing
}

// invalidateStaleRound marks every measurement of a round which can no longer advance the
// analysis as failed and aborts the round.
func invalidateStaleRound(run *v1alpha1.AnalysisRun, roundID string, reason error) {
	for i := range run.Status.MetricResults {
		result := &run.Status.MetricResults[i]
		for j := range result.Measurements {
			measurement := &result.Measurements[j]
			rc, ok := measurementround.RoundFromMetadata(measurement.Metadata)
			if !ok || rc.ID != roundID {
				continue
			}
			*measurement = metricutil.MarkMeasurementError(*measurement, reason)
			measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(measurementround.MetricStatusFailed)
			measurement.Metadata[measurementround.MetadataKeyRoundPhase] = string(measurementround.RoundPhaseAborted)
		}
	}
}

// publishRoundComplete flips the round phase on every measurement belonging to the round.
// It is only called after the round confirmed all required metrics.
func publishRoundComplete(run *v1alpha1.AnalysisRun, roundID string) {
	for i := range run.Status.MetricResults {
		result := &run.Status.MetricResults[i]
		for j := range result.Measurements {
			md := result.Measurements[j].Metadata
			rc, ok := measurementround.RoundFromMetadata(md)
			if !ok || rc.ID != roundID {
				continue
			}
			md[measurementround.MetadataKeyRoundPhase] = string(measurementround.RoundPhaseComplete)
		}
	}
}
