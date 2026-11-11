package prometheus

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"github.com/argoproj/argo-rollouts/metric/measurementround"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/argoproj/argo-rollouts/utils/evaluate"
	metricutil "github.com/argoproj/argo-rollouts/utils/metric"
	timeutil "github.com/argoproj/argo-rollouts/utils/time"
)

// sampleWindow records the exact interval sent to Prometheus for a range query so it can be
// persisted on the Measurement as the sample interval used by the round.
type sampleWindow struct {
	start time.Time
	end   time.Time
	step  time.Duration
}

// RunAt implements metric.FixedTimeProvider. Instant queries are pinned to the round's fixed
// evaluation time and range queries are evaluated against that same time and snapped to an
// exact step grid, so Resume and retry attempts issue byte-identical requests.
//
// The shared evaluation time does not make responses from different Prometheus backends an
// atomic database snapshot; it only guarantees every query in the round observes the same
// cut point.
func (p *Provider) RunAt(ctx context.Context, run *v1alpha1.AnalysisRun, metric v1alpha1.Metric, rc measurementround.RoundContext) v1alpha1.Measurement {
	startTime := timeutil.MetaNow()
	measurement := v1alpha1.Measurement{
		StartedAt: &startTime,
		Metadata:  rc.Metadata(),
	}

	queryCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	response, warnings, window, err := p.executeQueryAt(queryCtx, metric, rc)
	if err != nil {
		measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(roundErrorStatus(err))
		return metricutil.MarkMeasurementError(measurement, err)
	}

	newValue, newStatus, err := p.processResponse(metric, response)
	if err != nil {
		measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(measurementround.MetricStatusFailed)
		return metricutil.MarkMeasurementError(measurement, err)
	}
	measurement.Value = newValue

	metricStatus := measurementround.MetricStatusComplete
	if len(warnings) > 0 {
		metricStatus = measurementround.MetricStatusPartial
		warningMetadata := ""
		for _, warning := range warnings {
			warningMetadata = fmt.Sprintf(`%s"%s", `, warningMetadata, warning)
		}
		warningMetadata = warningMetadata[:len(warningMetadata)-2]
		if warningMetadata != "" {
			measurement.Metadata["warnings"] = warningMetadata
			// Only round identity and warning text are logged; authentication material and
			// request parameters carrying secrets are never part of these fields.
			p.logCtx.WithFields(rc.SafeFields()).Warnf("Prometheus returned warnings for metric %q: %s", metric.Name, warningMetadata)
		}
	}

	measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(metricStatus)
	measurement.Metadata[measurementround.MetadataKeyIdentity] = rc.Identity(metric.Name, metric.Provider.Prometheus.Query)
	if window != nil {
		measurement.Metadata[measurementround.MetadataKeySampleStart] = window.start.UTC().Format(time.RFC3339Nano)
		measurement.Metadata[measurementround.MetadataKeySampleEnd] = window.end.UTC().Format(time.RFC3339Nano)
		measurement.Metadata[measurementround.MetadataKeySampleStep] = window.step.String()
	}

	measurement.Phase = newStatus
	finishedTime := timeutil.MetaNow()
	measurement.FinishedAt = &finishedTime
	return measurement
}

func roundErrorStatus(err error) measurementround.MetricStatus {
	if errors.Is(err, context.DeadlineExceeded) {
		return measurementround.MetricStatusTimeout
	}
	return measurementround.MetricStatusFailed
}

// executeQueryAt performs the backend call against the round cut point. Range expressions
// resolve now() to the fixed evaluation time and the resulting window is aligned to the
// configured step grid before the request is sent.
func (p *Provider) executeQueryAt(ctx context.Context, metric v1alpha1.Metric, rc measurementround.RoundContext) (model.Value, v1.Warnings, *sampleWindow, error) {
	prom := metric.Provider.Prometheus
	if prom.RangeQuery != nil {
		start, err := evaluate.EvalTimeAt(prom.RangeQuery.Start, rc.EvaluationTime)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse rangeQuery.start as time: %w", err)
		}
		end, err := evaluate.EvalTimeAt(prom.RangeQuery.End, rc.EvaluationTime)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse rangeQuery.end as time: %w", err)
		}
		stepDuration, err := prom.RangeQuery.Step.Duration()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse rangeQuery.step as duration: %w", err)
		}
		if window := end.Sub(start); window > rc.MaxWindow {
			return nil, nil, nil, fmt.Errorf("%w: %s exceeds %s", measurementround.ErrObservationWindowTooLarge, window, rc.MaxWindow)
		}
		gridStart, gridEnd := measurementround.AlignToStepGrid(rc.EvaluationTime, start, end, stepDuration)
		value, warnings, err := p.api.QueryRange(ctx, prom.Query, v1.Range{
			Start: gridStart,
			End:   gridEnd,
			Step:  stepDuration,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		return value, warnings, &sampleWindow{start: gridStart, end: gridEnd, step: stepDuration}, nil
	}

	value, warnings, err := p.api.Query(ctx, prom.Query, rc.EvaluationTime)
	if err != nil {
		return nil, nil, nil, err
	}
	return value, warnings, nil, nil
}
