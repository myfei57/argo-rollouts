package analysis

import (
	"context"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-rollouts/metric"
	"github.com/argoproj/argo-rollouts/metric/measurementround"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	timeutil "github.com/argoproj/argo-rollouts/utils/time"
)

// roundFakeProvider is a FixedTimeProvider which records the fixed evaluation time of every
// round query instead of performing a real backend call.
type roundFakeProvider struct {
	mu         sync.Mutex
	runAtCalls int
	runCalls   int
	evalTimes  []time.Time
	roundIDs   []string
	failNext   bool
}

func (f *roundFakeProvider) Run(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric) v1alpha1.Measurement {
	f.mu.Lock()
	f.runCalls++
	f.mu.Unlock()
	now := timeutil.MetaNow()
	return v1alpha1.Measurement{Phase: v1alpha1.AnalysisPhaseSuccessful, Value: "10", StartedAt: &now, FinishedAt: &now}
}

func (f *roundFakeProvider) Resume(run *v1alpha1.AnalysisRun, m v1alpha1.Metric, _ v1alpha1.Measurement) v1alpha1.Measurement {
	return f.Run(run, m)
}

func (f *roundFakeProvider) Terminate(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric, measurement v1alpha1.Measurement) v1alpha1.Measurement {
	return measurement
}

func (f *roundFakeProvider) GarbageCollect(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric, _ int) error {
	return nil
}

func (f *roundFakeProvider) Type() string { return "Prometheus" }

func (f *roundFakeProvider) GetMetadata(_ v1alpha1.Metric) map[string]string {
	return map[string]string{}
}

func (f *roundFakeProvider) RunAt(_ context.Context, _ *v1alpha1.AnalysisRun, m v1alpha1.Metric, rc measurementround.RoundContext) v1alpha1.Measurement {
	f.mu.Lock()
	f.runAtCalls++
	f.evalTimes = append(f.evalTimes, rc.EvaluationTime)
	f.roundIDs = append(f.roundIDs, rc.ID)
	fail := f.failNext
	f.mu.Unlock()

	now := timeutil.MetaNow()
	measurement := v1alpha1.Measurement{
		StartedAt:  &now,
		FinishedAt: &now,
		Value:      "10",
		Metadata:   rc.Metadata(),
	}
	measurement.Metadata[measurementround.MetadataKeyIdentity] = rc.Identity(m.Name, "Prometheus|"+m.Provider.Prometheus.Query)
	if fail {
		measurement.Phase = v1alpha1.AnalysisPhaseError
		measurement.Message = "simulated backend failure"
		measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(measurementround.MetricStatusFailed)
		return measurement
	}
	measurement.Phase = v1alpha1.AnalysisPhaseSuccessful
	measurement.Metadata[measurementround.MetadataKeyMetricStatus] = string(measurementround.MetricStatusComplete)
	return measurement
}

func (f *roundFakeProvider) snapshot() (int, []time.Time, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runAtCalls, append([]time.Time{}, f.evalTimes...), append([]string{}, f.roundIDs...)
}

// plainProvider implements only the legacy Provider interface, deliberately lacking the
// FixedTimeProvider capability.
type plainProvider struct{}

func (p *plainProvider) Run(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric) v1alpha1.Measurement {
	now := timeutil.MetaNow()
	return v1alpha1.Measurement{Phase: v1alpha1.AnalysisPhaseSuccessful, StartedAt: &now, FinishedAt: &now}
}
func (p *plainProvider) Resume(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric, m v1alpha1.Measurement) v1alpha1.Measurement {
	return m
}
func (p *plainProvider) Terminate(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric, m v1alpha1.Measurement) v1alpha1.Measurement {
	return m
}
func (p *plainProvider) GarbageCollect(_ *v1alpha1.AnalysisRun, _ v1alpha1.Metric, _ int) error { return nil }
func (p *plainProvider) Type() string                                                          { return "Web" }
func (p *plainProvider) GetMetadata(_ v1alpha1.Metric) map[string]string                       { return nil }

func roundPromMetric(name string) v1alpha1.Metric {
	return v1alpha1.Metric{
		Name: name,
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{Query: "up{job=\"" + name + "\"}"},
		},
	}
}

func roundEnabledRun(metrics []v1alpha1.Metric, annotations ...map[string]string) *v1alpha1.AnalysisRun {
	anns := map[string]string{measurementround.AnnotationEnable: "true"}
	for _, extra := range annotations {
		for k, v := range extra {
			anns[k] = v
		}
	}
	return &v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{Annotations: anns},
		Spec:       v1alpha1.AnalysisRunSpec{Metrics: metrics},
	}
}

func newRoundFixtureController(t *testing.T, f *fixture, provider metric.Provider) *Controller {
	t.Helper()
	c, _, _ := f.newController(noResyncPeriodFunc)
	c.newProvider = func(_ log.Entry, _ string, _ v1alpha1.Metric) (metric.Provider, error) {
		return provider, nil
	}
	return c
}

// TestMeasurementRoundPinsEvaluationTimeAcrossParallelMetrics verifies all parallel metrics
// of a round share one fixed cut point and the round is published complete once confirmed.
func TestMeasurementRoundPinsEvaluationTimeAcrossParallelMetrics(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	run := roundEnabledRun([]v1alpha1.Metric{roundPromMetric("m1"), roundPromMetric("m2")})
	newRun := c.reconcileAnalysisRun(run)

	calls, evalTimes, roundIDs := fake.snapshot()
	assert.Equal(t, 2, calls)
	assert.Equal(t, 0, fake.runCalls)
	require.Len(t, evalTimes, 2)
	assert.True(t, evalTimes[0].Equal(f.now))
	assert.True(t, evalTimes[0].Equal(evalTimes[1]), "parallel queries must share the fixed cut point")
	assert.Equal(t, roundIDs[0], roundIDs[1])

	require.Len(t, newRun.Status.MetricResults, 2)
	for _, result := range newRun.Status.MetricResults {
		md := result.Measurements[0].Metadata
		assert.Equal(t, roundIDs[0], md[measurementround.MetadataKeyRoundID])
		assert.Equal(t, string(measurementround.RoundPhaseComplete), md[measurementround.MetadataKeyRoundPhase])
		assert.NotEmpty(t, md[measurementround.MetadataKeySpecDigest])
		assert.NotEmpty(t, md[measurementround.MetadataKeyIdentity])
	}
	assert.Equal(t, v1alpha1.AnalysisPhaseSuccessful, newRun.Status.Phase)
}

// TestMeasurementRoundDefaultModeUsesIndependentMeasurements verifies runs without the
// opt-in annotation keep the legacy provider behavior unchanged.
func TestMeasurementRoundDefaultModeUsesIndependentMeasurements(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	run := &v1alpha1.AnalysisRun{
		Spec: v1alpha1.AnalysisRunSpec{Metrics: []v1alpha1.Metric{roundPromMetric("m1"), roundPromMetric("m2")}},
	}
	newRun := c.reconcileAnalysisRun(run)

	calls, _, _ := fake.snapshot()
	assert.Equal(t, 0, calls)
	assert.Equal(t, 2, fake.runCalls)
	for _, result := range newRun.Status.MetricResults {
		assert.NotContains(t, result.Measurements[0].Metadata, measurementround.MetadataKeyRoundID)
	}
}

// TestMeasurementRoundResumeAfterControllerRestart verifies an in-flight round reconstructed
// from persisted status resumes at the same fixed evaluation time.
func TestMeasurementRoundResumeAfterControllerRestart(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	metrics := []v1alpha1.Metric{roundPromMetric("m1")}
	cutPoint := f.now.Add(-time.Minute)
	seedRound, err := measurementround.NewRound(measurementround.DefaultConfig(), roundEnabledRun(metrics), metrics, cutPoint)
	require.NoError(t, err)

	run := roundEnabledRun(metrics)
	run.Status = v1alpha1.AnalysisRunStatus{
		Phase: v1alpha1.AnalysisPhaseRunning,
		MetricResults: []v1alpha1.MetricResult{{
			Name:  "m1",
			Phase: v1alpha1.AnalysisPhaseRunning,
			Measurements: []v1alpha1.Measurement{{
				Phase:     v1alpha1.AnalysisPhaseRunning,
				StartedAt: timePtr(metav1.NewTime(f.now.Add(-2 * time.Minute))),
				Metadata:  seedRound.RoundContext.Metadata(),
			}},
		}},
	}

	newRun := c.reconcileAnalysisRun(run)

	calls, evalTimes, roundIDs := fake.snapshot()
	require.Equal(t, 1, calls)
	assert.True(t, evalTimes[0].Equal(cutPoint), "resume must reuse the round cut point, not wall-clock now")
	assert.Equal(t, seedRound.ID, roundIDs[0])
	assert.Equal(t, seedRound.ID, newRun.Status.MetricResults[0].Measurements[0].Metadata[measurementround.MetadataKeyRoundID])
}

// TestMeasurementRoundRetryKeepsRoundTime verifies a failed measurement is retried within
// the same round and at the same fixed evaluation time.
func TestMeasurementRoundRetryKeepsRoundTime(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{failNext: true}
	c := newRoundFixtureController(t, f, fake)

	metrics := []v1alpha1.Metric{roundPromMetric("m1")}
	run := roundEnabledRun(metrics)

	first := c.reconcileAnalysisRun(run.DeepCopy())
	firstMeasurement := first.Status.MetricResults[0].Measurements[0]
	require.Equal(t, v1alpha1.AnalysisPhaseError, firstMeasurement.Phase)
	require.Equal(t, string(measurementround.RoundPhaseOpen), firstMeasurement.Metadata[measurementround.MetadataKeyRoundPhase])
	firstRoundID := firstMeasurement.Metadata[measurementround.MetadataKeyRoundID]

	// advance the controller clock past the error retry interval and reconcile again
	f.now = f.now.Add(DefaultErrorRetryInterval + time.Second)
	fake.failNext = false
	second := c.reconcileAnalysisRun(first.DeepCopy())

	require.Len(t, second.Status.MetricResults[0].Measurements, 2)
	retryMeasurement := second.Status.MetricResults[0].Measurements[1]
	assert.Equal(t, v1alpha1.AnalysisPhaseSuccessful, retryMeasurement.Phase)
	assert.Equal(t, firstRoundID, retryMeasurement.Metadata[measurementround.MetadataKeyRoundID], "retry stays in the same round")
	assert.Equal(t,
		firstMeasurement.Metadata[measurementround.MetadataKeyEvaluationTime],
		retryMeasurement.Metadata[measurementround.MetadataKeyEvaluationTime],
		"retry uses the same fixed evaluation time")
	assert.Equal(t, string(measurementround.RoundPhaseComplete), retryMeasurement.Metadata[measurementround.MetadataKeyRoundPhase])

	calls, evalTimes, _ := fake.snapshot()
	require.Equal(t, 2, calls)
	assert.Equal(t, evalTimes[0], evalTimes[1])
}

// TestMeasurementRoundUnsupportedProviderExplicitError verifies providers lacking fixed-time
// support fail explicitly instead of silently querying wall-clock now.
func TestMeasurementRoundUnsupportedProviderExplicitError(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	c := newRoundFixtureController(t, f, &plainProvider{})

	run := roundEnabledRun([]v1alpha1.Metric{roundPromMetric("m1")})
	newRun := c.reconcileAnalysisRun(run)

	measurement := newRun.Status.MetricResults[0].Measurements[0]
	assert.Equal(t, v1alpha1.AnalysisPhaseError, measurement.Phase)
	assert.Contains(t, measurement.Message, measurementround.ErrFixedTimeUnsupported.Error())
	assert.NotEmpty(t, measurement.Metadata[measurementround.MetadataKeyRoundID])
	assert.Equal(t, string(measurementround.MetricStatusFailed), measurement.Metadata[measurementround.MetadataKeyMetricStatus])
}

// TestMeasurementRoundSpecChangeInvalidatesInFlightRound verifies an old round cannot
// advance the analysis after the metric spec changed; a new round is opened.
func TestMeasurementRoundSpecChangeInvalidatesInFlightRound(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	oldMetrics := []v1alpha1.Metric{roundPromMetric("m1")}
	staleRound, err := measurementround.NewRound(measurementround.DefaultConfig(), roundEnabledRun(oldMetrics), oldMetrics, f.now.Add(-time.Minute))
	require.NoError(t, err)

	newMetrics := []v1alpha1.Metric{roundPromMetric("m1")}
	newMetrics[0].Provider.Prometheus.Query = "up{job=\"changed\"}"
	run := roundEnabledRun(newMetrics)
	run.Status = v1alpha1.AnalysisRunStatus{
		Phase: v1alpha1.AnalysisPhaseRunning,
		MetricResults: []v1alpha1.MetricResult{{
			Name:  "m1",
			Phase: v1alpha1.AnalysisPhaseRunning,
			Measurements: []v1alpha1.Measurement{{
				Phase:     v1alpha1.AnalysisPhaseRunning,
				StartedAt: timePtr(metav1.NewTime(f.now.Add(-2 * time.Minute))),
				Metadata:  staleRound.RoundContext.Metadata(),
			}},
		}},
	}

	newRun := c.reconcileAnalysisRun(run)
	measurement := newRun.Status.MetricResults[0].Measurements[0]
	assert.NotEqual(t, staleRound.ID, measurement.Metadata[measurementround.MetadataKeyRoundID])
	currentDigest, err := measurementround.SpecDigest(newMetrics)
	require.NoError(t, err)
	assert.Equal(t, currentDigest, measurement.Metadata[measurementround.MetadataKeySpecDigest])

	// the stale round id must be gone from the persisted status entirely
	for _, result := range newRun.Status.MetricResults {
		for _, m := range result.Measurements {
			assert.NotEqual(t, staleRound.ID, m.Metadata[measurementround.MetadataKeyRoundID])
		}
	}
}

// TestMeasurementRoundRevisionChangeOpensNewRound verifies rollout revision changes block
// advancement of the old round.
func TestMeasurementRoundRevisionChangeOpensNewRound(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	metrics := []v1alpha1.Metric{roundPromMetric("m1")}
	oldRun := roundEnabledRun(metrics, map[string]string{measurementround.RevisionAnnotationKey: "42"})
	staleRound, err := measurementround.NewRound(measurementround.DefaultConfig(), oldRun, metrics, f.now.Add(-time.Minute))
	require.NoError(t, err)

	run := roundEnabledRun(metrics, map[string]string{measurementround.RevisionAnnotationKey: "43"})
	run.Status = v1alpha1.AnalysisRunStatus{
		Phase: v1alpha1.AnalysisPhaseRunning,
		MetricResults: []v1alpha1.MetricResult{{
			Name:  "m1",
			Phase: v1alpha1.AnalysisPhaseRunning,
			Measurements: []v1alpha1.Measurement{{
				Phase:     v1alpha1.AnalysisPhaseRunning,
				StartedAt: timePtr(metav1.NewTime(f.now.Add(-2 * time.Minute))),
				Metadata:  staleRound.RoundContext.Metadata(),
			}},
		}},
	}

	newRun := c.reconcileAnalysisRun(run)
	measurement := newRun.Status.MetricResults[0].Measurements[0]
	assert.NotEqual(t, staleRound.ID, measurement.Metadata[measurementround.MetadataKeyRoundID])
	assert.Equal(t, "43", measurement.Metadata[measurementround.MetadataKeyRevision])
}

// TestMeasurementRoundMissingMetricDoesNotPublish verifies the round stays open while a
// required metric has not confirmed, without borrowing previous round successes.
func TestMeasurementRoundMissingMetricDoesNotPublish(t *testing.T) {
	f := newFixture(t)
	defer f.Close()
	fake := &roundFakeProvider{}
	c := newRoundFixtureController(t, f, fake)

	delayed := roundPromMetric("m2")
	delayed.InitialDelay = "1h"
	run := roundEnabledRun([]v1alpha1.Metric{roundPromMetric("m1"), delayed})
	run.Status.StartedAt = &metav1.Time{Time: f.now}

	newRun := c.reconcileAnalysisRun(run)

	require.Len(t, newRun.Status.MetricResults, 1)
	measurement := newRun.Status.MetricResults[0].Measurements[0]
	assert.Equal(t, string(measurementround.RoundPhaseOpen), measurement.Metadata[measurementround.MetadataKeyRoundPhase],
		"round must not be published while m2 is missing")
	assert.Equal(t, v1alpha1.AnalysisPhaseRunning, newRun.Status.Phase)
}
