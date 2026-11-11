package measurementround

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

func testMetrics() []v1alpha1.Metric {
	return []v1alpha1.Metric{
		{
			Name:             "metric-a",
			SuccessCondition: "result == 1",
			Provider: v1alpha1.MetricProvider{
				Prometheus: &v1alpha1.PrometheusMetric{Query: "up"},
			},
		},
		{
			Name:             "metric-b",
			SuccessCondition: "result == 2",
			Provider: v1alpha1.MetricProvider{
				Prometheus: &v1alpha1.PrometheusMetric{Query: "rate(http_requests_total[5m])"},
			},
		},
	}
}

func testRun() *v1alpha1.AnalysisRun {
	return &v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "test-run",
			UID:         "run-uid-1",
			Annotations: map[string]string{RevisionAnnotationKey: "42"},
		},
	}
}

func TestSpecDigestStableAndChanges(t *testing.T) {
	metrics := testMetrics()
	d1, err := SpecDigest(metrics)
	require.NoError(t, err)
	d2, err := SpecDigest(testMetrics())
	require.NoError(t, err)
	assert.Equal(t, d1, d2)
	assert.Len(t, d1, 16)

	modified := testMetrics()
	modified[0].Provider.Prometheus.Query = "down"
	d3, err := SpecDigest(modified)
	require.NoError(t, err)
	assert.NotEqual(t, d1, d3)
}

func TestNewRoundPinsCutPointAndIdentity(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	round, err := NewRound(cfg, testRun(), testMetrics(), now)
	require.NoError(t, err)

	assert.NotEmpty(t, round.ID)
	assert.Equal(t, now, round.EvaluationTime)
	assert.Equal(t, "42", round.Revision)
	assert.Equal(t, cfg.MaxWindow, round.MaxWindow)
	assert.Equal(t, cfg.MaxResultBytes, round.MaxResultBytes)
	assert.Equal(t, RoundPhaseOpen, round.Phase())

	digest, err := SpecDigest(testMetrics())
	require.NoError(t, err)
	assert.Equal(t, digest, round.SpecDigest)

	// Two rounds at different cut points get different IDs but the same spec digest.
	later, err := NewRound(cfg, testRun(), testMetrics(), now.Add(time.Minute))
	require.NoError(t, err)
	assert.NotEqual(t, round.ID, later.ID)
	assert.Equal(t, round.SpecDigest, later.SpecDigest)
}

func TestRoundMetadataRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 123, time.UTC)
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), now)
	require.NoError(t, err)

	restored, ok := RoundFromMetadata(round.RoundContext.Metadata())
	require.True(t, ok)
	// limits are intentionally not persisted; they are re-applied from configuration
	assert.Equal(t, round.ID, restored.ID)
	assert.Equal(t, round.EvaluationTime, restored.EvaluationTime)
	assert.Equal(t, round.SpecDigest, restored.SpecDigest)
	assert.Equal(t, round.Revision, restored.Revision)

	_, ok = RoundFromMetadata(map[string]string{"unrelated": "x"})
	assert.False(t, ok)
}

func TestIdentityStableAndBoundToInputs(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	id1 := round.Identity("metric-a", "up")
	id2 := round.Identity("metric-a", "up")
	assert.Equal(t, id1, id2)
	assert.NotEqual(t, id1, round.Identity("metric-a", "down"))
	assert.NotEqual(t, id1, round.Identity("metric-b", "up"))
}

func TestAlignToStepGrid(t *testing.T) {
	step := time.Minute
	eval := time.Unix(100, 500) // not on a step boundary

	t.Run("exact multiple window stays on grid", func(t *testing.T) {
		cutPoint := time.Unix(200, 0)
		start := time.Unix(0, 0)
		end := time.Unix(120, 0)
		gStart, gEnd := AlignToStepGrid(cutPoint, start, end, step)
		assert.Equal(t, int64(0), gStart.UnixNano()%int64(step))
		assert.Equal(t, int64(0), gEnd.UnixNano()%int64(step))
		assert.Equal(t, 2*time.Minute, gEnd.Sub(gStart))
	})

	t.Run("non divisible window snaps to whole steps", func(t *testing.T) {
		start := time.Unix(10, 250)
		end := time.Unix(100, 500)
		gStart, gEnd := AlignToStepGrid(eval, start, end, step)
		assert.Equal(t, int64(0), gStart.UnixNano()%int64(step))
		assert.Equal(t, int64(0), gEnd.UnixNano()%int64(step))
		// window length is an exact multiple of step
		assert.Equal(t, int64(0), int64(gEnd.Sub(gStart))%int64(step))
	})

	t.Run("end beyond evaluation time clamps to cut point", func(t *testing.T) {
		start := eval.Add(-2 * time.Minute)
		end := eval.Add(time.Minute)
		_, gEnd := AlignToStepGrid(eval, start, end, step)
		assert.False(t, gEnd.After(eval))
	})

	t.Run("deterministic across retries", func(t *testing.T) {
		start := time.Unix(30, 700)
		end := time.Unix(90, 900)
		s1, e1 := AlignToStepGrid(eval, start, end, step)
		s2, e2 := AlignToStepGrid(eval, start, end, step)
		assert.True(t, s1.Equal(s2))
		assert.True(t, e1.Equal(e2))
	})

	t.Run("non positive step leaves window untouched", func(t *testing.T) {
		start := time.Unix(10, 0)
		end := time.Unix(20, 0)
		s, e := AlignToStepGrid(eval, start, end, 0)
		assert.True(t, s.Equal(start))
		assert.True(t, e.Equal(end))
	})
}

func TestConfirmRequiresEveryRequiredMetric(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	phase, missing := round.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"metric-a", "metric-b"}, missing)

	require.NoError(t, round.ObserveMust(Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete}))
	phase, missing = round.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"metric-b"}, missing)

	// a timeout is a retryable state: it must not publish the round so the retry replays
	// the same fixed evaluation time
	require.NoError(t, round.ObserveMust(Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusTimeout}))
	phase, missing = round.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"metric-b"}, missing)

	require.NoError(t, round.ObserveMust(Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusComplete}))
	phase, missing = round.Confirm()
	assert.Equal(t, RoundPhaseComplete, phase)
	assert.Empty(t, missing)
}

func TestObserveDuplicateAndIdentityChecks(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	// first terminal success recorded
	_, err = round.Observe(Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete, Bytes: 1})
	require.NoError(t, err)

	// duplicate response for the same identity is suppressed, original is kept
	existing, err := round.Observe(Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete, Bytes: 99})
	assert.ErrorIs(t, err, ErrDuplicateResponse)
	assert.Equal(t, 1, existing.Bytes)

	// a response carrying a different identity is rejected
	_, err = round.Observe(Observation{MetricName: "metric-a", Identity: "forged", Status: MetricStatusComplete})
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	// a failed observation may be retried (overwritten) within the round
	_, err = round.Observe(Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusFailed, Message: "boom"})
	require.NoError(t, err)
	retry, err := round.Observe(Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusComplete})
	require.NoError(t, err)
	assert.Equal(t, MetricStatusComplete, retry.Status)

	// observations for unknown metrics are rejected
	_, err = round.Observe(Observation{MetricName: "unknown", Identity: "x", Status: MetricStatusComplete})
	assert.Error(t, err)
}

func TestObserveEnforcesByteBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxResultBytes = 10
	round, err := NewRound(cfg, testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	obs, err := round.Observe(Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete, Bytes: 11})
	require.NoError(t, err)
	assert.Equal(t, MetricStatusFailed, obs.Status)
	assert.Contains(t, obs.Message, ErrResultTooLarge.Error())
}

func TestRunConcurrencyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentQueries = 2
	round, err := NewRound(cfg, testRun(), testMetrics()[:1], time.Now())
	require.NoError(t, err)

	var inFlight, maxInFlight int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			identity := fmt.Sprintf("id-%d", i)
			_, _ = round.Run(context.Background(), "metric-a", identity, func(ctx context.Context) (Result, error) {
				cur := atomic.AddInt32(&inFlight, 1)
				for {
					seen := atomic.LoadInt32(&maxInFlight)
					if cur <= seen || atomic.CompareAndSwapInt32(&maxInFlight, seen, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&inFlight, -1)
				return Result{Status: MetricStatusComplete, Bytes: 1}, nil
			})
		}(i)
	}
	wg.Wait()
	assert.Equal(t, int32(cfg.MaxConcurrentQueries), atomic.LoadInt32(&maxInFlight))
}

func TestRunCancelledBeforeQueryStarts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentQueries = 1
	metrics := []v1alpha1.Metric{testMetrics()[0]}
	round, err := NewRound(cfg, testRun(), metrics, time.Now())
	require.NoError(t, err)

	// occupy the only slot with a long-running query
	slotAcquired := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = round.Run(context.Background(), "metric-a", "holder", func(ctx context.Context) (Result, error) {
			close(slotAcquired)
			<-release
			return Result{Status: MetricStatusComplete}, nil
		})
	}()
	<-slotAcquired

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := atomic.Bool{}
	_, runErr := round.Run(ctx, "metric-a", "queued", func(ctx context.Context) (Result, error) {
		started.Store(true)
		return Result{Status: MetricStatusComplete}, nil
	})
	assert.ErrorIs(t, runErr, ErrRoundCancelled)
	assert.False(t, started.Load(), "queued query must not start after cancellation")

	close(release)
}

func TestRunClassifiesTimeoutAndFailure(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	obs, runErr := round.Run(context.Background(), "metric-a", "id-timeout", func(ctx context.Context) (Result, error) {
		return Result{}, context.DeadlineExceeded
	})
	assert.ErrorIs(t, runErr, context.DeadlineExceeded)
	assert.Equal(t, MetricStatusTimeout, obs.Status)

	obs, runErr = round.Run(context.Background(), "metric-b", "id-failed", func(ctx context.Context) (Result, error) {
		return Result{}, errors.New("backend down")
	})
	assert.EqualError(t, runErr, "backend down")
	assert.Equal(t, MetricStatusFailed, obs.Status)
	stored, ok := round.Observation("metric-b")
	require.True(t, ok)
	assert.Equal(t, MetricStatusFailed, stored.Status)
}

func TestOutOfOrderObservationsStillConfirm(t *testing.T) {
	metrics := []v1alpha1.Metric{
		{Name: "m1", Provider: v1alpha1.MetricProvider{Prometheus: &v1alpha1.PrometheusMetric{Query: "q1"}}},
		{Name: "m2", Provider: v1alpha1.MetricProvider{Prometheus: &v1alpha1.PrometheusMetric{Query: "q2"}}},
		{Name: "m3", Provider: v1alpha1.MetricProvider{Prometheus: &v1alpha1.PrometheusMetric{Query: "q3"}}},
	}
	round, err := NewRound(DefaultConfig(), testRun(), metrics, time.Now())
	require.NoError(t, err)

	// deliver observations out of order
	require.NoError(t, round.ObserveMust(Observation{MetricName: "m3", Identity: "i3", Status: MetricStatusPartial}))
	require.NoError(t, round.ObserveMust(Observation{MetricName: "m1", Identity: "i1", Status: MetricStatusComplete}))
	phase, missing := round.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"m2"}, missing)

	// a failed observation does not confirm the round; the retry stays on the same round
	require.NoError(t, round.ObserveMust(Observation{MetricName: "m2", Identity: "i2", Status: MetricStatusFailed}))
	phase, missing = round.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"m2"}, missing)

	// the successful retry (same identity) completes the round
	retry, err := round.Observe(Observation{MetricName: "m2", Identity: "i2", Status: MetricStatusComplete})
	require.NoError(t, err)
	assert.Equal(t, MetricStatusComplete, retry.Status)
	phase, missing = round.Confirm()
	assert.Equal(t, RoundPhaseComplete, phase)
	assert.Empty(t, missing)
}

func TestAdvanceableGuards(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)

	assert.NoError(t, round.Advanceable(round.SpecDigest, round.Revision))
	assert.ErrorIs(t, round.Advanceable("other-digest", round.Revision), ErrRoundSpecChanged)
	assert.ErrorIs(t, round.Advanceable(round.SpecDigest, "99"), ErrRoundRevisionChanged)
}

func TestRestoreRoundSimulatesControllerRestart(t *testing.T) {
	cfg := DefaultConfig()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	round, err := NewRound(cfg, testRun(), testMetrics(), now)
	require.NoError(t, err)

	// metric-a confirmed in the previous process, metric-b still pending
	obsA := Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete}
	require.NoError(t, round.ObserveMust(obsA))
	metaA := round.MetadataFor(obsA)

	run := testRun()
	run.Status.MetricResults = []v1alpha1.MetricResult{
		{
			Name: "metric-a",
			Measurements: []v1alpha1.Measurement{
				{Phase: v1alpha1.AnalysisPhaseSuccessful, Metadata: metaA},
			},
		},
		{
			Name: "metric-b",
			Measurements: []v1alpha1.Measurement{
				// in-flight measurement: round metadata present but no terminal status
				{Phase: v1alpha1.AnalysisPhaseRunning, Metadata: round.RoundContext.Metadata()},
			},
		},
	}

	rc, seed, ok := LatestOpenRound(run)
	require.True(t, ok)
	assert.Equal(t, round.ID, rc.ID)
	assert.Equal(t, round.EvaluationTime, rc.EvaluationTime)
	require.Len(t, seed, 1)
	assert.Equal(t, "metric-a", seed[0].MetricName)
	assert.Equal(t, MetricStatusComplete, seed[0].Status)

	restored := RestoreRound(rc, []string{"metric-a", "metric-b"}, cfg, seed...)
	digest, _ := SpecDigest(testMetrics())
	require.NoError(t, restored.Advanceable(digest, "42"))

	phase, missing := restored.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.Equal(t, []string{"metric-b"}, missing)

	// completing the remaining metric publishes the same round, at the same cut point
	require.NoError(t, restored.ObserveMust(Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusComplete}))
	phase, _ = restored.Confirm()
	assert.Equal(t, RoundPhaseComplete, phase)
	assert.Equal(t, now, restored.EvaluationTime)
}

func TestLatestOpenRoundIgnoresCompletedRounds(t *testing.T) {
	round1, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)
	obsA := Observation{MetricName: "metric-a", Identity: "id-a", Status: MetricStatusComplete}
	obsB := Observation{MetricName: "metric-b", Identity: "id-b", Status: MetricStatusComplete}
	require.NoError(t, round1.ObserveMust(obsA))
	require.NoError(t, round1.ObserveMust(obsB))
	phase, _ := round1.Confirm()
	require.Equal(t, RoundPhaseComplete, phase)
	md := round1.MetadataFor(obsA)
	round1.PublishComplete(md)

	run := testRun()
	run.Status.MetricResults = []v1alpha1.MetricResult{{
		Name:         "metric-a",
		Measurements: []v1alpha1.Measurement{{Metadata: md}},
	}}
	_, _, ok := LatestOpenRound(run)
	assert.False(t, ok, "completed rounds must not be resumed")
}

func TestNoCarryoverAcrossRounds(t *testing.T) {
	cfg := DefaultConfig()
	round1, err := NewRound(cfg, testRun(), testMetrics(), time.Now())
	require.NoError(t, err)
	require.NoError(t, round1.ObserveMust(Observation{MetricName: "metric-a", Identity: "a1", Status: MetricStatusComplete}))
	require.NoError(t, round1.ObserveMust(Observation{MetricName: "metric-b", Identity: "b1", Status: MetricStatusComplete}))
	phase, _ := round1.Confirm()
	require.Equal(t, RoundPhaseComplete, phase)

	// a new round starts at a new cut point; round 1 successes must not confirm it
	round2, err := NewRound(cfg, testRun(), testMetrics(), time.Now().Add(time.Minute))
	require.NoError(t, err)
	phase, missing := round2.Confirm()
	assert.Equal(t, RoundPhaseOpen, phase)
	assert.ElementsMatch(t, []string{"metric-a", "metric-b"}, missing)
}

func TestConfigFromAnnotations(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, enabled, err := ConfigFromAnnotations(nil)
		require.NoError(t, err)
		assert.False(t, enabled)
		assert.Equal(t, DefaultConfig(), cfg)
	})

	t.Run("enabled with defaults", func(t *testing.T) {
		_, enabled, err := ConfigFromAnnotations(map[string]string{AnnotationEnable: "true"})
		require.NoError(t, err)
		assert.True(t, enabled)
	})

	t.Run("enabled with overrides", func(t *testing.T) {
		cfg, enabled, err := ConfigFromAnnotations(map[string]string{
			AnnotationEnable:               "enabled",
			AnnotationMaxConcurrentQueries: "3",
			AnnotationMaxWindow:            "90m",
			AnnotationMaxResultBytes:       "2048",
		})
		require.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, 3, cfg.MaxConcurrentQueries)
		assert.Equal(t, 90*time.Minute, cfg.MaxWindow)
		assert.Equal(t, 2048, cfg.MaxResultBytes)
	})

	for _, tc := range []map[string]string{
		{AnnotationEnable: "true", AnnotationMaxConcurrentQueries: "0"},
		{AnnotationEnable: "true", AnnotationMaxWindow: "not-a-duration"},
		{AnnotationEnable: "true", AnnotationMaxResultBytes: "-1"},
	} {
		_, enabled, err := ConfigFromAnnotations(tc)
		assert.Error(t, err)
		assert.False(t, enabled)
	}
}

func TestSafeFieldsContainNoSecretMaterial(t *testing.T) {
	round, err := NewRound(DefaultConfig(), testRun(), testMetrics(), time.Now())
	require.NoError(t, err)
	fields := round.SafeFields()
	assert.Contains(t, fields, "round")
	assert.Contains(t, fields, "evaluationTime")
	assert.Contains(t, fields, "specDigest")
	// only identity fields, never provider configuration or credentials
	assert.Len(t, fields, 4)
}

// ObserveMust is a test helper that fails the test on an observation error.
func (r *Round) ObserveMust(obs Observation) error {
	_, err := r.Observe(obs)
	return err
}
