package prometheus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/argoproj/argo-rollouts/metric/measurementround"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

// recordingSpy is an HTTP spy which records the Prometheus query parameters of every request
// and replies with a scalar result echoing the requested evaluation time.
type recordingSpy struct {
	mu          sync.Mutex
	instantTime []string
	rangeStart  []string
	rangeEnd    []string
	rangeStep   []string
	queries     []string
	delay       time.Duration
}

func (s *recordingSpy) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// client_golang issues POST with a form-encoded body, falling back to GET on 405,
		// so parse both sources.
		_ = r.ParseForm()
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		q := r.Form
		s.mu.Lock()
		s.queries = append(s.queries, q.Get("query"))
		switch r.URL.Path {
		case "/api/v1/query":
			s.instantTime = append(s.instantTime, q.Get("time"))
		case "/api/v1/query_range":
			s.rangeStart = append(s.rangeStart, q.Get("start"))
			s.rangeEnd = append(s.rangeEnd, q.Get("end"))
			s.rangeStep = append(s.rangeStep, q.Get("step"))
		}
		s.mu.Unlock()

		echoTime := q.Get("time")
		if echoTime == "" {
			echoTime = q.Get("end")
		}
		var seconds float64
		fmt.Sscanf(echoTime, "%f", &seconds)
		resp := map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "scalar",
				"result":     []any{seconds, fmt.Sprintf("%d", int64(seconds))},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (s *recordingSpy) snapshot() (instant, start, end, step []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.instantTime...), append([]string{}, s.rangeStart...),
		append([]string{}, s.rangeEnd...), append([]string{}, s.rangeStep...)
}

func newRoundContext(t *testing.T, evalTime time.Time) measurementround.RoundContext {
	t.Helper()
	run := &v1alpha1.AnalysisRun{}
	round, err := measurementround.NewRound(measurementround.DefaultConfig(), run, []v1alpha1.Metric{{
		Name:     "m",
		Provider: v1alpha1.MetricProvider{Prometheus: &v1alpha1.PrometheusMetric{Query: "up"}},
	}}, evalTime)
	require.NoError(t, err)
	return round.RoundContext
}

func newRoundProvider(t *testing.T, serverURL string, metric v1alpha1.Metric, logEntry *log.Entry) *Provider {
	t.Helper()
	metric.Provider.Prometheus.Address = serverURL
	api, err := NewPrometheusAPI(metric)
	require.NoError(t, err)
	p, err := NewPrometheusProvider(api, *logEntry, metric)
	require.NoError(t, err)
	return p
}

func newSpyServer(t *testing.T, spy *recordingSpy) string {
	t.Helper()
	server := httptest.NewServer(spy.handler())
	t.Cleanup(server.Close)
	return server.URL
}

func instantMetric(name, query string) v1alpha1.Metric {
	return v1alpha1.Metric{
		Name:             name,
		SuccessCondition: "result >= 0",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{Query: query},
		},
	}
}

// TestRunAtParallelInstantQueriesShareFixedTime verifies through the HTTP spy that every
// parallel query of a round carries the exact same fixed evaluation time instead of each
// evaluating its own wall-clock now.
func TestRunAtParallelInstantQueriesShareFixedTime(t *testing.T) {
	spy := &recordingSpy{}
	serverURL := newSpyServer(t, spy)
	logger := log.NewEntry(log.New())
	evalTime := time.Date(2026, 11, 12, 10, 0, 30, 0, time.UTC)
	rc := newRoundContext(t, evalTime)

	metrics := []v1alpha1.Metric{
		instantMetric("m1", "up{job=\"a\"}"),
		instantMetric("m2", "up{job=\"b\"}"),
		instantMetric("m3", "up{job=\"c\"}"),
	}

	var wg sync.WaitGroup
	measurements := make([]v1alpha1.Measurement, len(metrics))
	for i, m := range metrics {
		wg.Add(1)
		go func(i int, metric v1alpha1.Metric) {
			defer wg.Done()
			p := newRoundProvider(t, serverURL, metric, logger)
			measurements[i] = p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
		}(i, m)
	}
	wg.Wait()

	for _, m := range measurements {
		assert.Equal(t, v1alpha1.AnalysisPhaseSuccessful, m.Phase)
		assert.Equal(t, string(measurementround.MetricStatusComplete), m.Metadata[measurementround.MetadataKeyMetricStatus])
		assert.Equal(t, rc.ID, m.Metadata[measurementround.MetadataKeyRoundID])
		assert.Equal(t, evalTime.UTC().Format(time.RFC3339Nano), m.Metadata[measurementround.MetadataKeyEvaluationTime])
	}

	times, _, _, _ := spy.snapshot()
	require.Len(t, times, len(metrics))
	expected := fmt.Sprintf("%d", evalTime.Unix())
	for _, ts := range times {
		assert.Equal(t, expected, ts, "every request must carry the same fixed cut point")
	}
}

// TestRunAtRetryReplaysSameRequest verifies a retry issues a byte-identical request at the
// same cut point.
func TestRunAtRetryReplaysSameRequest(t *testing.T) {
	spy := &recordingSpy{}
	serverURL := newSpyServer(t, spy)
	logger := log.NewEntry(log.New())
	evalTime := time.Date(2026, 11, 12, 10, 0, 30, 0, time.UTC)
	rc := newRoundContext(t, evalTime)
	metric := instantMetric("m1", "up")

	p := newRoundProvider(t, serverURL, metric, logger)
	first := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	second := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)

	assert.Equal(t, first.Value, second.Value)
	assert.Equal(t, first.Phase, second.Phase)
	times, _, _, _ := spy.snapshot()
	require.Len(t, times, 2)
	assert.Equal(t, times[0], times[1])
}

// TestRunAtRangeQueryPinnedToGrid verifies range expressions resolve now() against the round
// cut point and the request is snapped to an exact step grid, deterministically.
func TestRunAtRangeQueryPinnedToGrid(t *testing.T) {
	spy := &recordingSpy{}
	serverURL := newSpyServer(t, spy)
	logger := log.NewEntry(log.New())
	evalTime := time.Date(2026, 11, 12, 10, 0, 45, 0, time.UTC)
	rc := newRoundContext(t, evalTime)
	rc.MaxWindow = time.Hour

	metric := v1alpha1.Metric{
		Name:             "range-metric",
		SuccessCondition: "result >= 0",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{
				Query: "rate(http_requests_total[1m])",
				RangeQuery: &v1alpha1.PrometheusRangeQueryArgs{
					Start: `now() - duration("5m")`,
					End:   `now()`,
					Step:  "1m",
				},
			},
		},
	}
	p := newRoundProvider(t, serverURL, metric, logger)

	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	require.Equal(t, v1alpha1.AnalysisPhaseSuccessful, m.Phase, m.Message)

	_, starts, ends, steps := spy.snapshot()
	require.Len(t, starts, 1)
	// grid end is the cut point truncated to the step
	expectedEnd := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	expectedStart := expectedEnd.Add(-5 * time.Minute)
	assert.Equal(t, fmt.Sprintf("%d", expectedEnd.Unix()), ends[0])
	assert.Equal(t, fmt.Sprintf("%d", expectedStart.Unix()), starts[0])
	assert.Equal(t, "60", steps[0])
	// sample interval is persisted on the measurement
	assert.Equal(t, "2026-11-12 09:55:00 +0000 UTC", mustParseRFC3339(t, m.Metadata[measurementround.MetadataKeySampleStart]).String())
	assert.Equal(t, "1m0s", m.Metadata[measurementround.MetadataKeySampleStep])

	// retry replays the identical grid window
	_ = p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	_, starts2, ends2, _ := spy.snapshot()
	require.Len(t, starts2, 2)
	assert.Equal(t, starts[0], starts2[1])
	assert.Equal(t, ends[0], ends2[1])
}

// TestRunAtRangeWindowOutsideTimeDomain ensures a range window exceeding the round time
// domain is rejected explicitly.
func TestRunAtRangeWindowOutsideTimeDomain(t *testing.T) {
	spy := &recordingSpy{}
	serverURL := newSpyServer(t, spy)
	logger := log.NewEntry(log.New())
	evalTime := time.Date(2026, 11, 12, 10, 0, 45, 0, time.UTC)
	rc := newRoundContext(t, evalTime)
	rc.MaxWindow = 2 * time.Minute

	metric := v1alpha1.Metric{
		Name: "range-metric",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{
				Query: "rate(x[1m])",
				RangeQuery: &v1alpha1.PrometheusRangeQueryArgs{
					Start: `now() - duration("5m")`,
					End:   `now()`,
					Step:  "1m",
				},
			},
		},
	}
	p := newRoundProvider(t, serverURL, metric, logger)
	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	assert.Equal(t, v1alpha1.AnalysisPhaseError, m.Phase)
	assert.Contains(t, m.Message, measurementround.ErrObservationWindowTooLarge.Error())
	assert.Equal(t, string(measurementround.MetricStatusFailed), m.Metadata[measurementround.MetadataKeyMetricStatus])
}

// TestRunAtDelayedQueryTimesOut exercises a slow backend and the Timeout classification.
func TestRunAtDelayedQueryTimesOut(t *testing.T) {
	spy := &recordingSpy{delay: 1500 * time.Millisecond}
	serverURL := newSpyServer(t, spy)
	logger := log.NewEntry(log.New())
	rc := newRoundContext(t, time.Now())
	timeout := int64(1)
	metric := instantMetric("slow", "up")
	metric.Provider.Prometheus.Timeout = &timeout

	p := newRoundProvider(t, serverURL, metric, logger)
	start := time.Now()
	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	elapsed := time.Since(start)

	assert.Equal(t, v1alpha1.AnalysisPhaseError, m.Phase)
	assert.Equal(t, string(measurementround.MetricStatusTimeout), m.Metadata[measurementround.MetadataKeyMetricStatus])
	assert.Less(t, elapsed, 1400*time.Millisecond)
}

// TestRunAtWarningIsPartial verifies provider warnings mark the metric Partial while keeping
// the evaluated phase.
func TestRunAtWarningIsPartial(t *testing.T) {
	rc := newRoundContext(t, time.Now())
	mock := &mockAPI{
		value:    newScalar(10),
		warnings: v1.Warnings{"stale-read"},
	}
	metric := instantMetric("warn", "up")
	p, err := NewPrometheusProvider(mock, *log.NewEntry(log.New()), metric)
	require.NoError(t, err)

	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	assert.Equal(t, v1alpha1.AnalysisPhaseSuccessful, m.Phase)
	assert.Equal(t, string(measurementround.MetricStatusPartial), m.Metadata[measurementround.MetadataKeyMetricStatus])
	assert.Equal(t, `"stale-read"`, m.Metadata["warnings"])
}

// TestRunAtBackendFailure verifies backend errors are marked Failed.
func TestRunAtBackendFailure(t *testing.T) {
	rc := newRoundContext(t, time.Now())
	mock := &mockAPI{err: fmt.Errorf("prometheus unavailable")}
	metric := instantMetric("fail", "up")
	p, err := NewPrometheusProvider(mock, log.Entry{}, metric)
	require.NoError(t, err)

	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	assert.Equal(t, v1alpha1.AnalysisPhaseError, m.Phase)
	assert.Equal(t, string(measurementround.MetricStatusFailed), m.Metadata[measurementround.MetadataKeyMetricStatus])
	assert.Contains(t, m.Message, "prometheus unavailable")
}

// TestRunAtContextDeadlineIsTimeout verifies deadline errors are classified Timeout.
func TestRunAtContextDeadlineIsTimeout(t *testing.T) {
	rc := newRoundContext(t, time.Now())
	mock := &mockAPI{err: context.DeadlineExceeded}
	metric := instantMetric("timeout", "up")
	p, err := NewPrometheusProvider(mock, log.Entry{}, metric)
	require.NoError(t, err)

	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	assert.Equal(t, v1alpha1.AnalysisPhaseError, m.Phase)
	assert.Equal(t, string(measurementround.MetricStatusTimeout), m.Metadata[measurementround.MetadataKeyMetricStatus])
}

// TestRunAtEquivalentToDirectSameCutPointQuery verifies the round-mode evaluation matches a
// direct provider call made against the same cut point.
func TestRunAtEquivalentToDirectSameCutPointQuery(t *testing.T) {
	spy := &recordingSpy{}
	logger := log.NewEntry(log.New())
	evalTime := time.Date(2026, 11, 12, 10, 0, 30, 0, time.UTC)
	rc := newRoundContext(t, evalTime)
	metric := instantMetric("echo", "up")

	api, err := NewPrometheusAPI(v1alpha1.Metric{
		Name:     "echo",
		Provider: v1alpha1.MetricProvider{Prometheus: &v1alpha1.PrometheusMetric{Address: newSpyServer(t, spy), Query: "up"}},
	})
	require.NoError(t, err)
	p, err := NewPrometheusProvider(api, *logger, metric)
	require.NoError(t, err)

	roundMeasurement := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	require.Equal(t, v1alpha1.AnalysisPhaseSuccessful, roundMeasurement.Phase)

	// independently query the real provider at the same cut point
	directValue, directWarnings, directErr := api.Query(context.Background(), "up", rc.EvaluationTime)
	require.NoError(t, directErr)
	require.Empty(t, directWarnings)
	directValueStr, directStatus, evalErr := p.processResponse(metric, directValue)
	require.NoError(t, evalErr)

	assert.Equal(t, directStatus, roundMeasurement.Phase)
	scalar, ok := directValue.(*model.Scalar)
	require.True(t, ok)
	assert.Equal(t, scalar.Value.String(), roundMeasurement.Value)
	assert.Equal(t, directValueStr, roundMeasurement.Value)
}

// recordingHook captures log entries for secret-leak assertions.
type recordingHook struct {
	mu      sync.Mutex
	entries []string
}

func (h *recordingHook) Levels() []log.Level { return log.AllLevels }
func (h *recordingHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.entries = append(h.entries, line)
	h.mu.Unlock()
	return nil
}
func (h *recordingHook) text() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := ""
	for _, e := range h.entries {
		out += e
	}
	return out
}

// TestRunAtLogsContainNoSecrets verifies authentication material never reaches the logs of
// a round measurement.
func TestRunAtLogsContainNoSecrets(t *testing.T) {
	const secretPassword = "super-secret-password-123"

	logger := log.New()
	logger.SetLevel(log.DebugLevel)
	hook := &recordingHook{}
	logger.AddHook(hook)
	entry := log.NewEntry(logger)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("myuser:"+secretPassword))
		if r.Header.Get("Authorization") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "scalar", "result": []any{1, "1"}},
		})
	}))
	defer server.Close()

	rc := newRoundContext(t, time.Now())
	metric := v1alpha1.Metric{
		Name:             "authed",
		SuccessCondition: "result == 1",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{
				Address: server.URL,
				Query:   "up",
				Authentication: v1alpha1.Authentication{
					BasicAuth: v1alpha1.BasicAuthConfig{Username: "myuser", Password: secretPassword},
				},
			},
		},
	}
	api, err := NewPrometheusAPI(metric)
	require.NoError(t, err)
	p, err := NewPrometheusProvider(api, *entry, metric)
	require.NoError(t, err)

	m := p.RunAt(context.Background(), &v1alpha1.AnalysisRun{}, metric, rc)
	require.Equal(t, v1alpha1.AnalysisPhaseSuccessful, m.Phase)
	assert.NotContains(t, hook.text(), secretPassword)
}

func mustParseRFC3339(t *testing.T, raw string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, raw)
	require.NoError(t, err)
	return ts
}
