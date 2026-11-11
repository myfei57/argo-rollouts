// Package measurementround implements the optional MeasurementRound protocol.
//
// A MeasurementRound binds every metric query performed for a single AnalysisRun
// reconciliation round to one fixed evaluation time (the cut point) and to a finite
// observation window. Round state (round ID, metric spec digest, revision and the sample
// interval actually used) is persisted on the individual Measurements so that resumes,
// retries and controller restarts replay the exact same round instead of querying a new
// "now" for every attempt.
//
// The protocol is opt-in: AnalysisRuns without the enable annotation keep using the
// legacy independent measurement behavior unchanged.
package measurementround

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

const (
	// AnnotationEnable is the AnalysisRun annotation which opts in to the
	// MeasurementRound protocol when set to "true".
	AnnotationEnable = "analysis.argoproj.io/measurement-round"
	// AnnotationMaxConcurrentQueries bounds the number of queries of a single round that
	// may be in flight at the same time.
	AnnotationMaxConcurrentQueries = "analysis.argoproj.io/measurement-round-max-concurrent"
	// AnnotationMaxWindow bounds the time domain (lookback duration) of any range query in
	// the round. The value is parsed as a Go duration (e.g. "30m", "2h").
	AnnotationMaxWindow = "analysis.argoproj.io/measurement-round-max-window"
	// AnnotationMaxResultBytes bounds the serialized size of a single metric result.
	AnnotationMaxResultBytes = "analysis.argoproj.io/measurement-round-max-result-bytes"

	// Metadata keys persisted on every Measurement produced by a round. They double as the
	// durable round state which survives controller restarts.
	MetadataKeyRoundID        = "MeasurementRoundID"
	MetadataKeyEvaluationTime = "MeasurementRoundEvaluationTime"
	MetadataKeySpecDigest     = "MeasurementRoundSpecDigest"
	MetadataKeyRevision       = "MeasurementRoundRevision"
	MetadataKeyRoundPhase     = "MeasurementRoundPhase"
	MetadataKeyMetricStatus   = "MeasurementRoundMetricStatus"
	MetadataKeyIdentity       = "MeasurementRoundIdentity"
	MetadataKeySampleStart    = "MeasurementRoundSampleStart"
	MetadataKeySampleEnd      = "MeasurementRoundSampleEnd"
	MetadataKeySampleStep     = "MeasurementRoundSampleStep"

	// DefaultMaxConcurrentQueries is the default per-round query concurrency.
	DefaultMaxConcurrentQueries = 5
	// DefaultMaxWindow is the default finite observation window for range queries.
	DefaultMaxWindow = time.Hour
	// DefaultMaxResultBytes is the default serialized result byte budget per metric.
	DefaultMaxResultBytes = 1 << 20 // 1 MiB
)

var (
	// ErrFixedTimeUnsupported is returned when a provider cannot pin its queries to the
	// round's fixed evaluation time. Providers lacking the FixedTimeProvider capability
	// must fail explicitly instead of silently querying at wall-clock now.
	ErrFixedTimeUnsupported = errors.New("provider does not support fixed evaluation time measurements")
	// ErrRoundSpecChanged indicates the persisted round was built for a different metric
	// spec and cannot advance the current analysis.
	ErrRoundSpecChanged = errors.New("measurement round cannot advance: metric spec changed")
	// ErrRoundRevisionChanged indicates the persisted round was built for a different
	// rollout revision and cannot advance the current analysis.
	ErrRoundRevisionChanged = errors.New("measurement round cannot advance: rollout revision changed")
	// ErrResultTooLarge indicates a metric response exceeded the round result byte budget.
	ErrResultTooLarge = errors.New("measurement result exceeds round result byte limit")
	// ErrObservationWindowTooLarge indicates a range query window exceeded the round time
	// domain limit.
	ErrObservationWindowTooLarge = errors.New("measurement observation window exceeds round time domain limit")
	// ErrIdentityMismatch indicates a response arrived for an identity that was not the one
	// the round expected for the metric.
	ErrIdentityMismatch = errors.New("measurement response identity does not match round identity")
	// ErrDuplicateResponse indicates a terminal response for the same identity was already
	// recorded; the duplicate must be dropped rather than counted twice.
	ErrDuplicateResponse = errors.New("duplicate measurement response for round identity")
	// ErrRoundIncomplete indicates the round cannot be published because required metrics
	// have not confirmed a terminal observation.
	ErrRoundIncomplete = errors.New("measurement round is missing required metric confirmations")
	// ErrRoundCancelled indicates the round was cancelled before the query was started, so
	// no backend call was made.
	ErrRoundCancelled = errors.New("measurement round cancelled before query started")
)

// MetricStatus is the per-metric confirmation state recorded by a round.
type MetricStatus string

const (
	MetricStatusPending  MetricStatus = "Pending"
	MetricStatusComplete MetricStatus = "Complete"
	// MetricStatusPartial marks a completed response that carried provider warnings.
	MetricStatusPartial MetricStatus = "Partial"
	MetricStatusTimeout MetricStatus = "Timeout"
	MetricStatusFailed  MetricStatus = "Failed"
)

// Terminal reports whether the status is a definitive confirmation.
func (s MetricStatus) Terminal() bool {
	switch s {
	case MetricStatusComplete, MetricStatusPartial, MetricStatusTimeout, MetricStatusFailed:
		return true
	}
	return false
}

// RoundPhase is the lifecycle phase of a whole round.
type RoundPhase string

const (
	// RoundPhaseOpen means the round is still waiting for required metric confirmations.
	RoundPhaseOpen RoundPhase = "Open"
	// RoundPhaseComplete means every required metric confirmed a terminal observation.
	RoundPhaseComplete RoundPhase = "Complete"
	// RoundPhaseAborted means the round was cancelled or invalidated.
	RoundPhaseAborted RoundPhase = "Aborted"
)

// Config holds the resource limits enforced by a round.
type Config struct {
	// MaxConcurrentQueries limits how many backend queries a round runs in parallel.
	MaxConcurrentQueries int
	// MaxWindow is the finite time domain allowed for range queries.
	MaxWindow time.Duration
	// MaxResultBytes is the serialized byte budget for a single metric result.
	MaxResultBytes int
}

// DefaultConfig returns the safe default round limits.
func DefaultConfig() Config {
	return Config{
		MaxConcurrentQueries: DefaultMaxConcurrentQueries,
		MaxWindow:            DefaultMaxWindow,
		MaxResultBytes:       DefaultMaxResultBytes,
	}
}

// ConfigFromAnnotations resolves the round configuration from AnalysisRun annotations.
// The second return value reports whether the protocol was explicitly enabled.
func ConfigFromAnnotations(annotations map[string]string) (Config, bool, error) {
	cfg := DefaultConfig()
	enabled, ok := annotations[AnnotationEnable]
	if !ok {
		return cfg, false, nil
	}
	switch strings.ToLower(strings.TrimSpace(enabled)) {
	case "true", "1", "enabled":
	default:
		return cfg, false, nil
	}
	if raw := annotations[AnnotationMaxConcurrentQueries]; raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return cfg, false, fmt.Errorf("invalid %s annotation %q: must be a positive integer", AnnotationMaxConcurrentQueries, raw)
		}
		cfg.MaxConcurrentQueries = value
	}
	if raw := annotations[AnnotationMaxWindow]; raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return cfg, false, fmt.Errorf("invalid %s annotation %q: must be a positive Go duration", AnnotationMaxWindow, raw)
		}
		cfg.MaxWindow = value
	}
	if raw := annotations[AnnotationMaxResultBytes]; raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return cfg, false, fmt.Errorf("invalid %s annotation %q: must be a positive integer", AnnotationMaxResultBytes, raw)
		}
		cfg.MaxResultBytes = value
	}
	return cfg, true, nil
}

// RoundContext is the immutable identity of a round. It is fully serializable into
// Measurement metadata so a round can be reconstructed after a controller restart.
type RoundContext struct {
	// ID uniquely identifies the round within the AnalysisRun.
	ID string
	// EvaluationTime is the fixed cut point used by every query in the round.
	EvaluationTime time.Time
	// SpecDigest is the digest of the resolved metric specs the round was built for.
	SpecDigest string
	// Revision is the rollout revision (if any) the round was built for.
	Revision string
	// MaxWindow is the round time-domain limit.
	MaxWindow time.Duration
	// MaxResultBytes is the round per-result byte budget.
	MaxResultBytes int
}

// Metadata serializes the round-level context to Measurement metadata. The map never
// contains provider credentials or query parameters carrying secrets.
func (rc RoundContext) Metadata() map[string]string {
	return map[string]string{
		MetadataKeyRoundID:        rc.ID,
		MetadataKeyEvaluationTime: rc.EvaluationTime.UTC().Format(time.RFC3339Nano),
		MetadataKeySpecDigest:     rc.SpecDigest,
		MetadataKeyRevision:       rc.Revision,
		MetadataKeyRoundPhase:     string(RoundPhaseOpen),
	}
}

// SafeFields returns log fields describing the round without any secret material.
func (rc RoundContext) SafeFields() log.Fields {
	return log.Fields{
		"round":          rc.ID,
		"evaluationTime": rc.EvaluationTime.UTC().Format(time.RFC3339Nano),
		"specDigest":     rc.SpecDigest,
		"revision":       rc.Revision,
	}
}

// Identity derives the per-metric response identity used for duplicate detection. It binds
// the round, the metric and the concrete resolved query together.
func (rc RoundContext) Identity(metricName, resolvedQuery string) string {
	sum := sha256.Sum256([]byte(rc.ID + "|" + metricName + "|" + resolvedQuery))
	return hex.EncodeToString(sum[:])[:16]
}

// Round tracks the observations of one measurement round and enforces its resource limits.
type Round struct {
	RoundContext

	mu           sync.Mutex
	required     map[string]struct{}
	observations map[string]Observation
	phase        RoundPhase
	sem          chan struct{}
}

// Observation is the confirmation recorded for a single metric of a round.
type Observation struct {
	MetricName string
	Identity   string
	Status     MetricStatus
	Bytes      int
	Message    string
	// SampleStart/SampleEnd/SampleStep record the exact sample interval used for a range
	// query. They remain zero for instant queries.
	SampleStart time.Time
	SampleEnd   time.Time
	SampleStep  time.Duration
}

// Result is the outcome of a backend query executed through Round.Run.
type Result struct {
	Status      MetricStatus
	Bytes       int
	Message     string
	SampleStart time.Time
	SampleEnd   time.Time
	SampleStep  time.Duration
}

// SpecDigest computes a stable digest of the resolved metric specifications. A change in
// any metric spec produces a different digest and invalidates in-flight rounds.
func SpecDigest(metrics []v1alpha1.Metric) (string, error) {
	payload, err := json.Marshal(metrics)
	if err != nil {
		return "", fmt.Errorf("failed to digest metric specs: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:16], nil
}

// NewRound opens a new round pinned to the supplied evaluation time. The evaluation time
// must be captured once, before any parallel query is issued.
func NewRound(cfg Config, run *v1alpha1.AnalysisRun, metrics []v1alpha1.Metric, evaluationTime time.Time) (*Round, error) {
	digest, err := SpecDigest(metrics)
	if err != nil {
		return nil, err
	}
	revision := ""
	if run != nil && run.Annotations != nil {
		revision = run.Annotations[RevisionAnnotationKey]
	}
	idInput := fmt.Sprintf("%s|%s/%s|%s|%s",
		safeUID(run),
		namespaceOf(run),
		nameOf(run),
		evaluationTime.UTC().Format(time.RFC3339Nano),
		digest,
	)
	idSum := sha256.Sum256([]byte(idInput))
	rc := RoundContext{
		ID:             hex.EncodeToString(idSum[:])[:12],
		EvaluationTime: evaluationTime.UTC(),
		SpecDigest:     digest,
		Revision:       revision,
		MaxWindow:      cfg.MaxWindow,
		MaxResultBytes: cfg.MaxResultBytes,
	}
	required := make(map[string]struct{}, len(metrics))
	for _, m := range metrics {
		required[m.Name] = struct{}{}
	}
	return newRound(rc, required, cfg.MaxConcurrentQueries), nil
}

// RestoreRound rebuilds a round from a persisted RoundContext (e.g. after a controller
// restart) and seeds it with observations already recorded for the round.
func RestoreRound(rc RoundContext, requiredMetricNames []string, cfg Config, seed ...Observation) *Round {
	required := make(map[string]struct{}, len(requiredMetricNames))
	for _, name := range requiredMetricNames {
		required[name] = struct{}{}
	}
	r := newRound(rc, required, cfg.MaxConcurrentQueries)
	for _, obs := range seed {
		if obs.Identity == "" || obs.MetricName == "" {
			continue
		}
		r.observations[obs.MetricName] = obs
	}
	return r
}

func newRound(rc RoundContext, required map[string]struct{}, maxConcurrent int) *Round {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentQueries
	}
	return &Round{
		RoundContext: rc,
		required:     required,
		observations: map[string]Observation{},
		phase:        RoundPhaseOpen,
		sem:          make(chan struct{}, maxConcurrent),
	}
}

// Phase returns the current round phase.
func (r *Round) Phase() RoundPhase {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase
}

// Advanceable verifies that the round was built for the current spec digest and rollout
// revision. A changed spec or revision makes an old round unable to advance the analysis.
func (r *Round) Advanceable(currentDigest, currentRevision string) error {
	if r.SpecDigest != currentDigest {
		return ErrRoundSpecChanged
	}
	if r.Revision != currentRevision {
		return ErrRoundRevisionChanged
	}
	return nil
}

// Run executes fn as one query of the round, acquiring a concurrency slot first. If the
// context is cancelled before a slot is available, the query is never started and
// ErrRoundCancelled is returned. Terminal observations are recorded automatically and
// provider errors become Timeout or Failed observations so a round never silently loses a
// required metric. The returned Observation reflects what was actually recorded, including
// any byte-budget downgrade.
func (r *Round) Run(ctx context.Context, metricName, identity string, fn func(context.Context) (Result, error)) (Observation, error) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		// Cancellation must stop queries which have not started yet.
		return Observation{}, ErrRoundCancelled
	}
	defer func() { <-r.sem }()

	if err := ctx.Err(); err != nil {
		return Observation{}, ErrRoundCancelled
	}

	result, err := fn(ctx)
	if err != nil {
		status := MetricStatusFailed
		if errors.Is(err, context.DeadlineExceeded) {
			status = MetricStatusTimeout
		}
		obs, _ := r.Observe(Observation{
			MetricName: metricName,
			Identity:   identity,
			Status:     status,
			Message:    err.Error(),
		})
		return obs, err
	}
	if result.Status == "" {
		result.Status = MetricStatusComplete
	}
	return r.Observe(Observation{
		MetricName:  metricName,
		Identity:    identity,
		Status:      result.Status,
		Bytes:       result.Bytes,
		Message:     result.Message,
		SampleStart: result.SampleStart,
		SampleEnd:   result.SampleEnd,
		SampleStep:  result.SampleStep,
	})
}

// Observe records a metric observation, enforcing identity checks, duplicate suppression
// and the result byte budget. It returns the observation as stored.
func (r *Round) Observe(obs Observation) (Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.required[obs.MetricName]; !ok {
		return Observation{}, fmt.Errorf("metric %q is not part of round %s", obs.MetricName, r.ID)
	}
	existing, exists := r.observations[obs.MetricName]
	if exists {
		if existing.Identity != obs.Identity {
			return Observation{}, fmt.Errorf("%w: metric=%s expected=%s got=%s", ErrIdentityMismatch, obs.MetricName, existing.Identity, obs.Identity)
		}
		// A definitive success is never replaced or counted twice. Failed or timed out
		// observations may be retried within the same round.
		if existing.Status == MetricStatusComplete || existing.Status == MetricStatusPartial {
			return existing, ErrDuplicateResponse
		}
	}
	if r.MaxResultBytes > 0 && obs.Bytes > r.MaxResultBytes {
		obs.Status = MetricStatusFailed
		obs.Message = fmt.Sprintf("%s: %d > %d bytes", ErrResultTooLarge.Error(), obs.Bytes, r.MaxResultBytes)
	}
	if !obs.Status.Terminal() {
		obs.Status = MetricStatusFailed
	}
	r.observations[obs.MetricName] = obs
	return obs, nil
}

// Observation returns the recorded observation for a metric.
func (r *Round) Observation(metricName string) (Observation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	obs, ok := r.observations[metricName]
	return obs, ok
}

// Confirm publishes round completeness only when every required metric has a successful
// confirmation (Complete or Partial). Failed and timed out observations stay retryable and
// therefore keep the round open, so retries replay the same round instead of opening a new
// one. It returns the resulting phase and the sorted list of unconfirmed metrics. Successful
// observations from previous rounds are never counted for the current round.
func (r *Round) Confirm() (RoundPhase, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	missing := make([]string, 0)
	for name := range r.required {
		obs, ok := r.observations[name]
		if !ok || (obs.Status != MetricStatusComplete && obs.Status != MetricStatusPartial) {
			missing = append(missing, name)
			continue
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		r.phase = RoundPhaseComplete
	}
	return r.phase, missing
}

// Abort marks the round as aborted, e.g. when the AnalysisRun is terminating.
func (r *Round) Abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phase = RoundPhaseAborted
}

// ObservationCount returns the number of recorded observations.
func (r *Round) ObservationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.observations)
}

// MetadataFor merges round-level metadata with the metric-level observation metadata
// persisted on a Measurement.
func (r *Round) MetadataFor(obs Observation) map[string]string {
	md := r.RoundContext.Metadata()
	md[MetadataKeyMetricStatus] = string(obs.Status)
	md[MetadataKeyIdentity] = obs.Identity
	if !obs.SampleStart.IsZero() {
		md[MetadataKeySampleStart] = obs.SampleStart.UTC().Format(time.RFC3339Nano)
	}
	if !obs.SampleEnd.IsZero() {
		md[MetadataKeySampleEnd] = obs.SampleEnd.UTC().Format(time.RFC3339Nano)
	}
	if obs.SampleStep > 0 {
		md[MetadataKeySampleStep] = obs.SampleStep.String()
	}
	return md
}

// PublishComplete stamps the complete phase onto the metadata map of a confirmed round.
func (r *Round) PublishComplete(md map[string]string) {
	if r.Phase() == RoundPhaseComplete {
		md[MetadataKeyRoundPhase] = string(RoundPhaseComplete)
	}
}

// RoundFromMetadata reconstructs a RoundContext from Measurement metadata. The second
// return value is false when the metadata does not describe a round.
func RoundFromMetadata(md map[string]string) (RoundContext, bool) {
	if md == nil || md[MetadataKeyRoundID] == "" {
		return RoundContext{}, false
	}
	evalTime, err := time.Parse(time.RFC3339Nano, md[MetadataKeyEvaluationTime])
	if err != nil {
		return RoundContext{}, false
	}
	return RoundContext{
		ID:             md[MetadataKeyRoundID],
		EvaluationTime: evalTime,
		SpecDigest:     md[MetadataKeySpecDigest],
		Revision:       md[MetadataKeyRevision],
	}, true
}

// ObservationFromMetadata reconstructs a seeded observation from Measurement metadata.
func ObservationFromMetadata(metricName string, md map[string]string) (Observation, bool) {
	if _, ok := RoundFromMetadata(md); !ok {
		return Observation{}, false
	}
	status := MetricStatus(md[MetadataKeyMetricStatus])
	if !status.Terminal() {
		return Observation{}, false
	}
	obs := Observation{
		MetricName: metricName,
		Identity:   md[MetadataKeyIdentity],
		Status:     status,
	}
	if raw := md[MetadataKeySampleStart]; raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			obs.SampleStart = t
		}
	}
	if raw := md[MetadataKeySampleEnd]; raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			obs.SampleEnd = t
		}
	}
	if raw := md[MetadataKeySampleStep]; raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			obs.SampleStep = d
		}
	}
	return obs, true
}

// LatestOpenRound scans the AnalysisRun status and returns the context of the most recently
// opened, not yet completed round together with its persisted observations. Completed rounds
// are never resumed.
func LatestOpenRound(run *v1alpha1.AnalysisRun) (RoundContext, []Observation, bool) {
	if run == nil {
		return RoundContext{}, nil, false
	}
	var (
		found  bool
		latest RoundContext
	)
	for i := range run.Status.MetricResults {
		result := &run.Status.MetricResults[i]
		for j := range result.Measurements {
			md := result.Measurements[j].Metadata
			rc, ok := RoundFromMetadata(md)
			if !ok || md[MetadataKeyRoundPhase] != string(RoundPhaseOpen) {
				continue
			}
			// Measurements are appended over time; a different round ID means a newer round.
			if !found || latest.ID != rc.ID {
				latest = rc
			}
			found = true
		}
	}
	if !found {
		return RoundContext{}, nil, false
	}
	var seed []Observation
	for i := range run.Status.MetricResults {
		result := &run.Status.MetricResults[i]
		for j := range result.Measurements {
			md := result.Measurements[j].Metadata
			rc, ok := RoundFromMetadata(md)
			if !ok || rc.ID != latest.ID {
				continue
			}
			if obs, ok := ObservationFromMetadata(result.Name, md); ok {
				seed = append(seed, obs)
			}
		}
	}
	return latest, seed, true
}

// AlignToStepGrid snaps a range window onto exact step boundaries relative to the fixed
// evaluation time. The end is truncated to the latest step boundary and the start is
// rebuilt as a whole number of steps before the end, which guarantees retries issue
// byte-identical range requests and the window aligns to a precise step grid.
func AlignToStepGrid(evaluationTime, start, end time.Time, step time.Duration) (time.Time, time.Time) {
	if step <= 0 {
		return start, end
	}
	if end.After(evaluationTime) {
		end = evaluationTime
	}
	stepNanos := int64(step)
	endNanos := end.UnixNano()
	gridEndNanos := endNanos - (endNanos % stepNanos)
	gridEnd := time.Unix(0, gridEndNanos)

	windowSteps := end.Sub(start) / step
	if windowSteps < 0 {
		windowSteps = 0
	}
	gridStart := time.Unix(0, gridEndNanos-int64(windowSteps)*stepNanos)
	return gridStart, gridEnd
}

// RevisionAnnotationKey mirrors annotations.RevisionAnnotation without pulling the heavier
// annotations package into this leaf package.
const RevisionAnnotationKey = "rollout.argoproj.io/revision"

func safeUID(run *v1alpha1.AnalysisRun) string {
	if run == nil {
		return ""
	}
	return string(run.UID)
}

func namespaceOf(run *v1alpha1.AnalysisRun) string {
	if run == nil {
		return ""
	}
	return run.Namespace
}

func nameOf(run *v1alpha1.AnalysisRun) string {
	if run == nil {
		return ""
	}
	return run.Name
}
