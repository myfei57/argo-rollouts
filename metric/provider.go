package metric

import (
	"context"

	"github.com/argoproj/argo-rollouts/metric/measurementround"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

// Provider methods to query an external systems and generate a measurement
type Provider interface {
	// Run start a new external system call for a measurement
	// Should be idempotent and do nothing if a call has already been started
	Run(*v1alpha1.AnalysisRun, v1alpha1.Metric) v1alpha1.Measurement
	// Resume Checks if the external system call is finished and returns the current measurement
	Resume(*v1alpha1.AnalysisRun, v1alpha1.Metric, v1alpha1.Measurement) v1alpha1.Measurement
	// Terminate will terminate an in-progress measurement
	Terminate(*v1alpha1.AnalysisRun, v1alpha1.Metric, v1alpha1.Measurement) v1alpha1.Measurement
	// GarbageCollect is used to garbage collect completed measurements to the specified limit
	GarbageCollect(*v1alpha1.AnalysisRun, v1alpha1.Metric, int) error
	// Type gets the provider type
	Type() string
	// GetMetadata returns any additional metadata which providers need to store/display as part
	// of the metric result. For example, Prometheus uses is to store the final resolved queries.
	GetMetadata(metric v1alpha1.Metric) map[string]string
}

// FixedTimeProvider is an optional Provider capability used by the MeasurementRound
// protocol. Implementations pin every query to the round's fixed evaluation time instead
// of evaluating wall-clock now independently on each call.
//
// A provider which cannot guarantee fixed-time queries must NOT implement this interface;
// the controller then fails the round explicitly with measurementround.ErrFixedTimeUnsupported
// rather than silently mixing pinned and unpinned queries. Identical timestamps returned by
// independent backends must never be described as an atomic database snapshot: the contract
// only guarantees a common evaluation time, not cross-backend transactional consistency.
type FixedTimeProvider interface {
	Provider
	// RunAt performs the measurement using the round's fixed evaluation time and observation
	// window. The context bounds the query lifetime; cancellation before a query starts must
	// avoid the backend call entirely.
	RunAt(ctx context.Context, run *v1alpha1.AnalysisRun, metric v1alpha1.Metric, rc measurementround.RoundContext) v1alpha1.Measurement
}
