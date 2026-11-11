// Package explain provides a read-only, side-effect free explanation of how an
// AnalysisRun candidate would be built for a fixed Rollout, its stable/latest
// ReplicaSets and a bounded set of AnalysisTemplate/ClusterAnalysisTemplate
// snapshots. It never creates AnalysisRuns, never calls metric providers and
// never reads cluster Secrets: secret references are kept as opaque sources and
// missing sensitive inputs are reported as Unresolved instead of being guessed.
package explain

import (
	appsv1 "k8s.io/api/apps/v1"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

const (
	// ReportAPIVersion is the API version used by explanation reports.
	ReportAPIVersion = "argoproj.io/explain/v1"
	// ReportKind is the kind of an explanation report.
	ReportKind = "ExplainAnalysisBuildReport"
	// ReportFormatVersion is bumped whenever the report schema changes.
	ReportFormatVersion = 1

	// ScopeNamespaced identifies a namespace scoped AnalysisTemplate.
	ScopeNamespaced Scope = "Namespaced"
	// ScopeCluster identifies a cluster scoped ClusterAnalysisTemplate.
	ScopeCluster Scope = "Cluster"

	// Resolution statuses.
	StatusResolved   ResolutionStatus = "Resolved"
	StatusUnresolved ResolutionStatus = "Unresolved"

	// Object kinds.
	kindRollout                 = "Rollout"
	kindReplicaSet              = "ReplicaSet"
	kindAnalysisTemplate        = "AnalysisTemplate"
	kindClusterAnalysisTemplate = "ClusterAnalysisTemplate"
	kindAnalysisRun             = "AnalysisRun"
	kindSecretInput             = "SecretInput"
)

// Scope is the template scope (namespaced vs cluster). Namespaced and cluster
// templates sharing the same name are never merged.
type Scope string

// ResolutionStatus describes whether a value could be resolved from the
// supplied snapshots without guessing.
type ResolutionStatus string

// Limits bounds the template graph traversal and expansion so that a malicious
// or broken reference graph cannot produce an unbounded candidate.
type Limits struct {
	// MaxTemplates is the maximum number of unique templates reachable.
	MaxTemplates int `json:"maxTemplates"`
	// MaxEdges is the maximum number of reference edges followed (including
	// repeated visits of a diamond shared template).
	MaxEdges int `json:"maxEdges"`
	// MaxDepth is the maximum reference nesting depth (root refs are depth 1).
	MaxDepth int `json:"maxDepth"`
	// MaxExpansionBytes bounds the total canonical JSON size of all unique
	// reached template objects.
	MaxExpansionBytes int `json:"maxExpansionBytes"`
}

// DefaultLimits returns the conservative default traversal limits.
func DefaultLimits() Limits {
	return Limits{
		MaxTemplates:      64,
		MaxEdges:          256,
		MaxDepth:          32,
		MaxExpansionBytes: 4 * 1024 * 1024,
	}
}

// RunMeta captures the ObjectMeta inputs of NewAnalysisRunFromTemplates. It is
// supplied by the caller so the library stays independent of controller
// specific label conventions.
type RunMeta struct {
	Name         string            `json:"name"`
	GenerateName string            `json:"generateName,omitempty"`
	Namespace    string            `json:"namespace"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// SecretInput is an optionally supplied value for a SecretKeyRef argument. The
// value is only held in memory for substitution; it is never serialized into a
// Report or logged.
type SecretInput struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	// Value carries the externally supplied secret value. Reports only retain
	// the opaque reference, never this field.
	Value string `json:"-"`
}

// Input is the fixed snapshot set used for an explanation. All objects are
// deep copied on entry and never mutated.
type Input struct {
	Rollout  *v1alpha1.Rollout         `json:"-"`
	StableRS *appsv1.ReplicaSet        `json:"-"`
	LatestRS *appsv1.ReplicaSet        `json:"-"`
	Analysis *v1alpha1.RolloutAnalysis `json:"-"`
	// AnalysisFieldPath records where the RolloutAnalysis lives in the Rollout
	// (e.g. spec.strategy.canary.analysis) for source attribution.
	AnalysisFieldPath string `json:"analysisFieldPath"`

	// Templates is the finite, closed set of namespace scoped templates that
	// references may resolve against. Only templates in the Rollout namespace
	// are visible, matching the namespace scoped lister behavior.
	Templates []*v1alpha1.AnalysisTemplate `json:"-"`
	// ClusterTemplates is the finite set of cluster scoped templates.
	ClusterTemplates []*v1alpha1.ClusterAnalysisTemplate `json:"-"`

	// SecretInputs optionally provides secret values. Missing entries stay
	// Unresolved instead of being guessed.
	SecretInputs []SecretInput `json:"-"`
	// SharedSecretNamespace is the externally configured equivalent of the
	// controller --analysis-shared-secret-namespace flag. It is never inferred
	// from the cluster.
	SharedSecretNamespace string `json:"sharedSecretNamespace,omitempty"`

	RunMeta RunMeta `json:"runMeta"`
	Limits  Limits  `json:"limits"`
}

// ObjectIdentity identifies an object by scope, namespace, name, UID and
// resourceVersion. Name alone is never treated as a unique identity.
type ObjectIdentity struct {
	Kind            string `json:"kind"`
	Scope           Scope  `json:"scope,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

// RefEdge is one AnalysisTemplateRef traversal between two objects.
type RefEdge struct {
	// From is the object holding the reference (the Rollout or a template).
	From ObjectIdentity `json:"from"`
	// FieldPath is the in-object location of the ref, e.g.
	// "spec.strategy.canary.analysis.templates[0]" or "spec.templates[2]".
	FieldPath string `json:"fieldPath"`
	// RefIndex is the index inside the owning templates list.
	RefIndex int `json:"refIndex"`
	// ClusterScope mirrors AnalysisTemplateRef.IsClusterScope().
	ClusterScope bool `json:"clusterScope"`
	// TemplateName is the referenced name.
	TemplateName string `json:"templateName"`
	// To is the resolved target object.
	To ObjectIdentity `json:"to"`
}

// SourceHop is one hop of a source path.
type SourceHop struct {
	// Edge is the reference edge followed to reach Object. It is nil on the
	// root hop.
	Edge *RefEdge `json:"edge,omitempty"`
	// Object is the object positioned at this hop.
	Object ObjectIdentity `json:"object"`
	// Field is the location inside Object (empty for intermediate hops).
	Field string `json:"field,omitempty"`
}

// SourcePath is a complete path from the Rollout root to a specific field of a
// reached object.
type SourcePath struct {
	Hops []SourceHop `json:"hops"`
}

// ObjectDigest records the canonical digest of a used object.
type ObjectDigest struct {
	Identity ObjectIdentity `json:"identity"`
	// Digest is the sha256 hex digest of the canonical JSON encoding.
	Digest string `json:"digest"`
	// ByteSize is the size of the canonical JSON encoding.
	ByteSize int `json:"byteSize"`
}

// VisitRecord describes a single DFS visit of a template, including diamond
// re-visits that are later removed by the unique-template filter.
type VisitRecord struct {
	Sequence int            `json:"sequence"`
	Identity ObjectIdentity `json:"identity"`
	Depth    int            `json:"depth"`
	// Deduped is true when FilterUniqueTemplates dropped this occurrence
	// because an earlier visit of the same scope/name won.
	Deduped bool `json:"deduped"`
	// EdgePath is the chain of refs followed to reach this visit.
	EdgePath []RefEdge `json:"edgePath"`
}

// TraversalSummary records how the reference graph was walked, in the exact
// traversal, grouping and de-duplication order of getAnalysisTemplatesFromRefs.
type TraversalSummary struct {
	RootRefs []RefEdge     `json:"rootRefs"`
	Edges    []RefEdge     `json:"edges"`
	Visits   []VisitRecord `json:"visits"`
	// UniqueNamespaced is the final de-duplicated namespaced template order,
	// matching FilterUniqueTemplates output.
	UniqueNamespaced []ObjectIdentity `json:"uniqueNamespaced"`
	// UniqueCluster is the final de-duplicated cluster template order.
	UniqueCluster []ObjectIdentity `json:"uniqueCluster"`
	// Cycles holds bounded cycle diagnostics when a reference loop is found.
	Cycles []CycleDiagnostic `json:"cycles,omitempty"`
}

// CycleDiagnostic is a bounded reference cycle path.
type CycleDiagnostic struct {
	// Path is the edge chain that closes back onto an ancestor.
	Path []RefEdge `json:"path"`
	// BackTo is the ancestor identity re-entered by the cycle.
	BackTo ObjectIdentity `json:"backTo"`
}

// SecretRef is an opaque secret reference; no secret data is ever carried.
type SecretRef struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Key          string `json:"key"`
	SharedSecret bool   `json:"sharedSecret"`
	// Supplied indicates whether an external SecretInput was provided.
	Supplied bool `json:"supplied"`
}

// PodTemplateHashSource attributes a podTemplateHashValue argument to a
// ReplicaSet snapshot label.
type PodTemplateHashSource struct {
	// RS is the ReplicaSet identity (stable or latest).
	RS ObjectIdentity `json:"rs"`
	// Which is "Stable" or "Latest".
	Which string `json:"which"`
	// LabelKey is the label read from the ReplicaSet.
	LabelKey string `json:"labelKey"`
	// Present indicates the label existed on the snapshot.
	Present bool `json:"present"`
}

// ValueFromExplanation explains the adopted ValueFrom of an argument.
type ValueFromExplanation struct {
	// Kind is SecretKeyRef, FieldRef or PodTemplateHashValue.
	Kind string `json:"kind,omitempty"`
	// Secret is set for secret references and stays fully opaque.
	Secret *SecretRef `json:"secret,omitempty"`
	// FieldPath is the rollout field path for fieldRef arguments.
	FieldPath string `json:"fieldPath,omitempty"`
	// FieldRefObject is the object read by a fieldRef (always the Rollout).
	FieldRefObject *ObjectIdentity `json:"fieldRefObject,omitempty"`
	// PodTemplateHash is set for podTemplateHashValue arguments.
	PodTemplateHash *PodTemplateHashSource `json:"podTemplateHash,omitempty"`
}

// ArgDefinition is one template-side occurrence of an argument definition.
type ArgDefinition struct {
	Source SourcePath `json:"source"`
	// ValuePresent distinguishes a nil Value from a pointer to "".
	ValuePresent bool `json:"valuePresent"`
	// ValueIsEmpty is true when Value is a non-nil pointer to "".
	ValueIsEmpty bool `json:"valueIsEmpty,omitempty"`
	// Value carries the default value when present and non-secret.
	Value string `json:"value,omitempty"`
	// Secret is set when the definition itself uses a secret ValueFrom.
	Secret *SecretRef `json:"secret,omitempty"`
	// Winner marks the occurrence actually adopted by flattenArgs. Diamond
	// duplicates with the same name are not all marked as winners.
	Winner bool `json:"winner"`
	// Deduped marks occurrences that lost first-occurrence de-duplication.
	Deduped bool `json:"deduped,omitempty"`
}

// ArgOverride records an incoming Rollout analysis argument overriding a
// template default.
type ArgOverride struct {
	Source SourcePath `json:"source"`
	// OverrideKind is Value or ValueFrom.
	OverrideKind string `json:"overrideKind"`
	// ValuePresent distinguishes nil from a pointer to "".
	ValuePresent bool                  `json:"valuePresent"`
	ValueIsEmpty bool                  `json:"valueIsEmpty,omitempty"`
	Value        string                `json:"value,omitempty"`
	ValueFrom    *ValueFromExplanation `json:"valueFrom,omitempty"`
}

// ArgExplanation is the full provenance chain of one final run argument.
type ArgExplanation struct {
	Name   string           `json:"name"`
	Status ResolutionStatus `json:"status"`
	// HasValue means the adopted argument carries a non-nil Value pointer.
	HasValue bool `json:"hasValue"`
	// ValueIsEmpty means Value is a non-nil pointer to "".
	ValueIsEmpty bool `json:"valueIsEmpty,omitempty"`
	// Value is the adopted value, redacted when secret sourced.
	Value string `json:"value,omitempty"`
	// Redacted means Value originates from a secret and is withheld.
	Redacted bool `json:"redacted,omitempty"`
	// ValueFrom explains the adopted ValueFrom, if any.
	ValueFrom *ValueFromExplanation `json:"valueFrom,omitempty"`
	// Definitions lists every template definition in traversal order.
	Definitions []ArgDefinition `json:"definitions"`
	// Winner is the source path of the adopted template default.
	Winner *SourcePath `json:"winner,omitempty"`
	// Override is the incoming argument override, when one was applied.
	Override *ArgOverride `json:"override,omitempty"`
}

// ParamSegment is a structured source segment for one replaced {{args.*}}
// fragment. Byte and rune ranges are provided both in the marshaled metric
// JSON (source) and in the escaped, substituted output, so segments stay
// mappable across UTF-8 and JSON escaping boundaries.
type ParamSegment struct {
	FieldPath       string `json:"fieldPath"`
	ArgName         string `json:"argName"`
	RawTag          string `json:"rawTag"`
	SourceByteRange [2]int `json:"sourceByteRange"`
	SourceRuneRange [2]int `json:"sourceRuneRange"`
	OutputByteRange [2]int `json:"outputByteRange"`
	OutputRuneRange [2]int `json:"outputRuneRange"`
	// ArgValueSource points at the adopted argument source for this fragment.
	ArgValueSource *SourcePath `json:"argValueSource,omitempty"`
	// SecretRef is the opaque secret reference when the fragment is secret fed.
	SecretRef *SecretRef       `json:"secretRef,omitempty"`
	Status    ResolutionStatus `json:"status"`
}

// MetricExplanation explains one flattened metric and its resolved form.
type MetricExplanation struct {
	Name   string           `json:"name"`
	Source SourcePath       `json:"source"`
	Status ResolutionStatus `json:"status"`
	// UnresolvedReasons lists missing args/secrets or unknown tags.
	UnresolvedReasons []string `json:"unresolvedReasons,omitempty"`
	// Segments lists every substituted parameter fragment in source order.
	Segments []ParamSegment `json:"segments,omitempty"`
	// Resolved is the metric after ResolveMetricArgs semantics, with secret
	// fed fields redacted. It is nil when Status is Unresolved.
	Resolved *v1alpha1.Metric `json:"resolved,omitempty"`
	// RedactedFields lists metric field paths whose resolved values are secret
	// fed and therefore withheld.
	RedactedFields []string `json:"redactedFields,omitempty"`
}

// RuleExplanation explains a dryRun or measurementRetention rule.
type RuleExplanation struct {
	Kind       string     `json:"kind"`
	MetricName string     `json:"metricName"`
	Source     SourcePath `json:"source"`
	// Origin is RolloutAnalysis or the owning template identity name.
	Origin string `json:"origin"`
	// Limit is retained for measurementRetention rules.
	Limit int32 `json:"limit,omitempty"`
	// MatchedMetrics are the flattened metric names matched by the rule regex
	// at runtime semantics (GetDryRunMetrics/GetMeasurementRetentionMetrics).
	MatchedMetrics []string `json:"matchedMetrics,omitempty"`
	// MatchError records the runtime "didn't match any metric" diagnostic.
	MatchError string `json:"matchError,omitempty"`
}

// Conflict describes a construction conflict with the two shortest source
// paths that establish it.
type Conflict struct {
	// Kind is DuplicateMetric, ConflictingArgDefault, DuplicateDryRunRule or
	// DuplicateRetentionRule.
	Kind  string `json:"kind"`
	Field string `json:"field"`
	Name  string `json:"name"`
	// Paths are the two shortest conflicting source paths. When more than two
	// definitions exist, only the two shortest are retained.
	Paths []SourcePath `json:"paths"`
	// ConstructorError is the exact error returned by the real constructor.
	ConstructorError string `json:"constructorError"`
}

// UnresolvedItem records a value that could not be resolved without guessing.
type UnresolvedItem struct {
	Kind    string       `json:"kind"`
	Name    string       `json:"name"`
	Reason  string       `json:"reason"`
	Secret  *SecretRef   `json:"secret,omitempty"`
	Sources []SourcePath `json:"sources,omitempty"`
}

// Diagnostic is a non-fatal observation (e.g. missing pod hash label).
type Diagnostic struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Candidate is the constructed AnalysisRun candidate plus its digest. The
// candidate is produced by the real NewAnalysisRunFromTemplates function.
type Candidate struct {
	// AnalysisRun is the constructed candidate (never created in the cluster).
	AnalysisRun v1alpha1.AnalysisRun `json:"analysisRun"`
	// Digest is the sha256 of the canonical candidate JSON.
	Digest string `json:"digest"`
}

// Report is the serializable explanation artifact.
type Report struct {
	APIVersion       string              `json:"apiVersion"`
	Kind             string              `json:"kind"`
	FormatVersion    int                 `json:"formatVersion"`
	Complete         bool                `json:"complete"`
	AnalysisPath     string              `json:"analysisPath"`
	Limits           Limits              `json:"limits"`
	Objects          []ObjectDigest      `json:"objects"`
	Traversal        TraversalSummary    `json:"traversal"`
	Candidate        *Candidate          `json:"candidate,omitempty"`
	ConstructorError string              `json:"constructorError,omitempty"`
	Args             []ArgExplanation    `json:"args"`
	Metrics          []MetricExplanation `json:"metrics"`
	Rules            []RuleExplanation   `json:"rules"`
	Conflicts        []Conflict          `json:"conflicts,omitempty"`
	Unresolved       []UnresolvedItem    `json:"unresolved,omitempty"`
	Diagnostics      []Diagnostic        `json:"diagnostics,omitempty"`
	// ReportDigest is the sha256 over the canonical report body with this
	// field left empty; it acts as the completion/integrity marker.
	ReportDigest string `json:"reportDigest,omitempty"`
}
