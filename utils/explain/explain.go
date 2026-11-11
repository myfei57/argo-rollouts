package explain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	analysisutil "github.com/argoproj/argo-rollouts/utils/analysis"
)

// explainer carries the working state of one explanation run.
type explainer struct {
	in         Input
	graph      *graph
	flat       *flattenResult
	slotByName map[string]*argSlot
	uniqueNS   []*v1alpha1.AnalysisTemplate
	uniqueCL   []*v1alpha1.ClusterAnalysisTemplate
}

// Explain constructs AnalysisRun candidates for the fixed Rollout, its
// stable/latest ReplicaSets and the bounded template snapshot set, and returns
// a Report explaining the full provenance of every adopted value. It never
// creates a run, never invokes a provider and never reads cluster Secrets.
//
// The construction itself is always delegated to the production functions
// (BuildArgumentsForRolloutAnalysisRun and NewAnalysisRunFromTemplates), so a
// successful candidate is identical to what the controller would build from
// the same snapshots.
func Explain(in Input) (*Report, error) {
	if err := validateInput(&in); err != nil {
		return nil, err
	}
	in = deepCopyInput(in)
	if in.Limits == (Limits{}) {
		in.Limits = DefaultLimits()
	}

	e := &explainer{in: in, slotByName: map[string]*argSlot{}}

	// Traversal errors (not found, cycle, limits) refuse any candidate.
	g, uniqueNS, uniqueCL, err := traverse(&in)
	e.graph = g
	if err != nil {
		return nil, err
	}
	e.uniqueNS, e.uniqueCL = uniqueNS, uniqueCL
	e.flat = flattenTemplates(g, uniqueNS, uniqueCL)
	for _, slot := range e.flat.slots {
		e.slotByName[slot.name] = slot
	}

	report := &Report{
		APIVersion:    ReportAPIVersion,
		Kind:          ReportKind,
		FormatVersion: ReportFormatVersion,
		AnalysisPath:  in.AnalysisFieldPath,
		Limits:        in.Limits,
		Traversal:     g.summary(uniqueNS, uniqueCL),
		Args:          []ArgExplanation{},
		Metrics:       []MetricExplanation{},
		Rules:         []RuleExplanation{},
	}
	report.Objects = e.objectDigests(uniqueNS, uniqueCL)

	// Incoming argument values are derived from the Rollout/ReplicaSet
	// snapshots by the production helper, never re-implemented.
	incoming, buildErr := analysisutil.BuildArgumentsForRolloutAnalysisRun(
		in.Analysis.Args, in.StableRS, in.LatestRS, in.Rollout)
	if buildErr != nil {
		report.ConstructorError = buildErr.Error()
		report.Conflicts = append(report.Conflicts, e.flat.conflicts...)
		report.Unresolved = append(report.Unresolved, e.collectUnresolved(nil, nil)...)
		report.Diagnostics = e.diagnostics()
		finalizeDigest(report)
		return report, nil
	}
	e.flat.applyIncomingArgs(g, incoming)
	e.enrichOverrides()

	// Authoritative construction via the production constructor.
	candidate, constructorErr := analysisutil.NewAnalysisRunFromTemplates(
		uniqueNS, uniqueCL, incoming,
		in.Analysis.DryRun, in.Analysis.MeasurementRetention,
		in.RunMeta.Labels, in.RunMeta.Annotations,
		in.RunMeta.Name, in.RunMeta.GenerateName, in.RunMeta.Namespace)

	report.Conflicts = append(report.Conflicts, e.flat.conflicts...)
	if constructorErr != nil {
		report.ConstructorError = constructorErr.Error()
		report.Args = e.argExplanations(nil)
		report.Unresolved = append(report.Unresolved, e.collectUnresolved(nil, nil)...)
		report.Diagnostics = e.diagnostics()
		finalizeDigest(report)
		return report, nil
	}

	// The simulation must agree with the production constructor field by field.
	if err := e.crossCheckCandidate(candidate); err != nil {
		return nil, err
	}

	candidateDigest, err := digestOf(candidate)
	if err != nil {
		return nil, err
	}
	report.Candidate = &Candidate{AnalysisRun: *candidate, Digest: candidateDigest}
	report.Args = e.argExplanations(candidate)
	report.Rules = e.ruleExplanations(candidate)
	report.Metrics = e.metricExplanations(candidate)
	report.Unresolved = append(report.Unresolved, e.collectUnresolved(candidate, report.Metrics)...)
	report.Diagnostics = e.diagnostics()
	report.Complete = len(report.Unresolved) == 0 && len(report.Conflicts) == 0
	finalizeDigest(report)
	return report, nil
}

func validateInput(in *Input) error {
	if in.Rollout == nil {
		return &ExplainError{Reason: ReasonInvalidInput, Message: "rollout snapshot is required"}
	}
	if in.Analysis == nil {
		return &ExplainError{Reason: ReasonInvalidInput, Message: "rollout analysis spec is required"}
	}
	if in.StableRS == nil || in.LatestRS == nil {
		return &ExplainError{Reason: ReasonInvalidInput, Message: "stable and latest ReplicaSet snapshots are required"}
	}
	if in.AnalysisFieldPath == "" {
		in.AnalysisFieldPath = "spec.strategy.canary.analysis"
	}
	return nil
}

func deepCopyInput(in Input) Input {
	out := in
	out.Rollout = in.Rollout.DeepCopy()
	out.StableRS = in.StableRS.DeepCopy()
	out.LatestRS = in.LatestRS.DeepCopy()
	out.Analysis = in.Analysis.DeepCopy()
	out.Templates = make([]*v1alpha1.AnalysisTemplate, 0, len(in.Templates))
	for _, t := range in.Templates {
		if t != nil {
			out.Templates = append(out.Templates, t.DeepCopy())
		}
	}
	out.ClusterTemplates = make([]*v1alpha1.ClusterAnalysisTemplate, 0, len(in.ClusterTemplates))
	for _, t := range in.ClusterTemplates {
		if t != nil {
			out.ClusterTemplates = append(out.ClusterTemplates, t.DeepCopy())
		}
	}
	if in.RunMeta.Labels != nil {
		out.RunMeta.Labels = cloneStringMap(in.RunMeta.Labels)
	}
	if in.RunMeta.Annotations != nil {
		out.RunMeta.Annotations = cloneStringMap(in.RunMeta.Annotations)
	}
	if in.SecretInputs != nil {
		out.SecretInputs = append([]SecretInput(nil), in.SecretInputs...)
	}
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// crossCheckCandidate guarantees the instrumented flatten/merge layer cannot
// drift from the production constructor output.
func (e *explainer) crossCheckCandidate(candidate *v1alpha1.AnalysisRun) error {
	if len(candidate.Spec.Metrics) != len(e.flat.metrics) {
		return &ExplainError{Reason: ReasonDiverged, Message: "metric count diverges from NewAnalysisRunFromTemplates"}
	}
	for i, src := range e.flat.metrics {
		if candidate.Spec.Metrics[i].Name != src.metric.Name {
			return &ExplainError{Reason: ReasonDiverged, Message: fmt.Sprintf("metric order diverges at index %d", i)}
		}
	}
	if len(candidate.Spec.Args) != len(e.flat.slots) {
		return &ExplainError{Reason: ReasonDiverged, Message: "arg count diverges from NewAnalysisRunFromTemplates"}
	}
	for i, slot := range e.flat.slots {
		if !argEqual(candidate.Spec.Args[i], slot.arg) {
			return &ExplainError{Reason: ReasonDiverged, Message: fmt.Sprintf("arg %q diverges from MergeArgs", slot.name)}
		}
	}
	if len(candidate.Spec.DryRun) != len(e.flat.dryRules) {
		return &ExplainError{Reason: ReasonDiverged, Message: "dryRun rule count diverges"}
	}
	if len(candidate.Spec.MeasurementRetention) != len(e.flat.retentionRules) {
		return &ExplainError{Reason: ReasonDiverged, Message: "measurementRetention rule count diverges"}
	}
	return nil
}

func argEqual(a, b v1alpha1.Argument) bool {
	if a.Name != b.Name {
		return false
	}
	if (a.Value == nil) != (b.Value == nil) {
		return false
	}
	if a.Value != nil && *a.Value != *b.Value {
		return false
	}
	if (a.ValueFrom == nil) != (b.ValueFrom == nil) {
		return false
	}
	if a.ValueFrom != nil && *a.ValueFrom != *b.ValueFrom {
		return false
	}
	return true
}

// enrichOverrides attaches Rollout-side ValueFrom provenance (fieldRef and
// podTemplateHashValue) to incoming overrides using the original
// AnalysisRunArgument definitions.
func (e *explainer) enrichOverrides() {
	for i := range e.in.Analysis.Args {
		raw := e.in.Analysis.Args[i]
		slot := e.slotByName[raw.Name]
		if slot == nil || slot.override == nil || raw.ValueFrom == nil {
			continue
		}
		if raw.ValueFrom.FieldRef != nil {
			slot.override.OverrideKind = "ValueFrom"
			slot.override.Value = ""
			slot.override.ValuePresent = false
			slot.override.ValueIsEmpty = false
			rolloutID := e.graph.rolloutID
			slot.override.ValueFrom = &ValueFromExplanation{
				Kind:           "FieldRef",
				FieldPath:      raw.ValueFrom.FieldRef.FieldPath,
				FieldRefObject: &rolloutID,
			}
		} else if raw.ValueFrom.PodTemplateHashValue != nil {
			slot.override.OverrideKind = "ValueFrom"
			slot.override.Value = ""
			slot.override.ValuePresent = false
			slot.override.ValueIsEmpty = false
			slot.override.ValueFrom = &ValueFromExplanation{
				Kind:            "PodTemplateHashValue",
				PodTemplateHash: e.graph.explainPodTemplateHash(*raw.ValueFrom.PodTemplateHashValue),
			}
		}
	}
}

func (e *explainer) argExplanations(candidate *v1alpha1.AnalysisRun) []ArgExplanation {
	out := make([]ArgExplanation, 0, len(e.flat.slots))
	for _, slot := range e.flat.slots {
		adopted := slot.arg
		if candidate != nil {
			for _, a := range candidate.Spec.Args {
				if a.Name == slot.name {
					adopted = a
					break
				}
			}
		}
		exp := ArgExplanation{
			Name:        slot.name,
			Status:      StatusResolved,
			Definitions: make([]ArgDefinition, 0, len(slot.definitions)),
		}
		if adopted.Value == nil && adopted.ValueFrom == nil {
			exp.Status = StatusUnresolved
		}
		exp.HasValue = adopted.Value != nil
		exp.ValueIsEmpty = adopted.Value != nil && *adopted.Value == ""
		if adopted.Value != nil {
			exp.Value = *adopted.Value
		}
		if ref := secretRefOfArgument(adopted, e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets); ref != nil {
			exp.ValueFrom = &ValueFromExplanation{Kind: "SecretKeyRef", Secret: ref}
			exp.Redacted = true
			exp.Value = ""
			if !ref.Supplied {
				exp.Status = StatusUnresolved
			}
		} else if adopted.ValueFrom != nil {
			exp.ValueFrom = e.graph.explainValueFrom(adopted.ValueFrom)
		}
		for _, occ := range slot.definitions {
			isWinner := slot.winner != nil && occ.path.String() == slot.winner.path.String() &&
				occ.index == slot.winner.index
			def := ArgDefinition{
				Source:       occ.path,
				ValuePresent: occ.arg.Value != nil,
				ValueIsEmpty: occ.arg.Value != nil && *occ.arg.Value == "",
				Winner:       isWinner,
			}
			if occ.arg.Value != nil {
				def.Value = *occ.arg.Value
			}
			if ref := secretRefOfArgument(occ.arg, e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets); ref != nil {
				def.Secret = ref
			}
			exp.Definitions = append(exp.Definitions, def)
		}
		if slot.winner != nil {
			winner := slot.winner.path
			exp.Winner = &winner
		}
		exp.Override = slot.override
		out = append(out, exp)
	}
	return out
}

func (e *explainer) metricExplanations(candidate *v1alpha1.AnalysisRun) []MetricExplanation {
	out := make([]MetricExplanation, 0, len(e.flat.metrics))
	for i, src := range e.flat.metrics {
		res := e.resolveMetric(src, candidate.Spec.Args)
		// Sanity: the resolved-before-redaction metric for fully resolved
		// non-secret metrics must equal the production output.
		if res.resolved != nil && len(res.secretFields) == 0 {
			realMetric, err := analysisutil.ResolveMetricArgs(src.metric, candidate.Spec.Args)
			if err != nil || !metricEqual(realMetric, res.resolved) {
				res.explanation.Status = StatusUnresolved
				res.explanation.UnresolvedReasons = append(res.explanation.UnresolvedReasons,
					"internal drift: resolved metric differs from production ResolveMetricArgs")
				res.explanation.Resolved = nil
			}
		}
		_ = i
		out = append(out, res.explanation)
	}
	return out
}

func metricEqual(a, b *v1alpha1.Metric) bool {
	if a == nil || b == nil {
		return a == b
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func (e *explainer) ruleExplanations(candidate *v1alpha1.AnalysisRun) []RuleExplanation {
	out := make([]RuleExplanation, 0, len(e.flat.dryRules)+len(e.flat.retentionRules))
	// The production helpers key their result map by *metric name*, so they
	// cannot answer "which metrics match this regex". We therefore evaluate
	// each rule regex directly, while still calling the production helpers to
	// reproduce their exact "didn't match any metric name(s)" errors.
	_, dryErr := analysisutil.GetDryRunMetrics(candidate.Spec.DryRun, candidate.Spec.Metrics)
	_, retErr := analysisutil.GetMeasurementRetentionMetrics(candidate.Spec.MeasurementRetention, candidate.Spec.Metrics)
	matchedMetricNames := func(pattern string) []string {
		var matched []string
		for _, m := range candidate.Spec.Metrics {
			if ok, _ := regexp.MatchString(pattern, m.Name); ok {
				matched = append(matched, m.Name)
			}
		}
		return matched
	}
	for _, r := range e.flat.dryRules {
		origin := "RolloutAnalysis"
		if r.node != nil {
			origin = renderIdentity(r.node.id)
		}
		rule := RuleExplanation{
			Kind:           "DryRun",
			MetricName:     r.dryRun.MetricName,
			Source:         r.path,
			Origin:         origin,
			MatchedMetrics: matchedMetricNames(r.dryRun.MetricName),
		}
		if dryErr != nil && len(rule.MatchedMetrics) == 0 {
			rule.MatchError = dryErr.Error()
		}
		out = append(out, rule)
	}
	for _, r := range e.flat.retentionRules {
		origin := "RolloutAnalysis"
		if r.node != nil {
			origin = renderIdentity(r.node.id)
		}
		rule := RuleExplanation{
			Kind:           "MeasurementRetention",
			MetricName:     r.rule.MetricName,
			Source:         r.path,
			Origin:         origin,
			Limit:          r.rule.Limit,
			MatchedMetrics: matchedMetricNames(r.rule.MetricName),
		}
		if retErr != nil && len(rule.MatchedMetrics) == 0 {
			rule.MatchError = retErr.Error()
		}
		out = append(out, rule)
	}
	return out
}

func (e *explainer) collectUnresolved(candidate *v1alpha1.AnalysisRun, metricExps []MetricExplanation) []UnresolvedItem {
	var items []UnresolvedItem
	seen := map[string]bool{}
	add := func(item UnresolvedItem) {
		key := item.Kind + "|" + item.Name + "|" + item.Reason
		if seen[key] {
			return
		}
		seen[key] = true
		items = append(items, item)
	}
	for _, slot := range e.flat.slots {
		if slot.arg.Value != nil || slot.arg.ValueFrom != nil {
			continue
		}
		var sources []SourcePath
		if slot.winner != nil {
			sources = append(sources, slot.winner.path)
		}
		add(UnresolvedItem{
			Kind:    "Argument",
			Name:    slot.name,
			Reason:  fmt.Sprintf("args.%s was not resolved", slot.name),
			Sources: sources,
		})
	}
	// Secret references that were never supplied.
	for _, slot := range e.flat.slots {
		ref := secretRefOfArgument(slot.arg, e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets)
		if ref != nil && !ref.Supplied {
			add(UnresolvedItem{
				Kind:   "SecretArgument",
				Name:   slot.name,
				Reason: fmt.Sprintf("secret %s/%s key %q is unavailable; values are never read from the cluster and never guessed", ref.Namespace, ref.Name, ref.Key),
				Secret: ref,
			})
		}
	}
	// Metric level unresolved state comes from the instrumented resolution,
	// which substitutes supplied secrets in-memory and never guesses missing
	// ones. Using raw run-spec args here would falsely flag supplied secrets
	// because the run spec intentionally keeps their ValueFrom opaque.
	for _, m := range metricExps {
		if m.Status != StatusUnresolved {
			continue
		}
		add(UnresolvedItem{
			Kind:    "MetricResolution",
			Name:    m.Name,
			Reason:  strings.Join(m.UnresolvedReasons, "; "),
			Sources: []SourcePath{m.Source},
		})
		for _, seg := range m.Segments {
			if seg.SecretRef != nil && !seg.SecretRef.Supplied {
				add(UnresolvedItem{
					Kind:   "SecretArgument",
					Name:   seg.ArgName,
					Reason: fmt.Sprintf("metric %q needs secret %s/%s key %q which was not supplied", m.Name, seg.SecretRef.Namespace, seg.SecretRef.Name, seg.SecretRef.Key),
					Secret: seg.SecretRef,
				})
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func (e *explainer) diagnostics() []Diagnostic {
	var out []Diagnostic
	for i := range e.in.Analysis.Args {
		raw := e.in.Analysis.Args[i]
		if raw.ValueFrom == nil || raw.ValueFrom.PodTemplateHashValue == nil {
			continue
		}
		var rs *appsv1.ReplicaSet
		which := *raw.ValueFrom.PodTemplateHashValue
		switch which {
		case v1alpha1.Stable:
			rs = e.in.StableRS
		case v1alpha1.Latest:
			rs = e.in.LatestRS
		}
		if rs == nil || rs.Labels == nil {
			out = append(out, Diagnostic{
				Kind:    "MissingPodTemplateHash",
				Message: fmt.Sprintf("argument %q references %s ReplicaSet pod template hash but the snapshot carries no labels", raw.Name, which),
			})
			continue
		}
		if _, ok := rs.Labels[v1alpha1.DefaultRolloutUniqueLabelKey]; !ok {
			out = append(out, Diagnostic{
				Kind:    "MissingPodTemplateHash",
				Message: fmt.Sprintf("argument %q references %s ReplicaSet label %q which is absent on the snapshot", raw.Name, which, v1alpha1.DefaultRolloutUniqueLabelKey),
			})
		}
	}
	return out
}

func (e *explainer) objectDigests(uniqueNS []*v1alpha1.AnalysisTemplate, uniqueCL []*v1alpha1.ClusterAnalysisTemplate) []ObjectDigest {
	out := make([]ObjectDigest, 0, 3+len(uniqueNS)+len(uniqueCL))
	appendDigest := func(id ObjectIdentity, obj any) {
		d, err := digestOf(obj)
		if err != nil {
			return
		}
		size, _ := jsonSize(obj)
		out = append(out, ObjectDigest{Identity: id, Digest: d, ByteSize: size})
	}
	appendDigest(e.graph.rolloutID, e.in.Rollout)
	appendDigest(e.graph.stableRSID, e.in.StableRS)
	appendDigest(e.graph.latestRSID, e.in.LatestRS)
	for _, t := range uniqueNS {
		ns := t.Namespace
		if ns == "" {
			ns = e.graph.namespace
		}
		appendDigest(identityOfMeta(kindAnalysisTemplate, ScopeNamespaced, ns, t.ObjectMeta), t)
	}
	for _, t := range uniqueCL {
		appendDigest(identityOfMeta(kindClusterAnalysisTemplate, ScopeCluster, "", t.ObjectMeta), t)
	}
	return out
}

func digestOf(obj any) (string, error) {
	b, err := canonicalJSON(obj)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(obj any) ([]byte, error) {
	return json.Marshal(obj)
}

// finalizeDigest stamps the completion marker: the digest covers the full
// canonical report body with ReportDigest left empty.
func finalizeDigest(r *Report) {
	r.ReportDigest = ""
	d, err := digestOf(r)
	if err != nil {
		return
	}
	r.ReportDigest = d
}
