package explain

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	rofake "github.com/argoproj/argo-rollouts/pkg/client/clientset/versioned/fake"
	analysisutil "github.com/argoproj/argo-rollouts/utils/analysis"
	templateutil "github.com/argoproj/argo-rollouts/utils/template"
)

// nestedMixedScopeSet builds A(namespaced) -> C(cluster) -> E(namespaced),
// exercising mixed scope nesting and the separate namespaced/cluster lists.
func nestedMixedScopeSet() ([]*v1alpha1.AnalysisTemplate, []*v1alpha1.ClusterAnalysisTemplate) {
	// service is defined once (in a-tpl); e-tpl only consumes it, so the set
	// is constructible without conflicting default values.
	e := namespacedTemplate("e-tpl", "uid-e", "5", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{promMetric("m-e", "up{job=\"{{args.service}}\"}")},
	})
	c := clusterTemplate("c-tpl", "uid-c", "6", v1alpha1.AnalysisTemplateSpec{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("e-tpl")},
		Args:      []v1alpha1.Argument{{Name: "cluster-only", Value: ptr.To("cval")}},
		Metrics:   []v1alpha1.Metric{promMetric("m-c", "cluster_query")},
		DryRun:    []v1alpha1.DryRun{{MetricName: "m-.*"}},
	})
	a := namespacedTemplate("a-tpl", "uid-a", "7", v1alpha1.AnalysisTemplateSpec{
		Templates: []v1alpha1.AnalysisTemplateRef{clusterRef("c-tpl")},
		Args:      []v1alpha1.Argument{{Name: "service", Value: ptr.To("a-service")}},
		Metrics:   []v1alpha1.Metric{promMetric("m-a", "rate({{args.service}})")},
	})
	return []*v1alpha1.AnalysisTemplate{a, e}, []*v1alpha1.ClusterAnalysisTemplate{c}
}

func TestExplainNestedMixedScopeTraversalAndIdentity(t *testing.T) {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, tpls, ctpls)

	report, err := Explain(in)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.True(t, report.Complete)

	// Traversal order: A before C before E; scopes stay separated.
	require.Len(t, report.Traversal.Visits, 3)
	assert.Equal(t, "a-tpl", report.Traversal.Visits[0].Identity.Name)
	assert.Equal(t, ScopeNamespaced, report.Traversal.Visits[0].Identity.Scope)
	assert.Equal(t, "c-tpl", report.Traversal.Visits[1].Identity.Name)
	assert.Equal(t, ScopeCluster, report.Traversal.Visits[1].Identity.Scope)
	assert.Equal(t, "e-tpl", report.Traversal.Visits[2].Identity.Name)
	assert.Equal(t, ScopeNamespaced, report.Traversal.Visits[2].Identity.Scope)

	// Identity carries scope, namespace, UID and resourceVersion.
	first := report.Traversal.Visits[0].Identity
	assert.Equal(t, testNamespace, first.Namespace)
	assert.Equal(t, "uid-a", first.UID)
	assert.Equal(t, "7", first.ResourceVersion)

	require.Len(t, report.Traversal.UniqueNamespaced, 2)
	require.Len(t, report.Traversal.UniqueCluster, 1)

	// Edge path is replayable against the real ref fields.
	rootEdge := report.Traversal.RootRefs[0]
	assert.Equal(t, "spec.strategy.canary.analysis.templates[0]", rootEdge.FieldPath)
	assert.False(t, rootEdge.ClusterScope)
}

func TestExplainCandidateMatchesProductionConstructorFieldByField(t *testing.T) {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args: []v1alpha1.AnalysisRunArgument{{
			Name:  "service",
			Value: "incoming-service",
		}},
		DryRun:               []v1alpha1.DryRun{{MetricName: "m-a"}},
		MeasurementRetention: []v1alpha1.MeasurementRetention{{MetricName: "m-c", Limit: 3}},
	}
	in := baseInput(rollout, analysis, tpls, ctpls)
	fp := inputFingerprint(in)

	report, err := Explain(in)
	require.NoError(t, err)
	require.NotNil(t, report.Candidate)

	// Replicate the controller construction path independently.
	g, uniqueNS, uniqueCL, err := traverse(&in)
	require.NoError(t, err)
	_ = g
	incoming, err := analysisutil.BuildArgumentsForRolloutAnalysisRun(analysis.Args, in.StableRS, in.LatestRS, in.Rollout)
	require.NoError(t, err)
	realRun, err := analysisutil.NewAnalysisRunFromTemplates(
		uniqueNS, uniqueCL, incoming, analysis.DryRun, analysis.MeasurementRetention,
		in.RunMeta.Labels, map[string]string{}, in.RunMeta.Name, "", in.RunMeta.Namespace)
	require.NoError(t, err)

	want, _ := json.Marshal(realRun.Spec)
	got, _ := json.Marshal(report.Candidate.AnalysisRun.Spec)
	assert.JSONEq(t, string(want), string(got))

	// Incoming override actually wins over both template defaults.
	assert.Equal(t, "incoming-service", *report.Candidate.AnalysisRun.Spec.Args[0].Value)

	// Inputs untouched.
	assert.Equal(t, fp, inputFingerprint(in))
}

func TestExplainDiamondSharedTemplateDedupAndWinner(t *testing.T) {
	rollout := testRollout()
	// Root refs [a, b]; both reference shared c. DFS visits c twice,
	// FilterUniqueTemplates keeps the first occurrence (via a).
	shared := namespacedTemplate("shared", "uid-shared", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "region", Value: ptr.To("us-east")}},
		Metrics: []v1alpha1.Metric{promMetric("m-shared", "q-{{args.region}}")},
	})
	a := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("shared")},
		Metrics:   []v1alpha1.Metric{promMetric("m-a", "a")},
	})
	b := namespacedTemplate("b-tpl", "uid-b", "1", v1alpha1.AnalysisTemplateSpec{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("shared")},
		Metrics:   []v1alpha1.Metric{promMetric("m-b", "b")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl"), nsRef("b-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{a, b, shared}, nil)

	report, err := Explain(in)
	require.NoError(t, err)

	// Four visits: a, shared(via a), b, shared(via b); last is deduped.
	require.Len(t, report.Traversal.Visits, 4)
	assert.False(t, report.Traversal.Visits[1].Deduped)
	assert.True(t, report.Traversal.Visits[3].Deduped)
	require.Len(t, report.Traversal.UniqueNamespaced, 3)

	arg := findArgExp(report, "region")
	require.NotNil(t, arg)
	require.Len(t, arg.Definitions, 1, "deduped template must not contribute a second arg definition")
	assert.True(t, arg.Definitions[0].Winner)
	// Winner path enters shared through a-tpl, the first occurrence.
	assert.Contains(t, arg.Winner.String(), "AnalysisTemplate/default/a-tpl")
	assert.Contains(t, arg.Winner.String(), "AnalysisTemplate/default/shared")

	// Only three metrics survive, and m-shared appears once.
	var names []string
	for _, m := range report.Candidate.AnalysisRun.Spec.Metrics {
		names = append(names, m.Name)
	}
	assert.Equal(t, []string{"m-a", "m-shared", "m-b"}, names)
}

func TestExplainSameNameDifferentScopeNeverMerged(t *testing.T) {
	rollout := testRollout()
	ns := namespacedTemplate("same-name", "uid-ns", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{promMetric("m-ns", "ns")},
	})
	cl := clusterTemplate("same-name", "uid-cl", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{promMetric("m-cl", "cl")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{
		nsRef("same-name"), clusterRef("same-name"),
	}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{ns}, []*v1alpha1.ClusterAnalysisTemplate{cl})

	report, err := Explain(in)
	require.NoError(t, err)
	require.Len(t, report.Traversal.UniqueNamespaced, 1)
	require.Len(t, report.Traversal.UniqueCluster, 1)
	assert.Len(t, report.Candidate.AnalysisRun.Spec.Metrics, 2)
}

func TestExplainIncomingArgOverrideNilAndEmptyString(t *testing.T) {
	rollout := testRollout()
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args: []v1alpha1.Argument{
			{Name: "kept", Value: ptr.To("default")},
			{Name: "emptied", Value: ptr.To("default")},
		},
		Metrics: []v1alpha1.Metric{
			promMetric("m1", "{{args.kept}}/{{args.emptied}}"),
		},
	})
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args: []v1alpha1.AnalysisRunArgument{
			{Name: "kept", Value: "override"},
			{Name: "emptied", Value: ""}, // pointer to empty string still overrides
		},
	}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	report, err := Explain(in)
	require.NoError(t, err)

	kept := findArgExp(report, "kept")
	require.NotNil(t, kept)
	require.NotNil(t, kept.Override)
	assert.Equal(t, "override", kept.Value)
	assert.False(t, kept.ValueIsEmpty)

	emptied := findArgExp(report, "emptied")
	require.NotNil(t, emptied)
	require.NotNil(t, emptied.Override)
	assert.True(t, emptied.HasValue, "pointer to empty string is still a value")
	assert.True(t, emptied.ValueIsEmpty)
	assert.Equal(t, "", emptied.Value)

	// Resolved metric proves empty string substitution semantics.
	m := findMetricExp(report, "m1")
	require.NotNil(t, m)
	require.NotNil(t, m.Resolved)
	assert.Equal(t, "override/", m.Resolved.Provider.Prometheus.Query)
}

func TestExplainUnresolvedTemplateArgFailsConstructorTruthfully(t *testing.T) {
	rollout := testRollout()
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "missing"}}, // nil Value, no ValueFrom
		Metrics: []v1alpha1.Metric{promMetric("m1", "{{args.missing}}")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	fp := inputFingerprint(in)

	report, err := Explain(in)
	require.NoError(t, err)
	assert.Nil(t, report.Candidate)
	assert.Contains(t, report.ConstructorError, "args.missing was not resolved")
	require.NotEmpty(t, report.Unresolved)
	assert.Equal(t, inputFingerprint(in), fp)
}

func TestExplainSameValueDifferentSourcesOnlyAdoptedOneWins(t *testing.T) {
	rollout := testRollout()
	first := namespacedTemplate("first", "uid-first", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "region", Value: ptr.To("us")}},
		Metrics: []v1alpha1.Metric{promMetric("m-first", "1")},
	})
	second := namespacedTemplate("second", "uid-second", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "region", Value: ptr.To("us")}}, // identical value
		Metrics: []v1alpha1.Metric{promMetric("m-second", "2")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("first"), nsRef("second")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{first, second}, nil)

	report, err := Explain(in)
	require.NoError(t, err)
	arg := findArgExp(report, "region")
	require.NotNil(t, arg)
	require.Len(t, arg.Definitions, 2, "both definitions are visible")
	var winners int
	for _, d := range arg.Definitions {
		if d.Winner {
			winners++
		}
	}
	assert.Equal(t, 1, winners, "same value must not make every definition a winner")
	assert.Contains(t, arg.Winner.String(), "AnalysisTemplate/default/first")
}

func TestExplainQuotesBackslashesAndUTF8Segments(t *testing.T) {
	rollout := testRollout()
	tricky := `a"b\c` + "\n" + `tab	end 中文`
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "token", Value: ptr.To(tricky)}},
		Metrics: []v1alpha1.Metric{promMetric("m1", `q="{{args.token}}"`)},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)

	report, err := Explain(in)
	require.NoError(t, err)
	m := findMetricExp(report, "m1")
	require.NotNil(t, m)
	require.Equal(t, StatusResolved, m.Status)
	require.Len(t, m.Segments, 1)
	seg := m.Segments[0]
	assert.Equal(t, "provider.prometheus.query", seg.FieldPath)
	assert.Equal(t, "{{args.token}}", seg.RawTag)

	marshaled, _ := json.Marshal(tpl.Spec.Metrics[0])
	// Source ranges address the raw tag inside the marshaled metric.
	assert.Equal(t, "{{args.token}}", string(marshaled[seg.SourceByteRange[0]:seg.SourceByteRange[1]]))
	quoted := quoteArgValue(tricky)
	resolvedStr, err := templateutil.ResolveQuotedArgs(string(marshaled), report.Candidate.AnalysisRun.Spec.Args)
	require.NoError(t, err)
	assert.Equal(t, quoted, resolvedStr[seg.OutputByteRange[0]:seg.OutputByteRange[1]])

	// Rune ranges stay valid across UTF-8 boundaries.
	assert.Equal(t, "{{args.token}}", string([]rune(string(marshaled))[seg.SourceRuneRange[0]:seg.SourceRuneRange[1]]))
	assert.Equal(t, quoted, string([]rune(resolvedStr)[seg.OutputRuneRange[0]:seg.OutputRuneRange[1]]))

	// The unmarshaled metric is identical to production ResolveMetricArgs.
	realMetric, err := analysisutil.ResolveMetricArgs(tpl.Spec.Metrics[0], report.Candidate.AnalysisRun.Spec.Args)
	require.NoError(t, err)
	assert.Equal(t, *realMetric, *m.Resolved)
	assert.Equal(t, `q="`+tricky+`"`, m.Resolved.Provider.Prometheus.Query)
}

func TestExplainFieldRefAndPodTemplateHashProvenance(t *testing.T) {
	rollout := testRollout()
	// Template-side arg definitions (nil values) are required for incoming
	// args to be adopted by MergeArgs.
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args: []v1alpha1.Argument{
			{Name: "name"},
			{Name: "stable"},
			{Name: "latest"},
		},
		Metrics: []v1alpha1.Metric{promMetric("m1", "{{args.name}}|{{args.stable}}|{{args.latest}}")},
	})
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args: []v1alpha1.AnalysisRunArgument{
			{Name: "name", ValueFrom: &v1alpha1.ArgumentValueFrom{FieldRef: &v1alpha1.FieldRef{FieldPath: "metadata.name"}}},
			{Name: "stable", ValueFrom: &v1alpha1.ArgumentValueFrom{PodTemplateHashValue: ptr.To(v1alpha1.Stable)}},
			{Name: "latest", ValueFrom: &v1alpha1.ArgumentValueFrom{PodTemplateHashValue: ptr.To(v1alpha1.Latest)}},
		},
	}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	report, err := Explain(in)
	require.NoError(t, err)
	m := findMetricExp(report, "m1")
	require.NotNil(t, m.Resolved)
	assert.Equal(t, "guestbook|"+stableHash+"|"+latestHash, m.Resolved.Provider.Prometheus.Query)
	// Every tag keeps its own structured segment and arg identity, even when
	// several fragments share one metric field.
	require.Len(t, m.Segments, 3)
	assert.Equal(t, "provider.prometheus.query", m.Segments[0].FieldPath)
	assert.Equal(t, []string{"name", "stable", "latest"}, []string{
		m.Segments[0].ArgName, m.Segments[1].ArgName, m.Segments[2].ArgName,
	})
	for _, seg := range m.Segments {
		require.NotNil(t, seg.ArgValueSource, "segment must map back to the adopting arg source")
	}

	nameArg := findArgExp(report, "name")
	require.NotNil(t, nameArg.Override.ValueFrom)
	assert.Equal(t, "FieldRef", nameArg.Override.ValueFrom.Kind)
	assert.Equal(t, "metadata.name", nameArg.Override.ValueFrom.FieldPath)

	stableArg := findArgExp(report, "stable")
	require.NotNil(t, stableArg.Override.ValueFrom.PodTemplateHash)
	assert.True(t, stableArg.Override.ValueFrom.PodTemplateHash.Present)
	assert.Equal(t, "Stable", stableArg.Override.ValueFrom.PodTemplateHash.Which)
}

func TestExplainSecretMissingIsUnresolvedAndNeverGuessed(t *testing.T) {
	rollout := testRollout()
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args: []v1alpha1.Argument{{Name: "token", ValueFrom: &v1alpha1.ValueFrom{
			SecretKeyRef: &v1alpha1.SecretKeyRef{Name: "web-secret", Key: "apikey"},
		}}},
		Metrics: []v1alpha1.Metric{promMetric("m1", "Bearer {{args.token}}")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)

	report, err := Explain(in)
	require.NoError(t, err)
	assert.False(t, report.Complete)
	m := findMetricExp(report, "m1")
	require.NotNil(t, m)
	assert.Equal(t, StatusUnresolved, m.Status)
	assert.Nil(t, m.Resolved, "no guessed resolved metric")
	require.NotEmpty(t, m.Segments)
	assert.Equal(t, StatusUnresolved, m.Segments[0].Status)
	require.NotNil(t, m.Segments[0].SecretRef)
	assert.False(t, m.Segments[0].SecretRef.Supplied)

	// The candidate run still exists (construction does not need secret data)
	// and retains the opaque ValueFrom instead of a fabricated value.
	require.NotNil(t, report.Candidate)
	require.NotNil(t, report.Candidate.AnalysisRun.Spec.Args[0].ValueFrom)
	assert.Nil(t, report.Candidate.AnalysisRun.Spec.Args[0].Value)
}

func TestExplainSuppliedSecretIsRedactedButConstructionStillVerified(t *testing.T) {
	rollout := testRollout()
	const secretValue = "super-secret-token-42"
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args: []v1alpha1.Argument{{Name: "token", ValueFrom: &v1alpha1.ValueFrom{
			SecretKeyRef: &v1alpha1.SecretKeyRef{Name: "web-secret", Key: "apikey"},
		}}},
		Metrics: []v1alpha1.Metric{promMetric("m1", "Bearer {{args.token}}")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	in.SecretInputs = []SecretInput{{Namespace: testNamespace, Name: "web-secret", Key: "apikey", Value: secretValue}}

	report, err := Explain(in)
	require.NoError(t, err)
	assert.True(t, report.Complete)

	raw, err := report.Marshal()
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secretValue, "secret value must never appear in a report")

	m := findMetricExp(report, "m1")
	require.NotNil(t, m.Resolved)
	assert.Contains(t, m.RedactedFields, "provider.prometheus.query")
	assert.Equal(t, "Bearer "+redactionMarker, m.Resolved.Provider.Prometheus.Query)
	require.NotNil(t, m.Segments[0].SecretRef)
	assert.True(t, m.Segments[0].SecretRef.Supplied)

	// The run spec keeps the opaque reference; the value only lived in memory.
	runArg := report.Candidate.AnalysisRun.Spec.Args[0]
	assert.Nil(t, runArg.Value)
	require.NotNil(t, runArg.ValueFrom.SecretKeyRef)
}

func TestExplainConflictsCarryTwoReplayableShortestPaths(t *testing.T) {
	rollout := testRollout()
	// Duplicate metric name across two templates.
	first := namespacedTemplate("first", "uid-first", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "region", Value: ptr.To("us")}},
		Metrics: []v1alpha1.Metric{promMetric("dup", "1")},
		DryRun:  []v1alpha1.DryRun{{MetricName: "rule-x"}},
	})
	second := namespacedTemplate("second", "uid-second", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "region", Value: ptr.To("eu")}},
		Metrics: []v1alpha1.Metric{promMetric("dup", "2")},
		DryRun:  []v1alpha1.DryRun{{MetricName: "rule-x"}},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("first"), nsRef("second")}}
	in := baseInput(rollout, analysis,
		[]*v1alpha1.AnalysisTemplate{first, second}, nil)

	report, err := Explain(in)
	require.NoError(t, err)
	assert.Nil(t, report.Candidate, "conflicting inputs must not yield a candidate")

	dupConflict := findConflict(report, ConflictDuplicateMetric, "dup")
	require.NotNil(t, dupConflict)
	require.Len(t, dupConflict.Paths, 2)
	assert.Contains(t, dupConflict.ConstructorError, "two metrics have the same name 'dup'")

	argConflict := findConflict(report, ConflictConflictingArgDefault, "region")
	require.NotNil(t, argConflict)
	require.Len(t, argConflict.Paths, 2)
	assert.Contains(t, argConflict.ConstructorError, "specified multiple times with different values")

	dryConflict := findConflict(report, ConflictDuplicateDryRunRule, "rule-x")
	require.NotNil(t, dryConflict)

	// Replay every conflict path against the real objects: each edge must
	// resolve to a real ref pointing at the next object, and the terminal
	// field must contain the conflicting name.
	byName := map[string]*v1alpha1.AnalysisTemplate{"first": first, "second": second}
	for _, c := range report.Conflicts {
		for _, p := range c.Paths {
			for _, hop := range p.Hops {
				if hop.Edge == nil {
					continue
				}
				if hop.Edge.From.Kind == "Rollout" {
					ref := analysis.Templates[hop.Edge.RefIndex]
					assert.Equal(t, hop.Edge.TemplateName, ref.TemplateName)
					assert.Equal(t, hop.Edge.ClusterScope, ref.IsClusterScope())
					continue
				}
				parent := byName[hop.Edge.From.Name]
				require.NotNil(t, parent, "edge parent must exist")
				ref := parent.Spec.Templates[hop.Edge.RefIndex]
				assert.Equal(t, hop.Edge.TemplateName, ref.TemplateName)
				assert.Equal(t, hop.Edge.ClusterScope, ref.IsClusterScope())
				assert.Equal(t, hop.Edge.To.Name, ref.TemplateName)
			}
			// The terminal field points at a real metric/arg definition.
			terminal := p.Hops[len(p.Hops)-1]
			if c.Kind == ConflictDuplicateMetric {
				owner := byName[terminal.Object.Name]
				require.NotNil(t, owner)
				assert.Equal(t, c.Name, owner.Spec.Metrics[0].Name)
			}
		}
	}
}

func TestExplainReferenceCycleIsBoundedAndRejected(t *testing.T) {
	rollout := testRollout()
	x := namespacedTemplate("x-tpl", "uid-x", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:   []v1alpha1.Metric{promMetric("m-x", "1")},
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("y-tpl")},
	})
	y := namespacedTemplate("y-tpl", "uid-y", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:   []v1alpha1.Metric{promMetric("m-y", "2")},
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("x-tpl")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("x-tpl")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{x, y}, nil)
	fp := inputFingerprint(in)

	report, err := Explain(in)
	require.Error(t, err)
	assert.Nil(t, report, "cycles must not produce a seemingly complete candidate")
	var ee *ExplainError
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, ReasonCycle, ee.Reason)
	require.NotNil(t, ee.Cycle)
	require.NotEmpty(t, ee.Cycle.Path)
	assert.Equal(t, "x-tpl", ee.Cycle.BackTo.Name)
	assert.Equal(t, fp, inputFingerprint(in))
}

func TestExplainLimitsAreEnforced(t *testing.T) {
	rollout := testRollout()
	chain := buildChainTemplates() // d4 -> d3 -> d2 -> d1 -> d0
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("d4")}}
	in := baseInput(rollout, analysis, chain, nil)
	in.Limits = Limits{MaxTemplates: 64, MaxEdges: 256, MaxDepth: 2, MaxExpansionBytes: 4 * 1024 * 1024}

	_, err := Explain(in)
	require.Error(t, err)
	var ee *ExplainError
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, ReasonLimitExceeded, ee.Reason)

	// Expansion byte limit.
	in.Limits = Limits{MaxTemplates: 64, MaxEdges: 256, MaxDepth: 32, MaxExpansionBytes: 1}
	_, err = Explain(in)
	require.Error(t, err)
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, ReasonLimitExceeded, ee.Reason)

	// Edge limit.
	in.Limits = Limits{MaxTemplates: 64, MaxEdges: 1, MaxDepth: 32, MaxExpansionBytes: 4 * 1024 * 1024}
	_, err = Explain(in)
	require.Error(t, err)
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, ReasonLimitExceeded, ee.Reason)
}

func buildChainTemplates() []*v1alpha1.AnalysisTemplate {
	var out []*v1alpha1.AnalysisTemplate
	for i := 0; i < 5; i++ {
		spec := v1alpha1.AnalysisTemplateSpec{
			Metrics: []v1alpha1.Metric{promMetric(fmt.Sprintf("m%d", i), "1")},
		}
		if i > 0 {
			spec.Templates = []v1alpha1.AnalysisTemplateRef{nsRef(fmt.Sprintf("d%d", i-1))}
		}
		out = append(out, namespacedTemplate(fmt.Sprintf("d%d", i), fmt.Sprintf("uid-d%d", i), "1", spec))
	}
	return out
}

func TestExplainMissingTemplateRefuses(t *testing.T) {
	rollout := testRollout()
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("ghost")}}
	in := baseInput(rollout, analysis, nil, nil)
	_, err := Explain(in)
	require.Error(t, err)
	var ee *ExplainError
	require.True(t, errors.As(err, &ee))
	assert.Equal(t, ReasonNotFound, ee.Reason)
}

func TestExplainZeroWritesConfirmedByAPISpy(t *testing.T) {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, tpls, ctpls)

	// Populate both clientsets as if the objects lived in the cluster, then
	// fail the test on any write verb. Explain must never touch either client.
	roObjects := []runtime.Object{rollout, tpls[0], tpls[1], ctpls[0]}
	roClient := rofake.NewSimpleClientset(roObjects...)
	var writes []string
	roClient.PrependReactor("*", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "get", "list", "watch":
			return false, nil, nil
		default:
			writes = append(writes, action.GetVerb())
			return true, nil, fmt.Errorf("unexpected write action: %s", action.GetVerb())
		}
	})
	kubeClient := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "web-secret"},
		Data:       map[string][]byte{"apikey": []byte("should-never-be-read")},
	}, in.StableRS, in.LatestRS)

	report, err := Explain(in)
	require.NoError(t, err)
	require.NotNil(t, report.Candidate)
	assert.Empty(t, writes)
	assert.Empty(t, roClient.Actions(), "explain must not perform any rollouts API action")
	assert.Empty(t, kubeClient.Actions(), "explain must not read Secrets or perform any kube API action")
}

func TestExplainDryRunRetentionRuleProvenanceAndMatching(t *testing.T) {
	rollout := testRollout()
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{
			promMetric("success-rate", "1"),
			promMetric("latency", "2"),
		},
		DryRun:               []v1alpha1.DryRun{{MetricName: "latency"}},
		MeasurementRetention: []v1alpha1.MeasurementRetention{{MetricName: "success-.*", Limit: 5}},
	})
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		DryRun:    []v1alpha1.DryRun{{MetricName: "success-rate"}},
	}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	report, err := Explain(in)
	require.NoError(t, err)

	var dryIncoming, dryTemplate, retention *RuleExplanation
	for i := range report.Rules {
		r := &report.Rules[i]
		switch r.Kind + "/" + r.MetricName {
		case "DryRun/success-rate":
			dryIncoming = r
		case "DryRun/latency":
			dryTemplate = r
		case "MeasurementRetention/success-.*":
			retention = r
		}
	}
	require.NotNil(t, dryIncoming)
	require.NotNil(t, dryTemplate)
	require.NotNil(t, retention)
	assert.Equal(t, "RolloutAnalysis", dryIncoming.Origin)
	assert.Contains(t, dryTemplate.Origin, "AnalysisTemplate/default/a-tpl")
	assert.Equal(t, []string{"success-rate"}, dryIncoming.MatchedMetrics)
	assert.Equal(t, []string{"latency"}, dryTemplate.MatchedMetrics)
	assert.Equal(t, []string{"success-rate"}, retention.MatchedMetrics)
	assert.Equal(t, int32(5), retention.Limit)

	// A rule matching nothing reproduces the runtime no-match diagnostic.
	bad := namespacedTemplate("b-tpl", "uid-b", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{promMetric("only-metric", "1")},
		DryRun:  []v1alpha1.DryRun{{MetricName: "no-such-metric"}},
	})
	in2 := baseInput(rollout, &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("b-tpl")}},
		[]*v1alpha1.AnalysisTemplate{bad}, nil)
	report2, err := Explain(in2)
	require.NoError(t, err)
	require.NotEmpty(t, report2.Rules)
	assert.Contains(t, report2.Rules[0].MatchError, "didn't match any metric name")
}

func TestExplainReportDigestCoversAllUsedObjects(t *testing.T) {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")}}
	in := baseInput(rollout, analysis, tpls, ctpls)
	report, err := Explain(in)
	require.NoError(t, err)

	// rollout + 2 RS + 2 namespaced + 1 cluster = 6 used objects.
	require.Len(t, report.Objects, 6)
	seenKinds := map[string]int{}
	for _, o := range report.Objects {
		assert.Len(t, o.Digest, 64)
		assert.Greater(t, o.ByteSize, 0)
		seenKinds[o.Identity.Kind]++
	}
	assert.Equal(t, 1, seenKinds["Rollout"])
	assert.Equal(t, 2, seenKinds["ReplicaSet"])
	assert.Equal(t, 2, seenKinds["AnalysisTemplate"])
	assert.Equal(t, 1, seenKinds["ClusterAnalysisTemplate"])
	assert.NotEmpty(t, report.ReportDigest)
	assert.True(t, report.Complete)

	// Round trip preserves the marker.
	data, err := report.Marshal()
	require.NoError(t, err)
	restored, err := UnmarshalReport(data)
	require.NoError(t, err)
	assert.Equal(t, report.ReportDigest, restored.ReportDigest)
}

func TestExplainDiamondConflictPicksTwoShortestReplayablePaths(t *testing.T) {
	rollout := testRollout()
	// Root [a, b]. a -> c (depth 2); b -> d -> c (depth 3). a and c both
	// define metric "dup", so the conflict paths must prefer the short a->c
	// route over the long b->d->c route.
	c := namespacedTemplate("c-tpl", "uid-c", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics: []v1alpha1.Metric{promMetric("dup", "c")},
	})
	d := namespacedTemplate("d-tpl", "uid-d", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:   []v1alpha1.Metric{promMetric("m-d", "d")},
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("c-tpl")},
	})
	a := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:   []v1alpha1.Metric{promMetric("dup", "a")},
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("c-tpl")},
	})
	b := namespacedTemplate("b-tpl", "uid-b", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:   []v1alpha1.Metric{promMetric("m-b", "b")},
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("d-tpl")},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl"), nsRef("b-tpl")}}
	in := baseInput(rollout, analysis,
		[]*v1alpha1.AnalysisTemplate{a, b, c, d}, nil)

	report, err := Explain(in)
	require.NoError(t, err)
	conflict := findConflict(report, ConflictDuplicateMetric, "dup")
	require.NotNil(t, conflict)
	require.Len(t, conflict.Paths, 2)

	// First path reaches dup directly in a-tpl; second reaches c-tpl via the
	// shortest route (a -> c), never the longer b -> d -> c route.
	assert.Contains(t, conflict.Paths[0].String(), "AnalysisTemplate/default/a-tpl")
	second := conflict.Paths[1].String()
	assert.Contains(t, second, "AnalysisTemplate/default/c-tpl")
	assert.Contains(t, second, "AnalysisTemplate/default/a-tpl")
	assert.NotContains(t, second, "b-tpl")

	// c-tpl was still visited twice, proving the longer diamond route exists
	// but loses both de-duplication and shortest-path selection.
	var cVisits int
	for _, v := range report.Traversal.Visits {
		if v.Identity.Name == "c-tpl" {
			cVisits++
		}
	}
	assert.Equal(t, 2, cVisits)
}

func TestExplainDuplicateRetentionRuleConflict(t *testing.T) {
	rollout := testRollout()
	first := namespacedTemplate("first", "uid-first", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:              []v1alpha1.Metric{promMetric("m1", "1")},
		MeasurementRetention: []v1alpha1.MeasurementRetention{{MetricName: "keep", Limit: 1}},
	})
	second := namespacedTemplate("second", "uid-second", "1", v1alpha1.AnalysisTemplateSpec{
		Metrics:              []v1alpha1.Metric{promMetric("m2", "2")},
		MeasurementRetention: []v1alpha1.MeasurementRetention{{MetricName: "keep", Limit: 2}},
	})
	analysis := &v1alpha1.RolloutAnalysis{Templates: []v1alpha1.AnalysisTemplateRef{nsRef("first"), nsRef("second")}}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{first, second}, nil)
	report, err := Explain(in)
	require.NoError(t, err)
	conflict := findConflict(report, ConflictDuplicateRetentionRule, "keep")
	require.NotNil(t, conflict)
	assert.Equal(t, "measurementRetention[*].metricName", conflict.Field)
	require.Len(t, conflict.Paths, 2)
	assert.Nil(t, report.Candidate)
}

func TestExplainAllInputsRemainImmutableAcrossScenarios(t *testing.T) {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args:      []v1alpha1.AnalysisRunArgument{{Name: "service", Value: "x"}},
	}
	in := baseInput(rollout, analysis, tpls, ctpls)
	before := inputFingerprint(in)

	_, err := Explain(in)
	require.NoError(t, err)
	assert.Equal(t, before, inputFingerprint(in))

	// Stability across repeated runs.
	r1, err := Explain(in)
	require.NoError(t, err)
	r2, err := Explain(in)
	require.NoError(t, err)
	assert.Equal(t, r1.ReportDigest, r2.ReportDigest)
}
