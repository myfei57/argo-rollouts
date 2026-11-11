package explain

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

func verificationInput() Input {
	rollout := testRollout()
	tpls, ctpls := nestedMixedScopeSet()
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args:      []v1alpha1.AnalysisRunArgument{{Name: "service", Value: "incoming"}},
	}
	return baseInput(rollout, analysis, tpls, ctpls)
}

func TestVerifyReportAcceptsUntamperedReport(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)
	require.NoError(t, VerifyReport(report, in))

	// Serialization round trip does not break verification.
	data, err := report.Marshal()
	require.NoError(t, err)
	restored, err := UnmarshalReport(data)
	require.NoError(t, err)
	require.NoError(t, VerifyReport(restored, in))
}

func TestVerifyReportRejectsTamperedMarker(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)
	report.ReportDigest = "deadbeef"
	err = VerifyReport(report, in)
	require.Error(t, err)
	ve, ok := err.(*VerificationError)
	require.True(t, ok)
	assert.Equal(t, ReasonDigestMismatch, ve.Reason)
}

func TestVerifyReportRejectsTamperedObject(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)

	// Tamper with a template after the report was produced; the recomputed
	// object digest must no longer match.
	tampered := in
	tampered.Templates = append([]*v1alpha1.AnalysisTemplate(nil), in.Templates...)
	for i, tpl := range tampered.Templates {
		if tpl.Name == "a-tpl" {
			tampered.Templates[i] = tpl.DeepCopy()
			tampered.Templates[i].Spec.Metrics[0].Provider.Prometheus.Query = "tampered-query"
		}
	}
	err = VerifyReport(report, tampered)
	require.Error(t, err)
	ve, ok := err.(*VerificationError)
	require.True(t, ok)
	assert.Equal(t, ReasonDigestMismatch, ve.Reason)
}

func TestVerifyReportRejectsVersionConflict(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)

	changed := in
	changed.Templates = append([]*v1alpha1.AnalysisTemplate(nil), in.Templates...)
	for i, tpl := range changed.Templates {
		if tpl.Name == "a-tpl" {
			changed.Templates[i] = tpl.DeepCopy()
			// Same digest content, new object identity.
			changed.Templates[i].ResourceVersion = "999"
		}
	}
	err = VerifyReport(report, changed)
	require.Error(t, err)
	ve, ok := err.(*VerificationError)
	require.True(t, ok)
	assert.Equal(t, ReasonVersionConflict, ve.Reason)
}

func TestVerifyReportRejectsMissingObject(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)

	missing := in
	missing.Templates = nil
	missing.ClusterTemplates = nil
	err = VerifyReport(report, missing)
	require.Error(t, err)
	ve, ok := err.(*VerificationError)
	require.True(t, ok)
	assert.Equal(t, ReasonMissingObject, ve.Reason)
}

func TestVerifyReportRejectsDivergedConstruction(t *testing.T) {
	in := verificationInput()
	report, err := Explain(in)
	require.NoError(t, err)

	// Mutate the recorded candidate; re-computation must expose the drift.
	report.Candidate.AnalysisRun.Spec.Metrics[0].Provider.Prometheus.Query = "not-what-the-constructor-builds"
	// The marker still matches the (now tampered) body, so this proves the
	// construction comparison is independent of digest validation.
	finalizeDigest(report)
	err = VerifyReport(report, in)
	require.Error(t, err)
	ve, ok := err.(*VerificationError)
	require.True(t, ok)
	assert.Equal(t, ReasonDiverged, ve.Reason)
}

func TestVerifyReportAcceptsUnresolvedButConsistentReport(t *testing.T) {
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
	require.NoError(t, VerifyReport(report, in))
}

func TestReportNeverContainsSecretValuesOrGuessMarkers(t *testing.T) {
	rollout := testRollout()
	const secretValue = "opaque-token-9999"
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
	data, err := report.Marshal()
	require.NoError(t, err)
	assert.NotContains(t, string(data), secretValue)

	// JSON walk: every secret reference stays opaque and no value field leaks.
	var generic map[string]any
	require.NoError(t, json.Unmarshal(data, &generic))
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				assert.NotEqual(t, "value", k)
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		case string:
			assert.NotContains(t, n, secretValue)
		}
	}
	walk(generic)
}

func TestExplainNilPointerValuePreservedInReport(t *testing.T) {
	rollout := testRollout()
	// A nil-valued arg default overridden by a pointer-to-empty incoming arg.
	tpl := namespacedTemplate("a-tpl", "uid-a", "1", v1alpha1.AnalysisTemplateSpec{
		Args:    []v1alpha1.Argument{{Name: "blank"}},
		Metrics: []v1alpha1.Metric{promMetric("m1", "x={{args.blank}}")},
	})
	analysis := &v1alpha1.RolloutAnalysis{
		Templates: []v1alpha1.AnalysisTemplateRef{nsRef("a-tpl")},
		Args:      []v1alpha1.AnalysisRunArgument{{Name: "blank", Value: ""}},
	}
	in := baseInput(rollout, analysis, []*v1alpha1.AnalysisTemplate{tpl}, nil)
	report, err := Explain(in)
	require.NoError(t, err)
	arg := findArgExp(report, "blank")
	require.NotNil(t, arg)
	assert.False(t, arg.Definitions[0].ValuePresent, "template default is nil")
	assert.True(t, arg.HasValue, "adopted value is a non-nil pointer")
	assert.True(t, arg.ValueIsEmpty)
	assert.Equal(t, ptr.To(""), report.Candidate.AnalysisRun.Spec.Args[0].Value)
}
