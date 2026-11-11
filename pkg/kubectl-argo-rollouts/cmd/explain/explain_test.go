package explain

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	rofake "github.com/argoproj/argo-rollouts/pkg/client/clientset/versioned/fake"
	fakeoptions "github.com/argoproj/argo-rollouts/pkg/kubectl-argo-rollouts/options/fake"
	explainutil "github.com/argoproj/argo-rollouts/utils/explain"
)

func typeMeta(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{Kind: kind, APIVersion: "argoproj.io/v1alpha1"}
}

func objectMeta(name, namespace, uid, rv string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: name, Namespace: namespace, UID: types.UID(uid), ResourceVersion: rv,
	}
}

func labelSelector(k, v string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{k: v}}
}

func promMetricLike(name, query string) v1alpha1.Metric {
	return v1alpha1.Metric{
		Name:             name,
		SuccessCondition: "true",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{Address: "http://prom:9090", Query: query},
		},
	}
}

func replicaSetLike(name, namespace, hash string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		TypeMeta:   metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{v1alpha1.DefaultRolloutUniqueLabelKey: hash}},
	}
}

func writeYAMLDocs(t *testing.T, dir, name string, objs ...any) string {
	t.Helper()
	var b strings.Builder
	for i, obj := range objs {
		data, err := yaml.Marshal(obj)
		require.NoError(t, err)
		if i > 0 {
			b.WriteString("---\n")
		}
		b.Write(data)
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

func cliSnapshots(t *testing.T) (rollout *v1alpha1.Rollout, tpl *v1alpha1.AnalysisTemplate, stableYAML, latestYAML any) {
	rollout = &v1alpha1.Rollout{
		TypeMeta:   typeMeta("Rollout"),
		ObjectMeta: objectMeta("guestbook", "default", "uid-ro", "100"),
		Spec: v1alpha1.RolloutSpec{
			Selector: labelSelector("app", "guestbook"),
			Strategy: v1alpha1.RolloutStrategy{Canary: &v1alpha1.CanaryStrategy{
				Analysis: &v1alpha1.RolloutAnalysisBackground{
					RolloutAnalysis: v1alpha1.RolloutAnalysis{
						Templates: []v1alpha1.AnalysisTemplateRef{{TemplateName: "a-tpl"}},
						Args:      []v1alpha1.AnalysisRunArgument{{Name: "service", Value: "cli-service"}},
					},
				},
			}},
		},
		Status: v1alpha1.RolloutStatus{StableRS: "stable-h", CurrentPodHash: "latest-h"},
	}
	tpl = &v1alpha1.AnalysisTemplate{
		TypeMeta:   typeMeta("AnalysisTemplate"),
		ObjectMeta: objectMeta("a-tpl", "default", "uid-at", "7"),
		Spec: v1alpha1.AnalysisTemplateSpec{
			Args:    []v1alpha1.Argument{{Name: "service", Value: ptr.To("default-service")}},
			Metrics: []v1alpha1.Metric{promMetricLike("m1", "up{job=\"{{args.service}}\"}")},
		},
	}
	stable := replicaSetLike("guestbook-stable", "default", "stable-h")
	latest := replicaSetLike("guestbook-latest", "default", "latest-h")
	return rollout, tpl, stable, latest
}

func TestCLIExplainProducesReportWithoutAPICalls(t *testing.T) {
	tf, o := fakeoptions.NewFakeArgoRolloutsOptions()
	defer tf.Cleanup()
	dir := t.TempDir()
	rollout, tpl, stable, latest := cliSnapshots(t)
	snapshotFile := writeYAMLDocs(t, dir, "snapshots.yaml", rollout, tpl, stable, latest)

	cmd := NewCmdExplain(o)
	cmd.PersistentPreRunE = o.PersistentPreRunE
	cmd.SetArgs([]string{"-f", snapshotFile})
	require.NoError(t, cmd.Execute())

	stdout := o.Out.(*bytes.Buffer).Bytes()
	require.NotEmpty(t, stdout)
	report, err := explainutil.UnmarshalReport(stdout)
	require.NoError(t, err)
	assert.True(t, report.Complete)
	require.NotNil(t, report.Candidate)
	assert.Equal(t, "cli-service", *report.Candidate.AnalysisRun.Spec.Args[0].Value)

	// The command must not call the rollouts API at all.
	fakeRO, ok := o.RolloutsClient.(*rofake.Clientset)
	require.True(t, ok)
	assert.Empty(t, fakeRO.Actions())
}

func TestCLIExplainVerifyRoundTripAndRejection(t *testing.T) {
	tf, o := fakeoptions.NewFakeArgoRolloutsOptions()
	defer tf.Cleanup()
	dir := t.TempDir()
	rollout, tpl, stable, latest := cliSnapshots(t)
	snapshotFile := writeYAMLDocs(t, dir, "snapshots.yaml", rollout, tpl, stable, latest)
	reportFile := filepath.Join(dir, "report.json")

	cmd := NewCmdExplain(o)
	cmd.PersistentPreRunE = o.PersistentPreRunE
	cmd.SetArgs([]string{"-f", snapshotFile, "--report", reportFile})
	require.NoError(t, cmd.Execute())

	// Verify accepts the untouched report.
	verifyCmd := NewCmdExplain(o)
	verifyCmd.PersistentPreRunE = o.PersistentPreRunE
	verifyCmd.SetArgs([]string{"-f", snapshotFile, "--verify", reportFile})
	require.NoError(t, verifyCmd.Execute())
	assert.Contains(t, o.Out.(*bytes.Buffer).String(), "verified successfully")

	// Tamper with the report and expect rejection.
	data, err := os.ReadFile(reportFile)
	require.NoError(t, err)
	tampered := strings.Replace(string(data), "cli-service", "tampered-service", 1)
	require.NotEqual(t, string(data), tampered)
	require.NoError(t, os.WriteFile(reportFile, []byte(tampered), 0o600))

	rejectCmd := NewCmdExplain(o)
	rejectCmd.PersistentPreRunE = o.PersistentPreRunE
	rejectCmd.SetArgs([]string{"-f", snapshotFile, "--verify", reportFile})
	err = rejectCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "report verification failed")
}

func TestCLIExplainRejectsMissingFile(t *testing.T) {
	tf, o := fakeoptions.NewFakeArgoRolloutsOptions()
	defer tf.Cleanup()
	cmd := NewCmdExplain(o)
	cmd.PersistentPreRunE = o.PersistentPreRunE
	cmd.SetArgs([]string{"-f", filepath.Join(t.TempDir(), "nope.yaml")})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestCLISecretFileKeepsValueOpaque(t *testing.T) {
	tf, o := fakeoptions.NewFakeArgoRolloutsOptions()
	defer tf.Cleanup()
	dir := t.TempDir()
	rollout, _, stable, latest := cliSnapshots(t)
	tpl := &v1alpha1.AnalysisTemplate{
		TypeMeta:   typeMeta("AnalysisTemplate"),
		ObjectMeta: objectMeta("secret-tpl", "default", "uid-secret", "1"),
		Spec: v1alpha1.AnalysisTemplateSpec{
			Args: []v1alpha1.Argument{{Name: "token", ValueFrom: &v1alpha1.ValueFrom{
				SecretKeyRef: &v1alpha1.SecretKeyRef{Name: "web-secret", Key: "apikey"},
			}}},
			Metrics: []v1alpha1.Metric{promMetricLike("m1", "Bearer {{args.token}}")},
		},
	}
	rollout.Spec.Strategy.Canary.Analysis.RolloutAnalysis.Templates = []v1alpha1.AnalysisTemplateRef{{TemplateName: "secret-tpl"}}
	snapshotFile := writeYAMLDocs(t, dir, "snapshots.yaml", rollout, tpl, stable, latest)
	secretFile := filepath.Join(dir, "secrets.yaml")
	require.NoError(t, os.WriteFile(secretFile, []byte("secrets:\n- namespace: default\n  name: web-secret\n  key: apikey\n  value: top-secret-value\n"), 0o600))

	cmd := NewCmdExplain(o)
	cmd.PersistentPreRunE = o.PersistentPreRunE
	cmd.SetArgs([]string{"-f", snapshotFile, "--secret-file", secretFile})
	require.NoError(t, cmd.Execute())

	stdout := o.Out.(*bytes.Buffer).String()
	assert.NotContains(t, stdout, "top-secret-value")
	report, err := explainutil.UnmarshalReport([]byte(stdout))
	require.NoError(t, err)
	assert.True(t, report.Complete)
}
