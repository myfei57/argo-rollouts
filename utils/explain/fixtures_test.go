package explain

import (
	"encoding/json"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

const (
	testNamespace = "default"
	stableHash    = "stable-hash-aaa"
	latestHash    = "latest-hash-bbb"
)

func testRollout() *v1alpha1.Rollout {
	return &v1alpha1.Rollout{
		TypeMeta: metav1.TypeMeta{Kind: "Rollout", APIVersion: "argoproj.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "guestbook",
			Namespace:       testNamespace,
			UID:             types.UID("uid-rollout-guestbook"),
			ResourceVersion: "100",
			Annotations:     map[string]string{"argoproj.io/revision": "42"},
		},
		Spec: v1alpha1.RolloutSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guestbook"}},
			Strategy: v1alpha1.RolloutStrategy{
				Canary: &v1alpha1.CanaryStrategy{},
			},
		},
		Status: v1alpha1.RolloutStatus{
			StableRS:       stableHash,
			CurrentPodHash: latestHash,
		},
	}
}

func testReplicaSet(name, hash string, rv string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			UID:             types.UID("uid-" + name),
			ResourceVersion: rv,
			Labels:          map[string]string{v1alpha1.DefaultRolloutUniqueLabelKey: hash, "app": "guestbook"},
		},
	}
}

func stableRS() *appsv1.ReplicaSet {
	return testReplicaSet("guestbook-stable", stableHash, "11")
}

func latestRS() *appsv1.ReplicaSet {
	return testReplicaSet("guestbook-latest", latestHash, "12")
}

func namespacedTemplate(name, uid, rv string, spec v1alpha1.AnalysisTemplateSpec) *v1alpha1.AnalysisTemplate {
	return &v1alpha1.AnalysisTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "AnalysisTemplate", APIVersion: "argoproj.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			UID:             types.UID(uid),
			ResourceVersion: rv,
		},
		Spec: spec,
	}
}

func clusterTemplate(name, uid, rv string, spec v1alpha1.AnalysisTemplateSpec) *v1alpha1.ClusterAnalysisTemplate {
	return &v1alpha1.ClusterAnalysisTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterAnalysisTemplate", APIVersion: "argoproj.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			UID:             types.UID(uid),
			ResourceVersion: rv,
		},
		Spec: spec,
	}
}

func promMetric(name, query string) v1alpha1.Metric {
	return v1alpha1.Metric{
		Name:             name,
		SuccessCondition: "true",
		Provider: v1alpha1.MetricProvider{
			Prometheus: &v1alpha1.PrometheusMetric{
				Address: "http://prom:9090",
				Query:   query,
			},
		},
	}
}

func nsRef(name string) v1alpha1.AnalysisTemplateRef {
	return v1alpha1.AnalysisTemplateRef{TemplateName: name}
}

func clusterRef(name string) v1alpha1.AnalysisTemplateRef {
	return v1alpha1.AnalysisTemplateRef{TemplateName: name, ClusterScope: ptr.To(true)}
}

func baseInput(rollout *v1alpha1.Rollout, analysis *v1alpha1.RolloutAnalysis,
	templates []*v1alpha1.AnalysisTemplate, cluster []*v1alpha1.ClusterAnalysisTemplate) Input {
	if analysis == nil {
		analysis = &v1alpha1.RolloutAnalysis{}
	}
	return Input{
		Rollout:           rollout,
		StableRS:          stableRS(),
		LatestRS:          latestRS(),
		Analysis:          analysis,
		AnalysisFieldPath: "spec.strategy.canary.analysis",
		Templates:         templates,
		ClusterTemplates:  cluster,
		RunMeta: RunMeta{
			Name:      "guestbook-run",
			Namespace: testNamespace,
			Labels:    map[string]string{"app": "guestbook"},
		},
		Limits: DefaultLimits(),
	}
}

// snapshotDigests marshals every input object so tests can assert the inputs
// are not mutated.
func inputFingerprint(in Input) string {
	parts := []any{
		in.Rollout, in.StableRS, in.LatestRS, in.Analysis,
		in.Templates, in.ClusterTemplates, in.SecretInputs,
	}
	b, _ := json.Marshal(parts)
	return string(b)
}

func findMetricExp(report *Report, name string) *MetricExplanation {
	for i := range report.Metrics {
		if report.Metrics[i].Name == name {
			return &report.Metrics[i]
		}
	}
	return nil
}

func findArgExp(report *Report, name string) *ArgExplanation {
	for i := range report.Args {
		if report.Args[i].Name == name {
			return &report.Args[i]
		}
	}
	return nil
}

func findConflict(report *Report, kind, name string) *Conflict {
	for i := range report.Conflicts {
		if report.Conflicts[i].Kind == kind && report.Conflicts[i].Name == name {
			return &report.Conflicts[i]
		}
	}
	return nil
}
