package explain

import (
	appsv1 "k8s.io/api/apps/v1"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

func secretKey(namespace, name, key string) string {
	return namespace + "/" + name + "#" + key
}

func (g *graph) analysisDryRun() []v1alpha1.DryRun {
	if g.analysis == nil {
		return nil
	}
	return g.analysis.DryRun
}

func (g *graph) analysisRetention() []v1alpha1.MeasurementRetention {
	if g.analysis == nil {
		return nil
	}
	return g.analysis.MeasurementRetention
}

// explainValueFrom attributes a ValueFrom to the supplied Rollout/ReplicaSet
// snapshots. Secret references stay opaque: only the reference descriptor and
// its supply state are retained, never the value.
func (g *graph) explainValueFrom(vf *v1alpha1.ValueFrom) *ValueFromExplanation {
	if vf == nil {
		return nil
	}
	out := &ValueFromExplanation{}
	if vf.SecretKeyRef != nil {
		out.Kind = "SecretKeyRef"
		ns := g.namespace
		if vf.SecretKeyRef.SharedSecret {
			// The controller would use --analysis-shared-secret-namespace; the
			// effective namespace must be supplied explicitly by the caller.
			ns = g.sharedSecretNamespace
		}
		ref := &SecretRef{
			Namespace:    ns,
			Name:         vf.SecretKeyRef.Name,
			Key:          vf.SecretKeyRef.Key,
			SharedSecret: vf.SecretKeyRef.SharedSecret,
		}
		_, ref.Supplied = g.secrets[secretKey(ns, ref.Name, ref.Key)]
		out.Secret = ref
		return out
	}
	if vf.FieldRef != nil {
		out.Kind = "FieldRef"
		out.FieldPath = vf.FieldRef.FieldPath
		rolloutID := g.rolloutID
		out.FieldRefObject = &rolloutID
		return out
	}
	return out
}

// explainPodTemplateHash attributes a podTemplateHashValue argument to the
// stable or latest ReplicaSet snapshot label.
func (g *graph) explainPodTemplateHash(which v1alpha1.ValueFromPodTemplateHash) *PodTemplateHashSource {
	out := &PodTemplateHashSource{
		Which:    string(which),
		LabelKey: v1alpha1.DefaultRolloutUniqueLabelKey,
	}
	var rs *appsv1.ReplicaSet
	switch which {
	case v1alpha1.Stable:
		rs = g.stableRS
		out.RS = g.stableRSID
	case v1alpha1.Latest:
		rs = g.latestRS
		out.RS = g.latestRSID
	}
	if rs != nil && rs.Labels != nil {
		_, out.Present = rs.Labels[v1alpha1.DefaultRolloutUniqueLabelKey]
	}
	return out
}

// secretRefOfArgument returns the opaque secret reference of an argument, if
// it carries one. sharedNamespace is the externally configured shared-secret
// namespace, which the library never infers from a cluster.
func secretRefOfArgument(arg v1alpha1.Argument, namespace, sharedNamespace string, supplied map[string]SecretInput) *SecretRef {
	if arg.ValueFrom == nil || arg.ValueFrom.SecretKeyRef == nil {
		return nil
	}
	ns := namespace
	if arg.ValueFrom.SecretKeyRef.SharedSecret && sharedNamespace != "" {
		ns = sharedNamespace
	}
	ref := &SecretRef{
		Namespace:    ns,
		Name:         arg.ValueFrom.SecretKeyRef.Name,
		Key:          arg.ValueFrom.SecretKeyRef.Key,
		SharedSecret: arg.ValueFrom.SecretKeyRef.SharedSecret,
	}
	_, ref.Supplied = supplied[secretKey(ns, ref.Name, ref.Key)]
	return ref
}
