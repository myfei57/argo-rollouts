// Package explain implements the read-only `kubectl argo rollouts explain`
// command. It builds AnalysisRun candidates from local snapshot files together
// with full provenance reports. The command never contacts the Kubernetes API
// for writes, never creates AnalysisRuns and never reads cluster Secrets.
package explain

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	goyaml "go.yaml.in/yaml/v2"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/argoproj/argo-rollouts/pkg/kubectl-argo-rollouts/options"
	"github.com/argoproj/argo-rollouts/utils/explain"
)

const explainExample = `
  # Explain the background AnalysisRun candidate from local snapshots
  %[1]s explain analysis -f rollout.yaml -f templates.yaml -f replicasets.yaml

  # Explain a canary step analysis with externally supplied secret values
  %[1]s explain analysis -f all.yaml --analysis step:2 --secret-file secrets.yaml

  # Verify a previously produced report against the same snapshot set
  %[1]s explain analysis -f all.yaml --verify report.json`

// ExplainOptions holds the command line options.
type ExplainOptions struct {
	options.ArgoRolloutsOptions
	Filenames    []string
	Analysis     string
	StableRSName string
	LatestRSName string
	SecretFile   string
	ReportOut    string
	VerifyFile   string
}

// NewCmdExplain returns a new instance of the explain command.
func NewCmdExplain(o *options.ArgoRolloutsOptions) *cobra.Command {
	explainOptions := ExplainOptions{ArgoRolloutsOptions: *o}
	cmd := &cobra.Command{
		Use:          "explain analysis",
		Short:        "Explain how an AnalysisRun would be built (read-only, no writes)",
		Long:         "Builds AnalysisRun candidates from local Rollout, ReplicaSet and AnalysisTemplate snapshots and reports the provenance of every metric, argument, dryRun and measurementRetention value. No resources are created and no providers are executed.",
		Example:      o.Example(explainExample),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return explainOptions.run()
		},
	}
	cmd.Flags().StringArrayVarP(&explainOptions.Filenames, "filename", "f", nil, "Snapshot files (YAML/JSON); repeatable")
	cmd.Flags().StringVar(&explainOptions.Analysis, "analysis", "background", "Analysis to explain: background, pre, post, step:<index>")
	cmd.Flags().StringVar(&explainOptions.StableRSName, "stable-rs", "", "Stable ReplicaSet name (default: derived from rollout status)")
	cmd.Flags().StringVar(&explainOptions.LatestRSName, "latest-rs", "", "Latest ReplicaSet name (default: derived from rollout status)")
	cmd.Flags().StringVar(&explainOptions.SecretFile, "secret-file", "", "YAML file supplying opaque secret values ({secrets:[{namespace,name,key,value}]})")
	cmd.Flags().StringVar(&explainOptions.ReportOut, "report", "", "Write the report JSON to this file instead of stdout")
	cmd.Flags().StringVar(&explainOptions.VerifyFile, "verify", "", "Verify an existing report JSON against the supplied snapshots")
	return cmd
}

type snapshotBundle struct {
	rollouts         []*v1alpha1.Rollout
	templates        []*v1alpha1.AnalysisTemplate
	clusterTemplates []*v1alpha1.ClusterAnalysisTemplate
	replicasets      []*appsv1.ReplicaSet
}

type secretFileDoc struct {
	Secrets []secretFileEntry `json:"secrets" yaml:"secrets"`
}

type secretFileEntry struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	Name      string `json:"name" yaml:"name"`
	Key       string `json:"key" yaml:"key"`
	Value     string `json:"value" yaml:"value"`
}

func (o *ExplainOptions) run() error {
	if len(o.Filenames) == 0 {
		return o.UsageErr(nil)
	}
	bundle, err := loadSnapshots(o.Filenames)
	if err != nil {
		return err
	}
	if len(bundle.rollouts) == 0 {
		return fmt.Errorf("no Rollout found in the supplied files")
	}
	rollout := bundle.rollouts[0]

	stableRS, latestRS, err := o.selectReplicaSets(rollout, bundle.replicasets)
	if err != nil {
		return err
	}
	analysis, fieldPath, err := selectAnalysis(rollout, o.Analysis)
	if err != nil {
		return err
	}
	secretInputs, err := loadSecretFile(o.SecretFile)
	if err != nil {
		return err
	}

	input := explain.Input{
		Rollout:               rollout,
		StableRS:              stableRS,
		LatestRS:              latestRS,
		Analysis:              analysis,
		AnalysisFieldPath:     fieldPath,
		Templates:             bundle.templates,
		ClusterTemplates:      bundle.clusterTemplates,
		SecretInputs:          secretInputs,
		SharedSecretNamespace: os.Getenv("ARGO_ROLLOUTS_SHARED_SECRET_NAMESPACE"),
		RunMeta: explain.RunMeta{
			Namespace: rollout.Namespace,
			Labels:    map[string]string{},
		},
		Limits: explain.DefaultLimits(),
	}

	if o.VerifyFile != "" {
		data, err := os.ReadFile(o.VerifyFile)
		if err != nil {
			return err
		}
		report, err := explain.UnmarshalReport(data)
		if err != nil {
			return err
		}
		if err := explain.VerifyReport(report, input); err != nil {
			return fmt.Errorf("report verification failed: %w", err)
		}
		_, err = fmt.Fprintf(o.Out, "report %s verified successfully against %d files\n", o.VerifyFile, len(o.Filenames))
		return err
	}

	report, err := explain.Explain(input)
	if err != nil {
		return err
	}
	data, err := report.Marshal()
	if err != nil {
		return err
	}
	if o.ReportOut != "" {
		if err := os.WriteFile(o.ReportOut, data, 0o600); err != nil {
			return err
		}
		_, err = fmt.Fprintf(o.Out, "report written to %s (complete=%v)\n", o.ReportOut, report.Complete)
		return err
	}
	_, err = o.Out.Write(append(data, '\n'))
	return err
}

func loadSnapshots(filenames []string) (*snapshotBundle, error) {
	bundle := &snapshotBundle{}
	for _, filename := range filenames {
		fileBytes, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		decoder := goyaml.NewDecoder(bytes.NewReader(fileBytes))
		for {
			var value any
			if err := decoder.Decode(&value); err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
			if value == nil {
				continue
			}
			valueBytes, err := goyaml.Marshal(value)
			if err != nil {
				return nil, err
			}
			var un unstructured.Unstructured
			if err := yaml.Unmarshal(valueBytes, &un); err != nil {
				return nil, err
			}
			gvk := un.GroupVersionKind()
			switch {
			case gvk.Group == rollouts.Group && gvk.Kind == rollouts.RolloutKind:
				var r v1alpha1.Rollout
				if err := yaml.UnmarshalStrict(valueBytes, &r, yaml.DisallowUnknownFields); err != nil {
					return nil, err
				}
				bundle.rollouts = append(bundle.rollouts, &r)
			case gvk.Group == rollouts.Group && gvk.Kind == rollouts.AnalysisTemplateKind:
				var t v1alpha1.AnalysisTemplate
				if err := yaml.UnmarshalStrict(valueBytes, &t, yaml.DisallowUnknownFields); err != nil {
					return nil, err
				}
				bundle.templates = append(bundle.templates, &t)
			case gvk.Group == rollouts.Group && gvk.Kind == rollouts.ClusterAnalysisTemplateKind:
				var t v1alpha1.ClusterAnalysisTemplate
				if err := yaml.UnmarshalStrict(valueBytes, &t, yaml.DisallowUnknownFields); err != nil {
					return nil, err
				}
				bundle.clusterTemplates = append(bundle.clusterTemplates, &t)
			case gvk.Group == "apps" && gvk.Kind == "ReplicaSet":
				var rs appsv1.ReplicaSet
				if err := yaml.UnmarshalStrict(valueBytes, &rs, yaml.DisallowUnknownFields); err != nil {
					return nil, err
				}
				bundle.replicasets = append(bundle.replicasets, &rs)
			}
		}
	}
	return bundle, nil
}

func (o *ExplainOptions) selectReplicaSets(rollout *v1alpha1.Rollout, sets []*appsv1.ReplicaSet) (*appsv1.ReplicaSet, *appsv1.ReplicaSet, error) {
	findByName := func(name string) (*appsv1.ReplicaSet, error) {
		for _, rs := range sets {
			if rs.Name == name {
				return rs, nil
			}
		}
		return nil, fmt.Errorf("ReplicaSet %q not found in snapshot files", name)
	}
	if o.StableRSName != "" && o.LatestRSName != "" {
		stable, err := findByName(o.StableRSName)
		if err != nil {
			return nil, nil, err
		}
		latest, err := findByName(o.LatestRSName)
		if err != nil {
			return nil, nil, err
		}
		return stable, latest, nil
	}
	var stable, latest *appsv1.ReplicaSet
	for _, rs := range sets {
		if rs.Labels == nil {
			continue
		}
		hash := rs.Labels[v1alpha1.DefaultRolloutUniqueLabelKey]
		if hash != "" && hash == rollout.Status.StableRS {
			stable = rs
		}
		if hash != "" && hash == rollout.Status.CurrentPodHash {
			latest = rs
		}
	}
	if stable == nil {
		return nil, nil, fmt.Errorf("stable ReplicaSet (pod hash %q) not found in snapshot files; pass --stable-rs", rollout.Status.StableRS)
	}
	if latest == nil {
		return nil, nil, fmt.Errorf("latest ReplicaSet (pod hash %q) not found in snapshot files; pass --latest-rs", rollout.Status.CurrentPodHash)
	}
	return stable, latest, nil
}

func selectAnalysis(rollout *v1alpha1.Rollout, selector string) (*v1alpha1.RolloutAnalysis, string, error) {
	switch {
	case selector == "background":
		if rollout.Spec.Strategy.Canary == nil || rollout.Spec.Strategy.Canary.Analysis == nil {
			return nil, "", fmt.Errorf("rollout has no canary background analysis")
		}
		return &rollout.Spec.Strategy.Canary.Analysis.RolloutAnalysis, "spec.strategy.canary.analysis", nil
	case selector == "pre":
		if rollout.Spec.Strategy.BlueGreen == nil || rollout.Spec.Strategy.BlueGreen.PrePromotionAnalysis == nil {
			return nil, "", fmt.Errorf("rollout has no blueGreen prePromotionAnalysis")
		}
		return rollout.Spec.Strategy.BlueGreen.PrePromotionAnalysis, "spec.strategy.blueGreen.prePromotionAnalysis", nil
	case selector == "post":
		if rollout.Spec.Strategy.BlueGreen == nil || rollout.Spec.Strategy.BlueGreen.PostPromotionAnalysis == nil {
			return nil, "", fmt.Errorf("rollout has no blueGreen postPromotionAnalysis")
		}
		return rollout.Spec.Strategy.BlueGreen.PostPromotionAnalysis, "spec.strategy.blueGreen.postPromotionAnalysis", nil
	case strings.HasPrefix(selector, "step:"):
		if rollout.Spec.Strategy.Canary == nil {
			return nil, "", fmt.Errorf("rollout has no canary strategy")
		}
		var index int
		if _, err := fmt.Sscanf(selector, "step:%d", &index); err != nil || index < 0 || index >= len(rollout.Spec.Strategy.Canary.Steps) {
			return nil, "", fmt.Errorf("invalid step selector %q", selector)
		}
		step := rollout.Spec.Strategy.Canary.Steps[index]
		if step.Analysis == nil {
			return nil, "", fmt.Errorf("canary step %d has no analysis", index)
		}
		return step.Analysis, fmt.Sprintf("spec.strategy.canary.steps[%d].analysis", index), nil
	default:
		return nil, "", fmt.Errorf("invalid --analysis selector %q (want background, pre, post or step:N)", selector)
	}
}

func loadSecretFile(path string) ([]explain.SecretInput, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc secretFileDoc
	if err := yaml.UnmarshalStrict(data, &doc, yaml.DisallowUnknownFields); err != nil {
		return nil, err
	}
	inputs := make([]explain.SecretInput, 0, len(doc.Secrets))
	for _, s := range doc.Secrets {
		if s.Namespace == "" || s.Name == "" || s.Key == "" {
			return nil, fmt.Errorf("secret entries require namespace, name and key")
		}
		inputs = append(inputs, explain.SecretInput{
			Namespace: s.Namespace,
			Name:      s.Name,
			Key:       s.Key,
			Value:     s.Value,
		})
	}
	return inputs, nil
}
