package explain

import (
	"fmt"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

// Conflict kind constants.
const (
	ConflictDuplicateMetric        = "DuplicateMetric"
	ConflictConflictingArgDefault  = "ConflictingArgDefault"
	ConflictDuplicateDryRunRule    = "DuplicateDryRunRule"
	ConflictDuplicateRetentionRule = "DuplicateRetentionRule"
)

type metricSource struct {
	metric v1alpha1.Metric
	node   *templateNode
	index  int
	path   SourcePath
}

type argDefOccurrence struct {
	arg     v1alpha1.Argument
	node    *templateNode
	index   int
	path    SourcePath
	deduped bool
}

type argSlot struct {
	name        string
	arg         v1alpha1.Argument
	definitions []argDefOccurrence
	winner      *argDefOccurrence
	override    *ArgOverride
}

type dryRuleSource struct {
	dryRun   v1alpha1.DryRun
	node     *templateNode
	index    int
	path     SourcePath
	incoming bool
}

type retentionRuleSource struct {
	rule     v1alpha1.MeasurementRetention
	node     *templateNode
	index    int
	path     SourcePath
	incoming bool
}

type flattenResult struct {
	metrics        []metricSource
	slots          []*argSlot
	dryRules       []dryRuleSource
	retentionRules []retentionRuleSource
	conflicts      []Conflict
}

// orderedNodes returns the unique nodes in the exact consumption order of
// FlattenTemplates: namespaced templates first, then cluster templates.
func orderedNodes(g *graph, uniqueNS []*v1alpha1.AnalysisTemplate, uniqueCL []*v1alpha1.ClusterAnalysisTemplate) []*templateNode {
	out := make([]*templateNode, 0, len(uniqueNS)+len(uniqueCL))
	for _, t := range uniqueNS {
		ns := t.Namespace
		if ns == "" {
			ns = g.namespace
		}
		out = append(out, g.nodes[nodeKey(ScopeNamespaced, ns, t.Name)])
	}
	for _, t := range uniqueCL {
		out = append(out, g.nodes[nodeKey(ScopeCluster, "", t.Name)])
	}
	return out
}

func specOf(n *templateNode) v1alpha1.AnalysisTemplateSpec {
	if n.scope == ScopeCluster {
		return n.ctpl.Spec
	}
	return n.tpl.Spec
}

// flattenTemplates mirrors FlattenTemplates while retaining the source of
// every adopted item. It never alters construction outcomes: conflicts are
// recorded with the exact constructor message and the same failure the real
// constructor would return.
func flattenTemplates(g *graph, uniqueNS []*v1alpha1.AnalysisTemplate, uniqueCL []*v1alpha1.ClusterAnalysisTemplate) *flattenResult {
	res := &flattenResult{}
	nodes := orderedNodes(g, uniqueNS, uniqueCL)

	// Metrics: flattenMetrics appends in order, errors on duplicate names.
	metricByName := map[string]*metricSource{}
	for _, n := range nodes {
		spec := specOf(n)
		for i, m := range spec.Metrics {
			field := fmt.Sprintf("spec.metrics[%d]", i)
			src := metricSource{
				metric: m,
				node:   n,
				index:  i,
				path:   g.shortestSourcePaths(n, field, 1)[0],
			}
			if prev, ok := metricByName[m.Name]; ok {
				res.conflicts = append(res.conflicts, Conflict{
					Kind:             ConflictDuplicateMetric,
					Field:            "spec.metrics[*].name",
					Name:             m.Name,
					Paths:            []SourcePath{prev.path, src.path},
					ConstructorError: fmt.Sprintf("two metrics have the same name '%s'", m.Name),
				})
				continue
			}
			metricByName[m.Name] = &src
			res.metrics = append(res.metrics, src)
		}
	}

	// Args: exact mirror of flattenArgs including nil vs empty-string handling.
	slotByName := map[string]*argSlot{}
	for _, n := range nodes {
		spec := specOf(n)
		for i, arg := range spec.Args {
			field := fmt.Sprintf("spec.args[%d]", i)
			occ := argDefOccurrence{
				arg:   arg,
				node:  n,
				index: i,
				path:  g.shortestSourcePaths(n, field, 1)[0],
			}
			slot, ok := slotByName[arg.Name]
			if !ok {
				slot = &argSlot{name: arg.Name, arg: arg}
				winner := occ
				slot.winner = &winner
				slotByName[arg.Name] = slot
				res.slots = append(res.slots, slot)
			} else {
				if slot.arg.Value != nil && arg.Value != nil && *slot.arg.Value != *arg.Value {
					res.conflicts = append(res.conflicts, Conflict{
						Kind:  ConflictConflictingArgDefault,
						Field: "spec.args[*].value",
						Name:  arg.Name,
						Paths: []SourcePath{
							g.shortestSourcePaths(slot.winner.node, fmt.Sprintf("spec.args[%d]", slot.winner.index), 1)[0],
							occ.path,
						},
						ConstructorError: fmt.Sprintf("Argument `%s` specified multiple times with different values: '%s', '%s'",
							arg.Name, *slot.arg.Value, *arg.Value),
					})
				}
				// A nil previous value is replaced even when the new value is
				// also nil; otherwise the first definition stays the winner.
				if slot.arg.Value == nil {
					slot.arg = arg
					winner := occ
					slot.winner = &winner
				}
			}
			slot.definitions = append(slot.definitions, occ)
		}
	}

	// Dry run rules: incoming rules first, then template rules, matching
	// mergeDryRunMetrics(rolloutAnalysis.DryRun, template.Spec.DryRun).
	seenDry := map[string]dryRuleSource{}
	for i, rule := range g.analysisDryRun() {
		src := dryRuleSource{
			dryRun:   rule,
			index:    i,
			path:     g.rolloutPath(fmt.Sprintf("%s.dryRun[%d]", g.analysisFieldPath, i)),
			incoming: true,
		}
		seenDry[rule.MetricName] = src
		res.dryRules = append(res.dryRules, src)
	}
	for _, n := range nodes {
		spec := specOf(n)
		for i, rule := range spec.DryRun {
			field := fmt.Sprintf("spec.dryRun[%d]", i)
			src := dryRuleSource{
				dryRun: rule,
				node:   n,
				index:  i,
				path:   g.shortestSourcePaths(n, field, 1)[0],
			}
			if prev, ok := seenDry[rule.MetricName]; ok {
				res.conflicts = append(res.conflicts, Conflict{
					Kind:             ConflictDuplicateDryRunRule,
					Field:            "dryRun[*].metricName",
					Name:             rule.MetricName,
					Paths:            []SourcePath{prev.path, src.path},
					ConstructorError: fmt.Sprintf("two Dry-Run metric rules have the same name '%s'", rule.MetricName),
				})
				continue
			}
			seenDry[rule.MetricName] = src
			res.dryRules = append(res.dryRules, src)
		}
	}

	// Measurement retention rules, same ordering and validation semantics.
	seenRetention := map[string]retentionRuleSource{}
	for i, rule := range g.analysisRetention() {
		src := retentionRuleSource{
			rule:     rule,
			index:    i,
			path:     g.rolloutPath(fmt.Sprintf("%s.measurementRetention[%d]", g.analysisFieldPath, i)),
			incoming: true,
		}
		seenRetention[rule.MetricName] = src
		res.retentionRules = append(res.retentionRules, src)
	}
	for _, n := range nodes {
		spec := specOf(n)
		for i, rule := range spec.MeasurementRetention {
			field := fmt.Sprintf("spec.measurementRetention[%d]", i)
			src := retentionRuleSource{
				rule:  rule,
				node:  n,
				index: i,
				path:  g.shortestSourcePaths(n, field, 1)[0],
			}
			if prev, ok := seenRetention[rule.MetricName]; ok {
				res.conflicts = append(res.conflicts, Conflict{
					Kind:             ConflictDuplicateRetentionRule,
					Field:            "measurementRetention[*].metricName",
					Name:             rule.MetricName,
					Paths:            []SourcePath{prev.path, src.path},
					ConstructorError: fmt.Sprintf("two Measurement Retention metric rules have the same name '%s'", rule.MetricName),
				})
				continue
			}
			seenRetention[rule.MetricName] = src
			res.retentionRules = append(res.retentionRules, src)
		}
	}

	return res
}

// applyIncomingArgs mirrors MergeArgs: incoming args only override matching
// template args, Value (even pointer-to-empty) wins over ValueFrom, unmatched
// incoming names are ignored, unresolved leftovers are reported, never guessed.
func (res *flattenResult) applyIncomingArgs(g *graph, incoming []v1alpha1.Argument) {
	for i := range incoming {
		in := incoming[i]
		var slot *argSlot
		for _, s := range res.slots {
			if s.name == in.Name {
				slot = s
				break
			}
		}
		if slot == nil {
			// Real MergeArgs silently ignores incoming args absent from templates.
			continue
		}
		path := g.rolloutPath(fmt.Sprintf("%s.args[%d]", g.analysisFieldPath, i))
		switch {
		case in.Value != nil:
			slot.arg.Value = in.Value
			slot.arg.ValueFrom = nil
			override := ArgOverride{
				Source:       path,
				OverrideKind: "Value",
				ValuePresent: true,
				ValueIsEmpty: *in.Value == "",
				Value:        *in.Value,
			}
			slot.override = &override
		case in.ValueFrom != nil:
			slot.arg.ValueFrom = in.ValueFrom
			slot.arg.Value = nil
			override := ArgOverride{
				Source:       path,
				OverrideKind: "ValueFrom",
				ValueFrom:    g.explainValueFrom(in.ValueFrom),
			}
			slot.override = &override
		}
	}
}

// unresolvedArgs returns slots matching the ResolveArgs failure condition.
func (res *flattenResult) unresolvedArgs() []*argSlot {
	var out []*argSlot
	for _, slot := range res.slots {
		if slot.arg.Value == nil && slot.arg.ValueFrom == nil {
			out = append(out, slot)
		}
	}
	return out
}

func (g *graph) rolloutPath(field string) SourcePath {
	return SourcePath{Hops: []SourceHop{{Object: g.rolloutID, Field: field}}}
}
