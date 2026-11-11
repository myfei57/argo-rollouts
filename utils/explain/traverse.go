package explain

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	analysisutil "github.com/argoproj/argo-rollouts/utils/analysis"
)

// templateNode is one unique template object reached by the traversal.
type templateNode struct {
	id      ObjectIdentity
	scope   Scope
	tpl     *v1alpha1.AnalysisTemplate
	ctpl    *v1alpha1.ClusterAnalysisTemplate
	refs    []v1alpha1.AnalysisTemplateRef
	visits  []*visit
	expSize int
}

// visit is one DFS occurrence of a node. A diamond shared template has several
// visits, of which only the first survives de-duplication.
type visit struct {
	seq      int
	node     *templateNode
	depth    int
	edgePath []RefEdge
	deduped  bool
}

// graph holds the walked reference graph and mirrors the bookkeeping of
// rolloutContext.getAnalysisTemplatesFromRefs.
type graph struct {
	rolloutID             ObjectIdentity
	analysisFieldPath     string
	namespace             string
	limits                Limits
	analysis              *v1alpha1.RolloutAnalysis
	stableRS              *appsv1.ReplicaSet
	latestRS              *appsv1.ReplicaSet
	stableRSID            ObjectIdentity
	latestRSID            ObjectIdentity
	secrets               map[string]SecretInput
	sharedSecretNamespace string

	nodes        map[string]*templateNode
	visits       []*visit
	edges        []RefEdge
	rootEdges    []RefEdge
	rawNS        []*v1alpha1.AnalysisTemplate
	rawCL        []*v1alpha1.ClusterAnalysisTemplate
	cycles       []CycleDiagnostic
	edgeCount    int
	expansionSum int
}

func nodeKey(scope Scope, namespace, name string) string {
	return string(scope) + "|" + namespace + "|" + name
}

func identityOfMeta(kind string, scope Scope, namespace string, meta metav1.ObjectMeta) ObjectIdentity {
	return ObjectIdentity{
		Kind:            kind,
		Scope:           scope,
		Namespace:       namespace,
		Name:            meta.Name,
		UID:             string(meta.UID),
		ResourceVersion: meta.ResourceVersion,
	}
}

// newGraph builds the closed snapshot resolver. Namespaced templates are only
// visible in the rollout namespace, exactly like the namespace scoped lister.
func newGraph(in *Input) (*graph, error) {
	g := &graph{
		rolloutID:         identityOfMeta(kindRollout, "", in.Rollout.Namespace, in.Rollout.ObjectMeta),
		analysisFieldPath: in.AnalysisFieldPath,
		namespace:         in.Rollout.Namespace,
		limits:            in.Limits,
		analysis:          in.Analysis,
		secrets:           map[string]SecretInput{},
		nodes:             map[string]*templateNode{},
	}
	if in.StableRS != nil {
		g.stableRS = in.StableRS
		g.stableRSID = identityOfMeta(kindReplicaSet, "", in.StableRS.Namespace, in.StableRS.ObjectMeta)
	}
	if in.LatestRS != nil {
		g.latestRS = in.LatestRS
		g.latestRSID = identityOfMeta(kindReplicaSet, "", in.LatestRS.Namespace, in.LatestRS.ObjectMeta)
	}
	for _, s := range in.SecretInputs {
		g.secrets[secretKey(s.Namespace, s.Name, s.Key)] = s
	}
	g.sharedSecretNamespace = in.SharedSecretNamespace

	for _, t := range in.Templates {
		if t == nil {
			continue
		}
		ns := t.Namespace
		if ns == "" {
			ns = in.Rollout.Namespace
		}
		id := identityOfMeta(kindAnalysisTemplate, ScopeNamespaced, ns, t.ObjectMeta)
		key := nodeKey(ScopeNamespaced, ns, t.Name)
		if existing, ok := g.nodes[key]; ok {
			if existing.id.UID != id.UID || existing.id.ResourceVersion != id.ResourceVersion {
				return nil, &ExplainError{
					Reason:  ReasonInvalidInput,
					Message: fmt.Sprintf("ambiguous snapshot: two namespaced templates named %q in namespace %q with different identity", t.Name, ns),
				}
			}
			continue
		}
		size, err := jsonSize(t)
		if err != nil {
			return nil, err
		}
		g.nodes[key] = &templateNode{
			id:      id,
			scope:   ScopeNamespaced,
			tpl:     t,
			refs:    t.Spec.Templates,
			expSize: size,
		}
	}

	for _, t := range in.ClusterTemplates {
		if t == nil {
			continue
		}
		id := identityOfMeta(kindClusterAnalysisTemplate, ScopeCluster, "", t.ObjectMeta)
		key := nodeKey(ScopeCluster, "", t.Name)
		if existing, ok := g.nodes[key]; ok {
			if existing.id.UID != id.UID || existing.id.ResourceVersion != id.ResourceVersion {
				return nil, &ExplainError{
					Reason:  ReasonInvalidInput,
					Message: fmt.Sprintf("ambiguous snapshot: two cluster templates named %q with different identity", t.Name),
				}
			}
			continue
		}
		size, err := jsonSize(t)
		if err != nil {
			return nil, err
		}
		g.nodes[key] = &templateNode{
			id:      id,
			scope:   ScopeCluster,
			ctpl:    t,
			refs:    t.Spec.Templates,
			expSize: size,
		}
	}
	return g, nil
}

func jsonSize(obj any) (int, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return 0, &ExplainError{Reason: ReasonInvalidInput, Message: err.Error()}
	}
	return len(b), nil
}

func idKey(id ObjectIdentity) string {
	return string(id.Scope) + "|" + id.Namespace + "|" + id.Name + "|" + id.UID + "|" + id.ResourceVersion
}

// walk performs the DFS. Parent is nil for the Rollout root refs. The append
// order (parent before children, namespaced and cluster lists kept separate)
// matches getAnalysisTemplatesFromRefs exactly.
func (g *graph) walk(refs []v1alpha1.AnalysisTemplateRef, parent *templateNode, parentField string,
	stack []string, stackEdges []RefEdge, depth int) error {
	for i := range refs {
		ref := refs[i]
		fieldPath := fmt.Sprintf("%s.templates[%d]", parentField, i)
		nextDepth := depth + 1
		if nextDepth > g.limits.MaxDepth {
			return newLimitError("template reference depth", nextDepth, g.limits.MaxDepth)
		}
		g.edgeCount++
		if g.edgeCount > g.limits.MaxEdges {
			return newLimitError("template reference edge", g.edgeCount, g.limits.MaxEdges)
		}

		scope := ScopeNamespaced
		ns := g.namespace
		if ref.IsClusterScope() {
			scope = ScopeCluster
			ns = ""
		}
		key := nodeKey(scope, ns, ref.TemplateName)
		node, ok := g.nodes[key]
		if !ok {
			// Same name in the other scope must not silently satisfy the ref.
			return newNotFoundError(scope, g.namespace, ref.TemplateName)
		}

		from := g.rolloutID
		if parent != nil {
			from = parent.id
		}
		edge := RefEdge{
			From:         from,
			FieldPath:    fieldPath,
			RefIndex:     i,
			ClusterScope: ref.IsClusterScope(),
			TemplateName: ref.TemplateName,
			To:           node.id,
		}

		// Bounded cycle detection: re-entering an ancestor closes a cycle. The
		// real controller recurses unboundedly here; we refuse with a path.
		for _, ancestor := range stack {
			if ancestor == key {
				diag := CycleDiagnostic{
					Path:   append(append([]RefEdge{}, stackEdges...), edge),
					BackTo: node.id,
				}
				g.cycles = append(g.cycles, diag)
				return newCycleError(diag)
			}
		}

		if depth == 0 {
			g.rootEdges = append(g.rootEdges, edge)
		}
		g.edges = append(g.edges, edge)

		// Append before recursing, and keep the scope lists separated.
		if node.scope == ScopeCluster {
			g.rawCL = append(g.rawCL, node.ctpl)
		} else {
			g.rawNS = append(g.rawNS, node.tpl)
		}
		v := &visit{
			seq:      len(g.visits),
			node:     node,
			depth:    nextDepth,
			edgePath: append(append([]RefEdge{}, stackEdges...), edge),
		}
		g.visits = append(g.visits, v)
		node.visits = append(node.visits, v)

		// First time this node is reached, account for its expansion budget.
		if len(node.visits) == 1 {
			g.expansionSum += node.expSize
			if g.expansionSum > g.limits.MaxExpansionBytes {
				return newLimitError("template expansion bytes", g.expansionSum, g.limits.MaxExpansionBytes)
			}
			if len(g.visitedUniqueNodes()) > g.limits.MaxTemplates {
				return newLimitError("unique template", len(g.visitedUniqueNodes()), g.limits.MaxTemplates)
			}
		}

		// The real code only recurses when Spec.Templates is non-nil.
		if node.refs != nil {
			if err := g.walk(node.refs, node, "spec", append(append([]string{}, stack...), key),
				append(append([]RefEdge{}, stackEdges...), edge), nextDepth); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *graph) visitedUniqueNodes() []*templateNode {
	unique := map[string]*templateNode{}
	for _, v := range g.visits {
		unique[idKey(v.node.id)] = v.node
	}
	out := make([]*templateNode, 0, len(unique))
	for _, n := range unique {
		out = append(out, n)
	}
	return out
}

// traverse walks the root refs and then applies the real FilterUniqueTemplates
// de-duplication, marking losing visits.
func traverse(in *Input) (*graph, []*v1alpha1.AnalysisTemplate, []*v1alpha1.ClusterAnalysisTemplate, error) {
	g, err := newGraph(in)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := g.walk(in.Analysis.Templates, nil, in.AnalysisFieldPath, nil, nil, 0); err != nil {
		return g, nil, nil, err
	}

	// Delegate to the production de-duplication rule so ordering and first
	// occurrence semantics cannot drift from the controller.
	uniqueNS, uniqueCL := analysisutil.FilterUniqueTemplates(g.rawNS, g.rawCL)

	seenNS := map[string]bool{}
	seenCL := map[string]bool{}
	for _, v := range g.visits {
		var key string
		if v.node.scope == ScopeCluster {
			key = v.node.id.Name
			if seenCL[key] {
				v.markDeduped()
				continue
			}
			seenCL[key] = true
		} else {
			key = v.node.id.Namespace + "/" + v.node.id.Name
			if seenNS[key] {
				v.markDeduped()
				continue
			}
			seenNS[key] = true
		}
	}
	return g, uniqueNS, uniqueCL, nil
}

func (v *visit) markDeduped() {
	v.deduped = true
}

// buildSourcePath turns an edge chain into a full source path, ending on
// finalObject/finalField.
func buildSourcePath(edgePath []RefEdge, finalObject ObjectIdentity, finalField string) SourcePath {
	hops := make([]SourceHop, 0, len(edgePath)+1)
	if len(edgePath) == 0 {
		hops = append(hops, SourceHop{Object: finalObject, Field: finalField})
		return SourcePath{Hops: hops}
	}
	hops = append(hops, SourceHop{Object: edgePath[0].From, Field: edgePath[0].FieldPath})
	for i, edge := range edgePath {
		field := finalField
		if i < len(edgePath)-1 {
			field = edgePath[i+1].FieldPath
		}
		edgeCopy := edge
		hops = append(hops, SourceHop{Edge: &edgeCopy, Object: edge.To, Field: field})
	}
	return SourcePath{Hops: hops}
}

// shortestSourcePaths returns up to two shortest root-to-field paths for a
// node. Ties break deterministically on the rendered path so conflict
// diagnostics are reproducible.
func (g *graph) shortestSourcePaths(n *templateNode, finalField string, limit int) []SourcePath {
	paths := make([]SourcePath, 0, len(n.visits))
	for _, v := range n.visits {
		paths = append(paths, buildSourcePath(v.edgePath, n.id, finalField))
	}
	sort.Slice(paths, func(i, j int) bool {
		ri, rj := len(paths[i].Hops), len(paths[j].Hops)
		if ri != rj {
			return ri < rj
		}
		return paths[i].String() < paths[j].String()
	})
	if len(paths) > limit {
		paths = paths[:limit]
	}
	return paths
}

// String renders a source path for human diagnostics.
func (p SourcePath) String() string {
	parts := make([]string, 0, len(p.Hops))
	for _, hop := range p.Hops {
		part := renderIdentity(hop.Object)
		if hop.Field != "" {
			part += "(" + hop.Field + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " -> ")
}

func renderIdentity(id ObjectIdentity) string {
	switch id.Kind {
	case kindClusterAnalysisTemplate:
		return fmt.Sprintf("ClusterAnalysisTemplate/%s", id.Name)
	case kindAnalysisTemplate:
		return fmt.Sprintf("AnalysisTemplate/%s/%s", id.Namespace, id.Name)
	case kindReplicaSet:
		return fmt.Sprintf("ReplicaSet/%s/%s", id.Namespace, id.Name)
	case kindAnalysisRun:
		return fmt.Sprintf("AnalysisRun/%s/%s", id.Namespace, id.Name)
	default:
		if id.Namespace != "" {
			return fmt.Sprintf("%s/%s/%s", id.Kind, id.Namespace, id.Name)
		}
		return fmt.Sprintf("%s/%s", id.Kind, id.Name)
	}
}

// summary converts the traversal into its serializable form.
func (g *graph) summary(uniqueNS []*v1alpha1.AnalysisTemplate, uniqueCL []*v1alpha1.ClusterAnalysisTemplate) TraversalSummary {
	visits := make([]VisitRecord, 0, len(g.visits))
	for _, v := range g.visits {
		visits = append(visits, VisitRecord{
			Sequence: v.seq,
			Identity: v.node.id,
			Depth:    v.depth,
			Deduped:  v.deduped,
			EdgePath: append([]RefEdge{}, v.edgePath...),
		})
	}
	nsIDs := make([]ObjectIdentity, 0, len(uniqueNS))
	for _, t := range uniqueNS {
		ns := t.Namespace
		if ns == "" {
			ns = g.namespace
		}
		nsIDs = append(nsIDs, identityOfMeta(kindAnalysisTemplate, ScopeNamespaced, ns, t.ObjectMeta))
	}
	clIDs := make([]ObjectIdentity, 0, len(uniqueCL))
	for _, t := range uniqueCL {
		clIDs = append(clIDs, identityOfMeta(kindClusterAnalysisTemplate, ScopeCluster, "", t.ObjectMeta))
	}
	return TraversalSummary{
		RootRefs:         append([]RefEdge{}, g.rootEdges...),
		Edges:            append([]RefEdge{}, g.edges...),
		Visits:           visits,
		UniqueNamespaced: nsIDs,
		UniqueCluster:    clIDs,
		Cycles:           append([]CycleDiagnostic{}, g.cycles...),
	}
}
