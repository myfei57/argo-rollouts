package explain

import (
	"encoding/json"
	"fmt"
	"sort"
)

// VerifyReport validates an imported report against the supplied snapshots:
// completion marker, object digests, reference integrity, identity versions and
// a full re-computation of the construction result. Tampering, missing objects
// and UID/resourceVersion conflicts are rejected with explicit reason codes;
// no cluster access is performed.
func VerifyReport(report *Report, in Input) error {
	if report == nil {
		return &VerificationError{Reason: ReasonMarkerInvalid, Message: "report is nil"}
	}
	if report.Kind != ReportKind || report.APIVersion != ReportAPIVersion {
		return &VerificationError{Reason: ReasonMarkerInvalid, Message: "report kind/apiVersion mismatch"}
	}
	if report.FormatVersion != ReportFormatVersion {
		return &VerificationError{Reason: ReasonVersionConflict,
			Message: fmt.Sprintf("unsupported report format version %d, expected %d", report.FormatVersion, ReportFormatVersion)}
	}
	if report.ReportDigest == "" {
		return &VerificationError{Reason: ReasonMarkerInvalid, Message: "report completion marker is missing"}
	}

	// Marker integrity: recompute the digest over the body without the marker.
	stored := report.ReportDigest
	report.ReportDigest = ""
	recomputed, err := digestOf(report)
	report.ReportDigest = stored
	if err != nil {
		return &VerificationError{Reason: ReasonMarkerInvalid, Message: err.Error()}
	}
	if recomputed != stored {
		return &VerificationError{Reason: ReasonDigestMismatch, Message: "report digest does not match its body; the report was tampered with"}
	}

	index, err := buildIdentityIndex(&in)
	if err != nil {
		return &VerificationError{Reason: ReasonInvalidInput, Message: err.Error()}
	}

	// Every digest entry must resolve to a supplied object with the same
	// identity, and the recomputed digest must match.
	for _, entry := range report.Objects {
		obj, ok := index.lookup(entry.Identity)
		if !ok {
			return &VerificationError{Reason: ReasonMissingObject,
				Message: fmt.Sprintf("report references object %s which is absent from the supplied snapshots", renderIdentity(entry.Identity))}
		}
		if obj.identity.UID != entry.Identity.UID || obj.identity.ResourceVersion != entry.Identity.ResourceVersion {
			return &VerificationError{Reason: ReasonVersionConflict,
				Message: fmt.Sprintf("object %s identity changed: report uid=%s rv=%s, snapshot uid=%s rv=%s",
					renderIdentity(entry.Identity), entry.Identity.UID, entry.Identity.ResourceVersion,
					obj.identity.UID, obj.identity.ResourceVersion)}
		}
		current, err := digestOf(obj.obj)
		if err != nil {
			return &VerificationError{Reason: ReasonDigestMismatch, Message: err.Error()}
		}
		if current != entry.Digest {
			return &VerificationError{Reason: ReasonDigestMismatch,
				Message: fmt.Sprintf("digest of %s changed; the object was tampered with", renderIdentity(entry.Identity))}
		}
	}

	// Every traversed object must have a digest entry.
	for _, visit := range report.Traversal.Visits {
		if !index.hasIdentity(visit.Identity) {
			return &VerificationError{Reason: ReasonMissingObject,
				Message: fmt.Sprintf("traversal reaches %s which is not part of the supplied snapshots", renderIdentity(visit.Identity))}
		}
	}

	// Re-run the full explanation and compare the construction outcome.
	fresh, err := Explain(in)
	if err != nil {
		return &VerificationError{Reason: ReasonDiverged, Message: "re-computation failed: " + err.Error()}
	}
	if err := compareReports(report, fresh); err != nil {
		return err
	}
	return nil
}

type indexedObject struct {
	identity ObjectIdentity
	obj      any
}

type identityIndex struct {
	byKey map[string]indexedObject
}

func buildIdentityIndex(in *Input) (*identityIndex, error) {
	idx := &identityIndex{byKey: map[string]indexedObject{}}
	// Index by resolution key (scope/namespace/name): a changed UID or
	// resourceVersion must surface as a version conflict, not a missing object.
	add := func(id ObjectIdentity, obj any) {
		idx.byKey[resolutionKeyOf(id)] = indexedObject{identity: id, obj: obj}
	}
	if in.Rollout != nil {
		add(identityOfMeta(kindRollout, "", in.Rollout.Namespace, in.Rollout.ObjectMeta), in.Rollout)
	}
	if in.StableRS != nil {
		add(identityOfMeta(kindReplicaSet, "", in.StableRS.Namespace, in.StableRS.ObjectMeta), in.StableRS)
	}
	if in.LatestRS != nil {
		add(identityOfMeta(kindReplicaSet, "", in.LatestRS.Namespace, in.LatestRS.ObjectMeta), in.LatestRS)
	}
	for _, t := range in.Templates {
		if t == nil {
			continue
		}
		ns := t.Namespace
		if ns == "" && in.Rollout != nil {
			ns = in.Rollout.Namespace
		}
		add(identityOfMeta(kindAnalysisTemplate, ScopeNamespaced, ns, t.ObjectMeta), t)
	}
	for _, t := range in.ClusterTemplates {
		if t == nil {
			continue
		}
		add(identityOfMeta(kindClusterAnalysisTemplate, ScopeCluster, "", t.ObjectMeta), t)
	}
	return idx, nil
}

func (i *identityIndex) lookup(id ObjectIdentity) (indexedObject, bool) {
	o, ok := i.byKey[resolutionKeyOf(id)]
	return o, ok
}

func (i *identityIndex) hasIdentity(id ObjectIdentity) bool {
	_, ok := i.byKey[resolutionKeyOf(id)]
	return ok
}

func resolutionKeyOf(id ObjectIdentity) string {
	switch id.Kind {
	case kindAnalysisTemplate:
		return nodeKey(ScopeNamespaced, id.Namespace, id.Name)
	case kindClusterAnalysisTemplate:
		return nodeKey(ScopeCluster, "", id.Name)
	default:
		return nodeKey(id.Scope, id.Namespace, id.Name)
	}
}

func compareReports(stored, fresh *Report) error {
	if stored.Complete != fresh.Complete {
		return &VerificationError{Reason: ReasonDiverged, Message: "completion marker diverges on re-computation"}
	}
	if (stored.Candidate == nil) != (fresh.Candidate == nil) {
		return &VerificationError{Reason: ReasonDiverged, Message: "candidate presence diverges on re-computation"}
	}
	if stored.Candidate != nil {
		a, _ := json.Marshal(stored.Candidate.AnalysisRun)
		b, _ := json.Marshal(fresh.Candidate.AnalysisRun)
		if string(a) != string(b) {
			return &VerificationError{Reason: ReasonDiverged, Message: "constructed AnalysisRun diverges on re-computation"}
		}
		if stored.Candidate.Digest != fresh.Candidate.Digest {
			return &VerificationError{Reason: ReasonDigestMismatch, Message: "candidate digest diverges on re-computation"}
		}
	}
	if stored.ConstructorError != fresh.ConstructorError {
		return &VerificationError{Reason: ReasonDiverged,
			Message: fmt.Sprintf("constructor error diverges: stored=%q fresh=%q", stored.ConstructorError, fresh.ConstructorError)}
	}
	if err := compareConflictSets(stored.Conflicts, fresh.Conflicts); err != nil {
		return err
	}
	if err := compareUnresolvedSets(stored.Unresolved, fresh.Unresolved); err != nil {
		return err
	}
	if len(stored.Traversal.Visits) != len(fresh.Traversal.Visits) {
		return &VerificationError{Reason: ReasonDiverged, Message: "traversal visit count diverges on re-computation"}
	}
	for i := range stored.Traversal.Visits {
		if stored.Traversal.Visits[i].Identity != fresh.Traversal.Visits[i].Identity ||
			stored.Traversal.Visits[i].Deduped != fresh.Traversal.Visits[i].Deduped {
			return &VerificationError{Reason: ReasonDiverged, Message: "traversal order or de-duplication diverges on re-computation"}
		}
	}
	if len(stored.Metrics) != len(fresh.Metrics) {
		return &VerificationError{Reason: ReasonDiverged, Message: "metric explanation count diverges"}
	}
	for i := range stored.Metrics {
		if len(stored.Metrics[i].Segments) != len(fresh.Metrics[i].Segments) {
			return &VerificationError{Reason: ReasonDiverged,
				Message: fmt.Sprintf("parameter segment count for metric %q diverges", stored.Metrics[i].Name)}
		}
		if stored.Metrics[i].Status != fresh.Metrics[i].Status {
			return &VerificationError{Reason: ReasonDiverged,
				Message: fmt.Sprintf("resolution status for metric %q diverges", stored.Metrics[i].Name)}
		}
	}
	return nil
}

func compareConflictSets(a, b []Conflict) error {
	if len(a) != len(b) {
		return &VerificationError{Reason: ReasonDiverged,
			Message: fmt.Sprintf("conflict count diverges: stored=%d fresh=%d", len(a), len(b))}
	}
	key := func(c Conflict) string {
		paths := ""
		for _, p := range c.Paths {
			paths += "|" + p.String()
		}
		return c.Kind + "/" + c.Name + "/" + c.Field + paths
	}
	sort.SliceStable(a, func(i, j int) bool { return key(a[i]) < key(a[j]) })
	sort.SliceStable(b, func(i, j int) bool { return key(b[i]) < key(b[j]) })
	for i := range a {
		if key(a[i]) != key(b[i]) || a[i].ConstructorError != b[i].ConstructorError {
			return &VerificationError{Reason: ReasonDiverged,
				Message: fmt.Sprintf("conflict %q diverges on re-computation", key(a[i]))}
		}
	}
	return nil
}

func compareUnresolvedSets(a, b []UnresolvedItem) error {
	if len(a) != len(b) {
		return &VerificationError{Reason: ReasonDiverged,
			Message: fmt.Sprintf("unresolved item count diverges: stored=%d fresh=%d", len(a), len(b))}
	}
	key := func(u UnresolvedItem) string { return u.Kind + "/" + u.Name + "/" + u.Reason }
	sort.SliceStable(a, func(i, j int) bool { return key(a[i]) < key(a[j]) })
	sort.SliceStable(b, func(i, j int) bool { return key(b[i]) < key(b[j]) })
	for i := range a {
		if key(a[i]) != key(b[i]) {
			return &VerificationError{Reason: ReasonDiverged,
				Message: fmt.Sprintf("unresolved item %q diverges", key(a[i]))}
		}
	}
	return nil
}

// Marshal renders the report to canonical indented JSON for file output.
func (r *Report) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// UnmarshalReport parses a report from JSON bytes.
func UnmarshalReport(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
