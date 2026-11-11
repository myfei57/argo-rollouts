package explain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	analysisutil "github.com/argoproj/argo-rollouts/utils/analysis"
	templateutil "github.com/argoproj/argo-rollouts/utils/template"
)

const (
	openBracket  = "{{"
	closeBracket = "}}"
	// redactionMarker replaces secret fed leaves in report-resolved metrics.
	redactionMarker = "***REDACTED-SECRET***"
)

// tagSpan is one {{...}} occurrence located in the marshaled metric JSON.
type tagSpan struct {
	start   int
	end     int
	inner   string
	cleaned string
}

// scanTags mirrors fasttemplate.Reset tag splitting: first open tag, then the
// nearest close tag; an unclosed open tag is an error with the same message.
func scanTags(s string) ([]tagSpan, error) {
	var spans []tagSpan
	pos := 0
	for {
		rel := strings.Index(s[pos:], openBracket)
		if rel < 0 {
			return spans, nil
		}
		open := pos + rel
		afterOpen := open + len(openBracket)
		relClose := strings.Index(s[afterOpen:], closeBracket)
		if relClose < 0 {
			return nil, fmt.Errorf("Cannot find end tag=%q in the template=%q starting from %q",
				closeBracket, s, s[afterOpen:])
		}
		close := afterOpen + relClose
		inner := s[afterOpen:close]
		spans = append(spans, tagSpan{
			start:   open,
			end:     close + len(closeBracket),
			inner:   inner,
			cleaned: strings.TrimSpace(inner),
		})
		pos = close + len(closeBracket)
	}
}

// jsonStringValue is one decoded JSON string value span with its field path.
type jsonStringValue struct {
	path  string
	start int
	end   int
}

type pathFrame struct {
	isMap      bool
	pendingKey string
	arrayIndex int
}

// jsonStringValues tokenizes marshaled JSON and records the byte span of every
// string value together with its dotted field path. Tag fragments can only
// appear inside string values of the metric struct.
func jsonStringValues(data []byte) ([]jsonStringValue, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*pathFrame
	var values []jsonStringValue

	currentPath := func() string {
		parts := make([]string, 0, len(stack))
		for _, f := range stack {
			if f.isMap {
				parts = append(parts, f.pendingKey)
			} else {
				parts = append(parts, strconv.Itoa(f.arrayIndex))
			}
		}
		return strings.Join(parts, ".")
	}

	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return values, nil
			}
			return nil, err
		}
		end := dec.InputOffset()
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &pathFrame{isMap: true})
			case '[':
				stack = append(stack, &pathFrame{isMap: false, arrayIndex: -1})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				// The nested container was itself a value of the parent.
				if len(stack) > 0 {
					parent := stack[len(stack)-1]
					if parent.isMap {
						parent.pendingKey = ""
					} else {
						parent.arrayIndex++
					}
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].isMap && stack[len(stack)-1].pendingKey == "" {
				// Object key: the next scalar value belongs to this key.
				stack[len(stack)-1].pendingKey = t
				continue
			}
			values = append(values, jsonStringValue{path: currentPath(), start: int(start), end: int(end)})
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				if top.isMap {
					top.pendingKey = ""
				} else {
					top.arrayIndex++
				}
			}
		default:
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				if top.isMap {
					top.pendingKey = ""
				} else {
					top.arrayIndex++
				}
			}
		}
	}
}

// containingField returns the field path of the innermost string value span
// containing the given byte offset.
func containingField(values []jsonStringValue, offset int) string {
	for _, v := range values {
		if offset >= v.start && offset < v.end {
			return v.path
		}
	}
	return ""
}

func runeLen(b []byte) int {
	return utf8.RuneCount(b)
}

// quoteArgValue replicates ResolveQuotedArgs' escaping exactly: strconv.Quote
// with the surrounding double quotes stripped.
func quoteArgValue(value string) string {
	q := strconv.Quote(value)
	return q[1 : len(q)-1]
}

// effectiveArgs builds the argument slice used for metric resolution. Supplied
// secrets are substituted in-memory only; the candidate run spec keeps its
// opaque ValueFrom. The first nil value reproduces the ResolveArgs failure.
func (e *explainer) effectiveArgs(adopted []v1alpha1.Argument) ([]v1alpha1.Argument, *UnresolvedItem) {
	out := make([]v1alpha1.Argument, len(adopted))
	copy(out, adopted)
	for i := range out {
		if out[i].Value != nil {
			continue
		}
		if ref := secretRefOfArgument(out[i], e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets); ref != nil {
			if !ref.Supplied {
				return nil, &UnresolvedItem{
					Kind:   "SecretArgument",
					Name:   out[i].Name,
					Reason: fmt.Sprintf("secret %s/%s key %q was not supplied and is never read from the cluster", ref.Namespace, ref.Name, ref.Key),
					Secret: ref,
				}
			}
			v := e.graph.secrets[secretKey(ref.Namespace, ref.Name, ref.Key)].Value
			out[i].Value = &v
			continue
		}
		return nil, &UnresolvedItem{
			Kind:   "Argument",
			Name:   out[i].Name,
			Reason: fmt.Sprintf("argument %q was not supplied", out[i].Name),
		}
	}
	return out, nil
}

// resolution captures the explanation of one flattened metric.
type resolution struct {
	explanation MetricExplanation
	resolved    *v1alpha1.Metric
	// secretFields are field paths whose resolved value is secret fed.
	secretFields map[string]bool
	// secretArgs are arg names whose adopted value is secret fed.
	secretArgs map[string]bool
}

// resolveMetric runs the instrumented resolution and cross-checks every output
// against the production ResolveMetricArgs / ResolveQuotedArgs functions so the
// explanation cannot silently diverge from construction semantics.
func (e *explainer) resolveMetric(src metricSource, adopted []v1alpha1.Argument) resolution {
	out := resolution{
		explanation: MetricExplanation{
			Name:   src.metric.Name,
			Source: src.path,
			Status: StatusResolved,
		},
		secretFields: map[string]bool{},
		secretArgs:   map[string]bool{},
	}
	marshaled, err := json.Marshal(src.metric)
	if err != nil {
		out.explanation.Status = StatusUnresolved
		out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, err.Error())
		return out
	}
	tags, err := scanTags(string(marshaled))
	if err != nil {
		// Mirror the production error for the unclosed-tag case.
		if _, realErr := analysisutil.ResolveMetricArgs(src.metric, adopted); realErr != nil && realErr.Error() == err.Error() {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, realErr.Error())
			return out
		}
		out.explanation.Status = StatusUnresolved
		out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, err.Error())
		return out
	}
	fields, err := jsonStringValues(marshaled)
	if err != nil {
		out.explanation.Status = StatusUnresolved
		out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, err.Error())
		return out
	}

	effective, unresolved := e.effectiveArgs(adopted)
	argByName := map[string]v1alpha1.Argument{}
	for _, a := range adopted {
		argByName[a.Name] = a
	}
	effByName := map[string]v1alpha1.Argument{}
	if effective != nil {
		for _, a := range effective {
			effByName[a.Name] = a
		}
	}

	var b strings.Builder
	outputPos := 0
	prev := 0
	for _, tag := range tags {
		b.WriteString(string(marshaled[prev:tag.start]))
		outputPos += tag.start - prev

		fieldPath := containingField(fields, tag.start)
		seg := ParamSegment{
			FieldPath:       fieldPath,
			RawTag:          string(marshaled[tag.start:tag.end]),
			SourceByteRange: [2]int{tag.start, tag.end},
			SourceRuneRange: [2]int{runeLen(marshaled[:tag.start]), runeLen(marshaled[:tag.end])},
			OutputByteRange: [2]int{-1, -1},
			OutputRuneRange: [2]int{-1, -1},
			Status:          StatusResolved,
		}
		argName := argNameFromTag(tag.cleaned)
		seg.ArgName = argName
		if slot := e.slotByName[argName]; slot != nil {
			if slot.override != nil {
				p := slot.override.Source
				seg.ArgValueSource = &p
			} else if slot.winner != nil {
				p := slot.winner.path
				seg.ArgValueSource = &p
			}
		}

		eff, known := effByName[argName]
		adoptedArg, adoptedKnown := argByName[argName]
		switch {
		case unresolved != nil && argName == unresolved.Name:
			seg.Status = StatusUnresolved
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, unresolved.Reason)
			if unresolved.Secret != nil {
				seg.SecretRef = unresolved.Secret
				out.secretFields[fieldPath] = true
				out.secretArgs[argName] = true
			}
		case !known || eff.Value == nil:
			// Unknown tag or a nil value the production resolver would reject.
			seg.Status = StatusUnresolved
			out.explanation.Status = StatusUnresolved
			if !adoptedKnown || tag.cleaned != "args."+argName {
				out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons,
					fmt.Sprintf("failed to resolve %s", seg.RawTag))
			} else {
				out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons,
					fmt.Sprintf("argument %q was not supplied", argName))
			}
			if ref := secretRefOfArgument(adoptedArg, e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets); ref != nil {
				seg.SecretRef = ref
				out.secretFields[fieldPath] = true
				out.secretArgs[argName] = true
			}
		default:
			replacement := quoteArgValue(*eff.Value)
			seg.OutputByteRange = [2]int{outputPos, outputPos + len(replacement)}
			seg.OutputRuneRange = [2]int{
				utf8.RuneCountInString(b.String()) + 0,
				utf8.RuneCountInString(b.String()) + utf8.RuneCountInString(replacement),
			}
			b.WriteString(replacement)
			outputPos += len(replacement)
			if ref := secretRefOfArgument(adoptedArg, e.graph.namespace, e.graph.sharedSecretNamespace, e.graph.secrets); ref != nil && ref.Supplied {
				seg.SecretRef = ref
				out.secretFields[fieldPath] = true
				out.secretArgs[argName] = true
			}
		}
		if seg.Status == StatusUnresolved {
			seg.OutputByteRange = [2]int{-1, -1}
			seg.OutputRuneRange = [2]int{-1, -1}
		}
		out.explanation.Segments = append(out.explanation.Segments, seg)
		prev = tag.end
	}
	b.WriteString(string(marshaled[prev:]))

	// When every fragment resolved, the constructed output must be byte
	// identical to the production template and metric resolution.
	if out.explanation.Status == StatusResolved {
		realStr, realErr := templateutil.ResolveQuotedArgs(string(marshaled), effective)
		if realErr != nil {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, realErr.Error())
			return out
		}
		if realStr != b.String() {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons,
				fmt.Sprintf("internal drift: substituted template differs from ResolveQuotedArgs for metric %q", src.metric.Name))
			return out
		}
		var resolved v1alpha1.Metric
		if err := json.Unmarshal([]byte(realStr), &resolved); err != nil {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, err.Error())
			return out
		}
		realMetric, realErr := analysisutil.ResolveMetricArgs(src.metric, effective)
		if realErr != nil {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, realErr.Error())
			return out
		}
		if !reflect.DeepEqual(realMetric, &resolved) {
			out.explanation.Status = StatusUnresolved
			out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons,
				fmt.Sprintf("internal drift: unmarshaled metric differs from ResolveMetricArgs for metric %q", src.metric.Name))
			return out
		}
		out.resolved = &resolved
		if len(out.secretFields) > 0 {
			// Re-resolve with secret values replaced by an opaque marker so the
			// reported metric keeps its literal structure (e.g. "Bearer <marker>")
			// without ever embedding secret data.
			redactedArgs := make([]v1alpha1.Argument, len(effective))
			copy(redactedArgs, effective)
			for i := range redactedArgs {
				if out.secretArgs[redactedArgs[i].Name] {
					marker := redactionMarker
					redactedArgs[i].Value = &marker
				}
			}
			redactedMetric, redactErr := analysisutil.ResolveMetricArgs(src.metric, redactedArgs)
			if redactErr != nil {
				out.explanation.Status = StatusUnresolved
				out.explanation.UnresolvedReasons = append(out.explanation.UnresolvedReasons, redactErr.Error())
				out.explanation.Resolved = nil
				return out
			}
			out.explanation.Resolved = redactedMetric
			out.explanation.RedactedFields = sortedKeys(out.secretFields)
		} else {
			out.explanation.Resolved = &resolved
		}
	}
	return out
}

// argNameFromTag extracts the argument name from an "args.<name>" tag. Unknown
// tag shapes keep their raw cleaned text so diagnostics stay truthful.
func argNameFromTag(cleaned string) string {
	const prefix = "args."
	if strings.HasPrefix(cleaned, prefix) {
		return cleaned[len(prefix):]
	}
	return cleaned
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
