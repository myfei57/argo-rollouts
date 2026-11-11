package explain

import "fmt"

// Reason codes returned by explain errors and report verification.
const (
	ReasonNotFound        = "TemplateNotFound"
	ReasonCycle           = "ReferenceCycle"
	ReasonLimitExceeded   = "LimitExceeded"
	ReasonInvalidInput    = "InvalidInput"
	ReasonDigestMismatch  = "DigestMismatch"
	ReasonMissingObject   = "MissingObject"
	ReasonVersionConflict = "VersionConflict"
	ReasonMarkerInvalid   = "CompletionMarkerInvalid"
	ReasonDiverged        = "ConstructionDiverged"
)

// ExplainError is a typed error carrying a stable reason and, for cycles and
// limit breaches, the bounded diagnostic context.
type ExplainError struct {
	Reason  string
	Message string
	// Cycle is populated for ReasonCycle.
	Cycle *CycleDiagnostic
	// Limit is populated for ReasonLimitExceeded.
	Limit *Limits
}

func (e *ExplainError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

func newNotFoundError(scope Scope, namespace, name string) error {
	return &ExplainError{
		Reason:  ReasonNotFound,
		Message: fmt.Sprintf("%s template %q not found in the supplied snapshot set (namespace=%q)", scope, name, namespace),
	}
}

func newCycleError(c CycleDiagnostic) error {
	return &ExplainError{
		Reason: ReasonCycle,
		Message: fmt.Sprintf("reference cycle detected re-entering %s template %q",
			c.BackTo.Scope, c.BackTo.Name),
		Cycle: &c,
	}
}

func newLimitError(what string, got, max int) error {
	l := DefaultLimits()
	return &ExplainError{
		Reason:  ReasonLimitExceeded,
		Message: fmt.Sprintf("%s limit exceeded: got %d, max %d; refusing to return a partial candidate", what, got, max),
		Limit:   &l,
	}
}

// VerificationError explains why an imported report could not be trusted.
type VerificationError struct {
	Reason  string
	Message string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}
