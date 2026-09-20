package proto

import (
	"errors"
	"fmt"
)

// ErrPayload is returned when a payload length violates an opcode's registered
// rule. Callers match it with errors.Is.
var ErrPayload = errors.New("proto: payload length violates the opcode's rule")

// PayloadRule is the payload-length contract of one opcode: what the Windows
// vendor driver was observed to send, expressed as a length range.
//
// Length is all that can be checked offline, and it is enough for the failure
// this exists to prevent. An 0xe4 with an empty payload wedged the embedded
// controller and killed the laptop's internal keyboard three times (Runs 1, 2
// and 4 in docs/protocol.md); the vendor's 0xe4 carrying its 8-byte argument is
// answered normally in all nine complete driver inits. The opcode was never the hazard.
// The missing argument was.
type PayloadRule struct {
	min, max int // max < 0 means no upper bound
	known    bool
}

// PayloadExactly requires a payload of exactly n bytes.
func PayloadExactly(n int) PayloadRule {
	return PayloadRule{min: n, max: n, known: true}
}

// PayloadAtLeast requires at least n bytes and sets no upper bound.
func PayloadAtLeast(n int) PayloadRule {
	return PayloadRule{min: n, max: -1, known: true}
}

// PayloadUnknown imposes no constraint. It is the honest value for an opcode
// the vendor driver has never been seen to send: a guessed rule would be worse
// than none, because it would read like evidence. Every use is pinned by
// TestPayloadRulesAreEvidenceBased, so the set can only change deliberately.
func PayloadUnknown() PayloadRule {
	return PayloadRule{known: false}
}

// Known reports whether the rule rests on an observation of the vendor driver.
func (r PayloadRule) Known() bool { return r.known }

// Check reports whether an n-byte payload satisfies the rule.
func (r PayloadRule) Check(n int) error {
	switch {
	case !r.known:
		return nil
	case n < r.min:
		return fmt.Errorf("%w: %d bytes, want %s", ErrPayload, n, r)
	case r.max >= 0 && n > r.max:
		return fmt.Errorf("%w: %d bytes, want %s", ErrPayload, n, r)
	default:
		return nil
	}
}

// String renders the rule for logs and dry runs.
func (r PayloadRule) String() string {
	switch {
	case !r.known:
		return "any length (the vendor driver has never been seen to send it)"
	case r.max < 0:
		return fmt.Sprintf("at least %d bytes", r.min)
	case r.min == r.max:
		return fmt.Sprintf("exactly %d bytes", r.min)
	default:
		return fmt.Sprintf("%d to %d bytes", r.min, r.max)
	}
}
