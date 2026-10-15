package serve

import (
	"errors"

	"github.com/qoryai/qory-github"
)

// Permanent marks err as one asking again would not change, such as Qory Apiary's
// refusal of a request or a take in of an issue that is gone: the [Worker] marks the
// delivery failed at once, without another attempt, and the change feed's reader moves
// past the entry. Each is logged. nil stays nil.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// permanentError is an error [Permanent] marked.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// IsPermanent is whether err, or an error it wraps, is one asking again would not
// change: one [Permanent] marked, or a take in's that wraps [github.ErrIssueGone],
// [github.ErrUnreachable] or [github.ErrInvalidChange].
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p) || errors.Is(err, github.ErrIssueGone) || errors.Is(err, github.ErrUnreachable) || errors.Is(err, github.ErrInvalidChange)
}

// Held marks err as one that passes only once something outside serve changes, such
// as Qory Apiary's 401 to an access key that waits for its approval: the [Worker] tries
// the delivery again after a wait that doubles to a minute, for as long as it takes,
// and never fails it for it, so no delivery is lost meanwhile. nil stays nil.
func Held(err error) error {
	if err == nil {
		return nil
	}
	return &heldError{err: err}
}

// heldError is an error [Held] marked.
type heldError struct{ err error }

func (e *heldError) Error() string { return e.err.Error() }
func (e *heldError) Unwrap() error { return e.err }

// IsHeld is whether err, or an error it wraps, is one [Held] marked.
func IsHeld(err error) bool {
	var h *heldError
	return errors.As(err, &h)
}
