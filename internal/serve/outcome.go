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
// change: a take in's that wraps [github.ErrIssueGone], [github.ErrUnreachable] or
// [github.ErrInvalidChange] anywhere, as a take in's error joins one with GitHub's
// answer; or one [Permanent] marked. An error that joins several, as [errors.Join]
// does, is [Permanent] only when every error it joins is, so a listing's error joined
// with its last part's refusal is tried again when the listing's may pass.
func IsPermanent(err error) bool {
	if errors.Is(err, github.ErrIssueGone) || errors.Is(err, github.ErrUnreachable) || errors.Is(err, github.ErrInvalidChange) {
		return true
	}
	return marked(err)
}

// marked is whether err is one [Permanent] marked, every part of a joined one.
func marked(err error) bool {
	for err != nil {
		if _, ok := err.(*permanentError); ok {
			return true
		}
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			joined := u.Unwrap()
			for _, e := range joined {
				if !marked(e) {
					return false
				}
			}
			return len(joined) > 0
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		default:
			return false
		}
	}
	return false
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

// Outage marks err as Qory Apiary's outage: it could not be reached, its answer could
// not be read, or it answered, within the answer's bound, maxPostAnswer or
// maxChangesAnswer, a 5xx or an answer not signed under the pin. An answer larger than
// its bound is a plain error, not an outage. A deploy or a proxy in front of it answers
// a 5xx or an unsigned answer for a while, and under the contract Qory Apiary itself
// may answer a 413, 415 or 400 bad_request unsigned. The [Worker] tries such a
// delivery again for longer than another error, see [outageFor]. nil stays nil.
func Outage(err error) error {
	if err == nil {
		return nil
	}
	return &outageError{err: err}
}

// outageError is an error [Outage] marked.
type outageError struct{ err error }

func (e *outageError) Error() string { return e.err.Error() }
func (e *outageError) Unwrap() error { return e.err }

// IsOutage is whether err, or an error it wraps, is one [Outage] marked.
func IsOutage(err error) bool {
	var o *outageError
	return errors.As(err, &o)
}
