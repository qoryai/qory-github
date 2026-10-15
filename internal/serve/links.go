package serve

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/store"
)

// The store's namespaces serve keeps the adapter's state in.
//
//   - installations: an installation of the App that is linked to Qory Apiary, by its
//     id. Only a linked installation's deliveries are handled.
//   - collections: a collection, a repository, that Qory Apiary linked to a workspace,
//     by its ref in lower case, set from the change feed. Only a linked collection's
//     items and comments are sent.
//   - repositories: the installation that reaches a repository, by its ref in lower
//     case, with the ref as GitHub writes it, set by each listing of an installation's
//     repositories.
//   - adapter: the instance id, the change feed's cursor and the sync interval.
const (
	nsInstallations = "installations"
	nsCollections   = "collections"
	nsRepositories  = "repositories"
	nsAdapter       = "adapter"

	keyInstanceID   = "instance_id"
	keyCursor       = "cursor"
	keySyncInterval = "sync_interval"
)

// Link marks the installation linked to Qory Apiary, so its deliveries are handled.
func Link(st *store.Store, installation int64) error {
	if installation <= 0 {
		return errors.New("an installation's id is positive")
	}
	return st.Put(nsInstallations, strconv.FormatInt(installation, 10), []byte("linked"), 0)
}

// Unlink marks the installation not linked, so its deliveries are done unhandled.
func Unlink(st *store.Store, installation int64) error {
	return st.Delete(nsInstallations, strconv.FormatInt(installation, 10))
}

// Linked is whether the installation is linked to Qory Apiary.
func Linked(st *store.Store, installation int64) (bool, error) {
	if installation <= 0 {
		return false, nil
	}
	return present(st.Get(nsInstallations, strconv.FormatInt(installation, 10)))
}

// present is whether a value was found, or the store's error.
func present(_ []byte, err error) (bool, error) {
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// collectionKey is a collection's key: its ref in lower case, since GitHub's owners
// and names are the same in any case.
func collectionKey(ref string) string { return strings.ToLower(ref) }

// The moments of the links this process stores. A request to Qory Apiary that is
// answered 409 collection_not_linked may have begun before the change feed unlinked
// the collection and linked it again; its answer then speaks of the unlink, and the
// link stored after it stands. So each link stored takes the next moment from
// linkClock, kept in linkedAt by store and collection, and a request notes the moment
// it began, [linkMoment]: [unlinkSince] unlinks only when no link was stored after.
// A link from before the process started has no moment, and is older than any request
// of the process. linkMu orders a link and an unlink of one store.
var (
	linkClock atomic.Uint64
	linkedAt  sync.Map // linkMark → uint64
	linkMu    sync.Mutex
)

// linkMark is a collection of a store, the key of linkedAt.
type linkMark struct {
	st  *store.Store
	key string
}

// linkMoment is the moment now, which a request notes when it begins.
func linkMoment() uint64 { return linkClock.Load() }

// linkCollection marks the collection linked, as the change feed says.
func linkCollection(st *store.Store, ref string) error {
	linkMu.Lock()
	defer linkMu.Unlock()
	linkedAt.Store(linkMark{st, collectionKey(ref)}, linkClock.Add(1))
	return st.Put(nsCollections, collectionKey(ref), []byte("linked"), 0)
}

// unlinkCollection marks the collection not linked, as the change feed says.
func unlinkCollection(st *store.Store, ref string) error {
	linkMu.Lock()
	defer linkMu.Unlock()
	return st.Delete(nsCollections, collectionKey(ref))
}

// unlinkSince marks the collection not linked, as Qory Apiary's answer to a request
// that began at the moment began says, unless a link was stored after that moment, and
// says whether it did.
func unlinkSince(st *store.Store, ref string, began uint64) (bool, error) {
	linkMu.Lock()
	defer linkMu.Unlock()
	if at, ok := linkedAt.Load(linkMark{st, collectionKey(ref)}); ok && at.(uint64) > began {
		return false, nil
	}
	return true, st.Delete(nsCollections, collectionKey(ref))
}

// collectionLinked is whether the collection is linked.
func collectionLinked(st *store.Store, ref string) (bool, error) {
	return present(st.Get(nsCollections, collectionKey(ref)))
}

// reach is what the store keeps of a repository: the installation that reaches it, and
// its ref as GitHub writes it.
type reach struct {
	Installation int64  `json:"installation"`
	Ref          string `json:"ref"`
}

// setReach keeps that installation reaches the repository ref.
func setReach(st *store.Store, ref string, installation int64) error {
	b, err := json.Marshal(reach{Installation: installation, Ref: ref})
	if err != nil {
		return err
	}
	return st.Put(nsRepositories, collectionKey(ref), b, 0)
}

// reachOf is the installation that reaches the repository ref, or false when the store
// knows none.
func reachOf(st *store.Store, ref string) (int64, bool, error) {
	b, err := st.Get(nsRepositories, collectionKey(ref))
	if errors.Is(err, store.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var r reach
	if err := json.Unmarshal(b, &r); err != nil || r.Installation <= 0 {
		return 0, false, errors.New("the store's entry for a repository is not one")
	}
	return r.Installation, true, nil
}

// reachedBy are the refs of the repositories the store knows the installation reaches.
func reachedBy(st *store.Store, installation int64) ([]string, error) {
	var refs []string
	err := st.Each(nsRepositories, func(_ string, v []byte) error {
		var r reach
		if json.Unmarshal(v, &r) == nil && r.Installation == installation {
			refs = append(refs, r.Ref)
		}
		return nil
	})
	return refs, err
}

// instanceID is serve's instance id, made once and kept in the store.
func instanceID(st *store.Store) (string, error) {
	b, err := st.Get(nsAdapter, keyInstanceID)
	if err == nil && accesskey.CheckInstanceID(string(b)) == nil {
		return string(b), nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	id, err := accesskey.NewInstanceID()
	if err != nil {
		return "", err
	}
	return id, st.Put(nsAdapter, keyInstanceID, []byte(id), 0)
}
