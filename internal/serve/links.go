package serve

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/store"
)

// The store's namespaces serve keeps the adapter's state in.
//
//   - installations: an installation of the App that is linked to Qory Apiary, by its
//     id, with the connection it is linked to and whether that connection is made, see
//     [link]. Only a linked installation's deliveries are handled.
//   - collections: a collection, a repository, that Qory Apiary linked to a workspace,
//     by its ref in lower case, set from the change feed. Only a linked collection's
//     items and comments are sent.
//   - repositories: the installation that reaches a repository, by its ref in lower
//     case, with the ref as GitHub writes it, set by each listing of an installation's
//     repositories. The installation's link names the connection the repository's
//     collection belongs to.
//   - adapter: the instance id, the change feed's cursor and the sync interval.
//   - connections_forbidden: when Qory Apiary first answered 403 connection_unknown to
//     a request for a live connection since its last 2xx, by the connection's id, see
//     [noteAnswer].
//   - connections_replaced: a pending link a connect for another connection replaced,
//     by the replaced connection's id, until its last listing, see [keepReplaced].
//   - installations_deleted: an installation GitHub deleted, by its id, for
//     [deletedFor], see [keepDeleted].
//   - connections_passes: the expiry of the newest pass a linked connect return was
//     minted under, by the connection's id, see [keepPass].
//   - pulls: when the last pull of a collection that finished without error began, and
//     when its last listing of open issues began, by its ref in lower case, see
//     [pullMark].
const (
	nsInstallations = "installations"
	nsCollections   = "collections"
	nsRepositories  = "repositories"
	nsAdapter       = "adapter"
	nsPulls         = "pulls"
	nsForbidden     = "connections_forbidden"
	nsReplaced      = "connections_replaced"
	nsPasses        = "connections_passes"
	nsDeleted       = "installations_deleted"

	keyInstanceID   = "instance_id"
	keyCursor       = "cursor"
	keySyncInterval = "sync_interval"
)

// The states of an installation's link: pending from the linked connect return, and live
// once Qory Apiary answers a listing that names the connection with a signed 204, which
// it does once the connection is made.
const (
	linkPending = "pending"
	linkLive    = "live"
)

// link is what the store keeps of a linked installation: the connection in Qory Apiary,
// ac_ and 16 characters; the link's state, [linkPending] or [linkLive]; and when the
// connect pass the link was made under expires, in Unix seconds, or 0 when no pass
// made it. Qory Apiary issues a connection's passes in order, so the pass that expires
// later is the newer, see [Connect.link]. Return is when the linked connect return
// minted for the link expires, in Unix seconds, or 0 when none was: a link pending past
// it and [returnSkew] more is listed once more, and a 403 drops it, see
// [Adapter.listConnection].
type link struct {
	Connection string `json:"connection_id"`
	State      string `json:"state"`
	Pass       int64  `json:"pass_expires_at,omitempty"`
	Return     int64  `json:"return_expires_at,omitempty"`
}

// connectionShape is a connection's id, the contract's pattern.
var connectionShape = regexp.MustCompile(`^ac_[0-9a-hjkmnp-tv-z]{16}$`)

// installMu orders the changes of the installations' links, each of which reads a link
// before it writes it. It is held for the store's reads and writes alone, never across
// a request: a listing and the link it decides on take the installation's lock, see
// [Adapter.lockInstallation].
var installMu sync.Mutex

// Link links the installation to the connection, in state, so its deliveries are
// handled.
func Link(st *store.Store, installation int64, connection, state string) error {
	return putLink(st, installation, link{Connection: connection, State: state})
}

// putLink keeps the installation's link l.
func putLink(st *store.Store, installation int64, l link) error {
	if installation <= 0 {
		return errors.New("an installation's id is positive")
	}
	if !connectionShape.MatchString(l.Connection) || (l.State != linkPending && l.State != linkLive) || l.Pass < 0 || l.Return < 0 {
		return errors.New("a link names a connection and is pending or live")
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return st.Put(nsInstallations, strconv.FormatInt(installation, 10), b, 0)
}

// Unlink marks the installation not linked, so its deliveries are done unhandled.
func Unlink(st *store.Store, installation int64) error {
	return st.Delete(nsInstallations, strconv.FormatInt(installation, 10))
}

// Linked is whether the installation is linked to Qory Apiary, pending or live.
func Linked(st *store.Store, installation int64) (bool, error) {
	_, ok, err := linkOf(st, installation)
	return ok, err
}

// linkOf is the installation's link, or false when it has none.
func linkOf(st *store.Store, installation int64) (link, bool, error) {
	if installation <= 0 {
		return link{}, false, nil
	}
	b, err := st.Get(nsInstallations, strconv.FormatInt(installation, 10))
	if errors.Is(err, store.ErrNotFound) {
		return link{}, false, nil
	}
	if err != nil {
		return link{}, false, err
	}
	var l link
	if json.Unmarshal(b, &l) != nil || !connectionShape.MatchString(l.Connection) || (l.State != linkPending && l.State != linkLive) || l.Pass < 0 || l.Return < 0 {
		return link{}, false, errors.New("the store's entry for an installation is not one")
	}
	return l, true, nil
}

// goLive marks the installation's link live when it is pending and names connection, as
// Qory Apiary's signed 204 to a listing that names connection says. A link that names
// another connection stays as it is.
func goLive(st *store.Store, installation int64, connection string) error {
	installMu.Lock()
	defer installMu.Unlock()
	l, ok, err := linkOf(st, installation)
	if err != nil || !ok || l.Connection != connection || l.State == linkLive {
		return err
	}
	l.State = linkLive
	return putLink(st, installation, l)
}

// linkedTo are the installations whose links name connection.
func linkedTo(st *store.Store, connection string) ([]int64, error) {
	var installations []int64
	err := st.Each(nsInstallations, func(key string, v []byte) error {
		var l link
		if json.Unmarshal(v, &l) == nil && l.Connection == connection {
			if id, err := strconv.ParseInt(key, 10, 64); err == nil && id > 0 {
				installations = append(installations, id)
			}
		}
		return nil
	})
	return installations, err
}

// connectionOf is the connection of the collection ref: that of the link of the
// installation that reaches it, or "" when the store knows none.
func connectionOf(st *store.Store, ref string) (string, error) {
	installation, ok, err := reachOf(st, ref)
	if err != nil || !ok {
		return "", err
	}
	l, ok, err := linkOf(st, installation)
	if err != nil || !ok {
		return "", err
	}
	return l.Connection, nil
}

// dropConnection drops what the store keeps of the connection, which ended: the link of
// each installation linked to it, and the records of the collections that installation
// reaches, see [dropInstallation]. A link to another connection stays, so an answer
// about a connection that a new connect has replaced since drops nothing. It says
// whether it dropped a link.
func dropConnection(st *store.Store, connection string) (bool, error) {
	installations, err := linkedTo(st, connection)
	if err != nil {
		return false, err
	}
	if err := forgetForbidden(st, connection); err != nil {
		return false, err
	}
	if err := forgetReplaced(st, connection); err != nil {
		return false, err
	}
	dropped := false
	for _, id := range installations {
		installMu.Lock()
		l, ok, err := linkOf(st, id)
		if err == nil && ok && l.Connection == connection {
			err = dropInstallation(st, id)
			dropped = true
		}
		installMu.Unlock()
		if err != nil {
			return dropped, err
		}
	}
	return dropped, nil
}

// forbiddenFor is how long Qory Apiary answers 403 connection_unknown, and no 2xx, to
// the requests for a live connection before serve takes the connection as ended: Qory
// Apiary answers so once it no longer holds a connection, as after its organisation is
// removed, not connection_ended, and such a 403 may also be passing. A day matches how
// long serve lets other failures last before it says so, see [outageFor]. The first 403
// is kept in the store, so a restart does not start the day again.
const forbiddenFor = 24 * time.Hour

// forbiddenMu orders the reads and writes of nsForbidden.
var forbiddenMu sync.Mutex

// lasting is whether a 403 with the refusal code code counts toward a 403 that lasts:
// connection_unknown alone does.
func lasting(code string) bool { return code == codeConnectionUnknown }

// noteAnswer notes Qory Apiary's signed answer, status and refusal code, at at, to a
// request for connection, and says whether the connection is to be taken as ended, as
// on 409 connection_ended: a 2xx forgets the connection's first 403; a 403 that
// [lasting] counts, for a connection an installation is linked to live, is kept as the
// first, unless one is kept already, and then ends the connection once [forbiddenFor]
// has passed since it. A pending link is never ended by 403s: Qory Apiary answers its
// listings 403 until the browser brings the connect return.
func noteAnswer(st *store.Store, connection string, status int, code string, at time.Time) (bool, error) {
	forbiddenMu.Lock()
	defer forbiddenMu.Unlock()
	if status >= 200 && status < 300 {
		return false, forgetForbidden(st, connection)
	}
	if status != http.StatusForbidden || !lasting(code) {
		return false, nil
	}
	live, err := connectionLive(st, connection)
	if err != nil || !live {
		return false, err
	}
	b, err := st.Get(nsForbidden, connection)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	since, perr := strconv.ParseInt(string(b), 10, 64)
	if err != nil || perr != nil || since <= 0 {
		return false, st.Put(nsForbidden, connection, []byte(strconv.FormatInt(at.Unix(), 10)), 0)
	}
	return !at.Before(time.Unix(since, 0).Add(forbiddenFor)), nil
}

// forgetForbidden forgets the connection's first 403.
func forgetForbidden(st *store.Store, connection string) error {
	if ok, err := present(st.Get(nsForbidden, connection)); err != nil || !ok {
		return err
	}
	return st.Delete(nsForbidden, connection)
}

// connectionLive is whether an installation is linked to connection, live.
func connectionLive(st *store.Store, connection string) (bool, error) {
	installations, err := linkedTo(st, connection)
	if err != nil {
		return false, err
	}
	for _, id := range installations {
		if l, ok, err := linkOf(st, id); err != nil || (ok && l.Connection == connection && l.State == linkLive) {
			return err == nil, err
		}
	}
	return false, nil
}

// replaced is what the store keeps of a pending link a connect for another connection
// replaced: the installation it linked, and when the connect return minted for it
// expires, in Unix seconds. Until its last listing, past that and [returnSkew] more,
// each listing of its connection is complete and names no collection, and a 204 to one
// ends the connection, see [Adapter.listReplaced].
type replaced struct {
	Installation int64 `json:"installation"`
	Return       int64 `json:"return_expires_at"`
}

// keepReplaced keeps that the installation's pending link l was replaced.
func keepReplaced(st *store.Store, installation int64, l link) error {
	b, err := json.Marshal(replaced{Installation: installation, Return: l.Return})
	if err != nil {
		return err
	}
	return st.Put(nsReplaced, l.Connection, b, 0)
}

// replacedOf is what the store keeps of the replaced connection, or false.
func replacedOf(st *store.Store, connection string) (replaced, bool, error) {
	b, err := st.Get(nsReplaced, connection)
	if errors.Is(err, store.ErrNotFound) {
		return replaced{}, false, nil
	}
	if err != nil {
		return replaced{}, false, err
	}
	var r replaced
	if json.Unmarshal(b, &r) != nil || r.Installation <= 0 || r.Return < 0 {
		return replaced{}, false, errors.New("the store's entry for a replaced connection is not one")
	}
	return r, true, nil
}

// forgetReplaced forgets the replaced connection.
func forgetReplaced(st *store.Store, connection string) error {
	if ok, err := present(st.Get(nsReplaced, connection)); err != nil || !ok {
		return err
	}
	return st.Delete(nsReplaced, connection)
}

// keepPass keeps pass, a pass's expiry in Unix seconds, as the newest a linked connect
// return was minted under for connection, in place of an older one. It is kept until
// that expiry, [sessionFor] and [returnFor] more: a pass that expired before it was
// accepted before then, and its session has ended by then, so no older pass reaches a
// link afterwards; the return's lifetime is a margin. A connection's end leaves it.
// The caller holds installMu, as for the link it writes.
func keepPass(st *store.Store, connection string, pass int64, now time.Time) error {
	newest, err := newestPass(st, connection)
	if err != nil {
		return err
	}
	pass = max(pass, newest)
	ttl := max(time.Unix(pass, 0).Add(sessionFor+returnFor).Sub(now), time.Second)
	return st.Put(nsPasses, connection, []byte(strconv.FormatInt(pass, 10)), ttl)
}

// newestPass is the expiry of the newest pass a linked connect return was minted under
// for connection, see [keepPass], or 0.
func newestPass(st *store.Store, connection string) (int64, error) {
	b, err := st.Get(nsPasses, connection)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	pass, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil || pass <= 0 {
		return 0, errors.New("the store's entry for a connection's newest pass is not one")
	}
	return pass, nil
}

// deletedFor is how long the store keeps that GitHub deleted an installation, see
// [keepDeleted]: a day, far past any connect under way when it was deleted.
const deletedFor = 24 * time.Hour

// keepDeleted keeps, for [deletedFor], that GitHub deleted the installation, so a
// connect that confirmed it before the deletion links nothing after it, see
// [Connect.link].
func keepDeleted(st *store.Store, installation int64) error {
	return st.Put(nsDeleted, strconv.FormatInt(installation, 10), []byte("1"), deletedFor)
}

// wasDeleted is whether GitHub deleted the installation, see [keepDeleted].
func wasDeleted(st *store.Store, installation int64) (bool, error) {
	return present(st.Get(nsDeleted, strconv.FormatInt(installation, 10)))
}

// dropInstallation drops what the store keeps of the installation: the records of the
// collections it reaches, which are its repositories, whether they are linked and their
// pulls, and then its link.
func dropInstallation(st *store.Store, installation int64) error {
	refs, err := reachedBy(st, installation)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		for _, ns := range []string{nsRepositories, nsPulls} {
			if err := st.Delete(ns, collectionKey(ref)); err != nil {
				return err
			}
		}
		if err := unlinkCollection(st, ref); err != nil {
			return err
		}
	}
	return Unlink(st, installation)
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
	linkedAt  sync.Map // linkMark -> uint64
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
