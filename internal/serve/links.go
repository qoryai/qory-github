package serve

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
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
//     [link]. Only the deliveries of a linked installation whose grant Qory Apiary's
//     copy holds are handled, see [granted].
//   - grants: Qory Apiary's copy of the adapter's grants, the connection of each by its
//     grant_ref, an installation's id, see [nsGrants].
//   - collections: a collection, a repository, that Qory Apiary linked to a workspace,
//     by its ref, the repository's id, set from the change feed. Only a linked
//     collection's items and comments are sent.
//   - repositories: the installation that reaches a repository, by its ref, the
//     repository's id, with the ref and the started_at of the newest listing of that
//     installation's repositories that named it, set by a listing of an installation's
//     repositories that named it, unless a listing of another installation that started
//     later named it, see [claimReach]. The installation's link names the connection
//     the repository's collection belongs to.
//   - adapter: the instance id, the change feed's cursor, the sync interval, and,
//     with the enrolment kept in the state directory, the id of the adapter in Qory
//     Apiary the state belongs to, see [ownState].
//   - connections_forbidden: when Qory Apiary first answered 403 connection_unknown to
//     a request that names a live connection since its last 2xx to one, by the
//     connection's id, see [noteAnswer].
//   - connections_replaced: a pending link a connect for another connection replaced,
//     by the replaced connection's id, until its last listing, see [keepReplaced].
//   - installations_deleted: an installation GitHub deleted, by its id, with the GitHub
//     account of its link, for [deletedFor], see [keepDeleted].
//   - connections_passes: the expiry of the newest pass a linked connect return was
//     minted under, by the connection's id, see [keepPass].
//   - pulls: when the last pull of a collection that finished without error began, and
//     when its last listing of open issues began, by its ref, see [pullMark].
//   - environments: the environment_ref serve last sent for a collection, by its ref,
//     kept once Qory Apiary took the listing's part that names the collection, none for
//     a collection sent with none, see [keepEnvironment].
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
	nsEnvironments  = "environments"

	keyInstanceID   = "instance_id"
	keyCursor       = "cursor"
	keySyncInterval = "sync_interval"
)

// The states of an installation's link: pending from the linked connect return, and live
// once Qory Apiary answers a listing that names the connection with a signed 204, which
// it does once the connection is made. A connection may end while it is pending, and a
// 409 connection_ended to any listing drops the link.
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
// [Adapter.listConnection]. Account is the id of the GitHub account the installation is
// on, as the connect that made the link read it, or 0 when none did: a connect for that
// account stops the installation's grant end, see [Adapter.stopEnd].
type link struct {
	Connection string `json:"connection_id"`
	State      string `json:"state"`
	Pass       int64  `json:"pass_expires_at,omitempty"`
	Return     int64  `json:"return_expires_at,omitempty"`
	Account    int64  `json:"account_id,omitempty"`
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
	if !connectionShape.MatchString(l.Connection) || (l.State != linkPending && l.State != linkLive) || l.Pass < 0 || l.Return < 0 || l.Account < 0 {
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
	if json.Unmarshal(b, &l) != nil || !connectionShape.MatchString(l.Connection) || (l.State != linkPending && l.State != linkLive) || l.Pass < 0 || l.Return < 0 || l.Account < 0 {
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
// reaches, see [dropInstallation], and each grant of the connection in Qory Apiary's
// copy, see [nsGrants], since a connection that ended has no grant. A link or a grant
// of another connection stays, so an answer about a connection that a new connect has
// replaced since drops nothing of the new one. It says whether it dropped a link.
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
	return dropped, dropGrantsOf(st, connection)
}

// dropGrantsOf drops each grant of connection from the copy, holding installMu.
func dropGrantsOf(st *store.Store, connection string) error {
	installMu.Lock()
	defer installMu.Unlock()
	var keys []string
	err := st.Each(nsGrants, func(key string, v []byte) error {
		var g grantEntry
		if json.Unmarshal(v, &g) == nil && g.Connection == connection {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := st.Delete(nsGrants, key); err != nil {
			return err
		}
	}
	return nil
}

// forbiddenFor is how long Qory Apiary answers 403 connection_unknown, and no 2xx, to
// the requests that name a live connection, its listings and its disconnects, before
// serve takes the connection as ended: Qory Apiary answers so once it no longer holds a
// connection, as after its organisation is removed, not connection_ended, and such a
// 403 may also be passing. A day matches how long serve lets other failures last before
// it says so, see [outageFor]. The first 403 is kept in the store, so a restart does
// not start the day again.
const forbiddenFor = 24 * time.Hour

// forbiddenMu orders the reads and writes of nsForbidden.
var forbiddenMu sync.Mutex

// lasting is whether a 403 with the refusal code code counts toward a 403 that lasts:
// connection_unknown alone does.
func lasting(code string) bool { return code == codeConnectionUnknown }

// noteAnswer notes Qory Apiary's signed answer, status and refusal code, at at, to a
// request that names connection, and says whether the connection is to be taken as
// ended, as on 409 connection_ended: a 2xx, or a 409 connection_suspended, which Qory
// Apiary answers only for a connection it holds, forgets the connection's first 403; a
// 403 that [lasting] counts, for a connection an installation is linked to live, is kept
// as the first, unless one is kept already, and then ends the connection once
// [forbiddenFor] has passed since it. A pending link is never ended by 403s: Qory
// Apiary answers its listings 403 until the browser brings the connect return.
func noteAnswer(st *store.Store, connection string, status int, code string, at time.Time) (bool, error) {
	forbiddenMu.Lock()
	defer forbiddenMu.Unlock()
	// A 2xx, or a 409 connection_suspended, says Qory Apiary holds the connection.
	if (status >= 200 && status < 300) || (status == http.StatusConflict && code == codeConnectionSuspended) {
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

// deletedRecord is what the store keeps of an installation GitHub deleted: the GitHub
// account of its link, by its id, 0 when serve did not know it.
type deletedRecord struct {
	Account int64 `json:"account_id,omitempty"`
}

// keepDeleted keeps, for [deletedFor], that GitHub deleted the installation, so a
// connect that confirmed it before the deletion links nothing after it, see
// [Connect.link], with account, the GitHub account of its link, so a connect for that
// account stops the end of its grant, see [Adapter.endUnlinked]. An account of 0 keeps
// the account the record has.
func keepDeleted(st *store.Store, installation, account int64) error {
	if account <= 0 {
		account = deletedAccount(st, installation)
	}
	b, err := json.Marshal(deletedRecord{Account: account})
	if err != nil {
		return err
	}
	return st.Put(nsDeleted, strconv.FormatInt(installation, 10), b, deletedFor)
}

// deletedAccount is the GitHub account that the record of [keepDeleted] has for the
// installation, by its id, or 0.
func deletedAccount(st *store.Store, installation int64) int64 {
	b, err := st.Get(nsDeleted, strconv.FormatInt(installation, 10))
	if err != nil {
		return 0
	}
	var r deletedRecord
	if json.Unmarshal(b, &r) != nil || r.Account < 0 {
		return 0
	}
	return r.Account
}

// wasDeleted is whether GitHub deleted the installation, see [keepDeleted].
func wasDeleted(st *store.Store, installation int64) (bool, error) {
	return present(st.Get(nsDeleted, strconv.FormatInt(installation, 10)))
}

// dropInstallation drops what the store keeps of the installation: the records of the
// collections it reaches, which are its repositories, whether they are linked, their
// pulls and the environment_refs sent for them, and then its link. A repository's
// record that a listing of another installation claimed meanwhile stays, see
// [dropReach].
func dropInstallation(st *store.Store, installation int64) error {
	refs, err := reachedBy(st, installation)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if err := dropReach(st, ref, installation); err != nil {
			return err
		}
		for _, ns := range repositoryRecords {
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

// collectionKey is a collection's key: its ref, the repository's id in decimal, which
// GitHub never gives another repository and which has one spelling. The factory is in
// use nowhere yet, so no record keyed by a repository's owner/name is carried over.
func collectionKey(ref string) string { return ref }

// The moments of the links this process stores. A request for a collection's items
// that Qory Apiary answers 409 collection_not_linked may have begun before the change
// feed unlinked the collection and linked it again; its answer then speaks of the
// unlink, and the link stored after it stands. So each link stored takes the next
// moment from linkClock, kept in linkedAt by store and collection, and a request notes
// the moment it began, [linkMoment]: [unlinkSince] unlinks only when no link was stored
// after. A link from before the process started has no moment, and is older than any
// request of the process. linkMu orders a link and an unlink of one store.
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
// that began at the moment began says, or as serve's drop of the repository's records
// that began then does, unless a link was stored after that moment, and says whether it
// did.
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

// reach is what the store keeps of a repository: the installation that reaches it, its
// ref, the repository's id, and Read, the started_at, in Unix seconds, of the newest
// listing of that installation's repositories that named it, or 0 when none is known,
// see [claimReach].
type reach struct {
	Installation int64  `json:"installation"`
	Ref          string `json:"ref"`
	Read         int64  `json:"read_at,omitempty"`
}

// reachMu orders the changes of the repositories' records, each of which reads a record
// before it writes or deletes it. It is held for the store's reads and writes alone, and
// no other lock is taken while it is held.
var reachMu sync.Mutex

// claimReach keeps that installation reaches the repository ref, as a listing of the
// installation's repositories that started at read and named it says. GitHub allows one
// installation of the App on an account, and a repository is one account's, so two
// installations reach a repository at once only around a transfer, when the listing of
// one of them is stale: the listing that started later wins, whatever order its parts
// arrive in, and of two that started in the same second the one claimed last wins. So
// a record the store holds for another installation is replaced when read, in whole
// seconds, is no earlier than the start of the newest listing that named the
// repository for that installation; a record whose listing started later stays. For
// the same installation the later of the two moments is kept, so a part of an older
// listing of the installation, sent late, never moves it back. A record the store does
// not hold, or cannot read, is written. A read of the zero time, as for a started_at
// that does not parse, counts as 0, which never replaces another installation's
// record, not even one whose moment is 0 too.
func claimReach(st *store.Store, ref string, installation int64, read time.Time) error {
	at := max(read.Unix(), 0)
	reachMu.Lock()
	defer reachMu.Unlock()
	b, err := st.Get(nsRepositories, collectionKey(ref))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	var old reach
	if err == nil && json.Unmarshal(b, &old) == nil && old.Installation > 0 {
		switch {
		case old.Installation == installation:
			at = max(at, old.Read)
		case at == 0 || at < old.Read:
			return nil
		}
	}
	b, err = json.Marshal(reach{Installation: installation, Ref: ref, Read: at})
	if err != nil {
		return err
	}
	return st.Put(nsRepositories, collectionKey(ref), b, 0)
}

// dropReach forgets which installation reaches the repository ref while the store's
// record names installation: a record a listing of another installation claimed since,
// see [claimReach], stays. A record the store cannot read is forgotten.
func dropReach(st *store.Store, ref string, installation int64) error {
	reachMu.Lock()
	defer reachMu.Unlock()
	b, err := st.Get(nsRepositories, collectionKey(ref))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var r reach
	if json.Unmarshal(b, &r) == nil && r.Installation > 0 && r.Installation != installation {
		return nil
	}
	return st.Delete(nsRepositories, collectionKey(ref))
}

// repositoryRecords are the namespaces that keep a record of a repository by its
// collection's key, which a drop of the repository's records drops besides which
// installation reaches it, see [dropReach]: its pulls and the environment_ref sent for
// it. Whether its collection is linked is dropped apart, see [unlinkCollection] and
// [unlinkSince].
var repositoryRecords = []string{nsPulls, nsEnvironments}

// keepEnvironment keeps env as the environment_ref serve last sent for the collection
// ref, once Qory Apiary took the listing's part that names it; none drops what was kept.
func keepEnvironment(st *store.Store, ref, env string) error {
	if env == "" {
		return st.Delete(nsEnvironments, collectionKey(ref))
	}
	return st.Put(nsEnvironments, collectionKey(ref), []byte(env), 0)
}

// sentEnvironment is the environment_ref serve last sent for the collection ref, see
// [keepEnvironment], or "" when it sent none or keeps none.
func sentEnvironment(st *store.Store, ref string) (string, error) {
	b, err := st.Get(nsEnvironments, collectionKey(ref))
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(b), err
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
