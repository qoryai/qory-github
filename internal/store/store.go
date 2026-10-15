// Package store is what qory-github serve keeps on its machine: one file in its state
// directory, a bbolt database, which only the user it runs as may read. It keeps the
// webhook deliveries GitHub sent, each until it is handled and then its GUID for
// [DeliveryRetention], so a delivery GitHub sends again is dropped; and values that
// other parts of serve keep under a namespace, each with an expiry or none.
//
// A [Store] is safe for concurrent use. Each change is written to disk before the call
// that makes it returns.
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/qoryai/qory-github/internal/ownerfile"
	bolt "go.etcd.io/bbolt"
)

// FileName is the store's file in the state directory.
const FileName = "qory-github.db"

// DeliveryRetention is how long a delivery is kept once it is handled, or has failed,
// counted from when it was received: its GUID is known for that long, so GitHub's
// redelivery of it in that time is dropped. A delivery that is still pending is never
// expired.
const DeliveryRetention = 7 * 24 * time.Hour

// ErrNotFound is what a lookup returns for a delivery or a value the store does not
// have, or no longer has because it expired.
var ErrNotFound = errors.New("not found")

// The top-level buckets. A delivery is kept as its record, under its sequence number in
// deliveries, its body under the same number in bodies until it is done, and its GUID in
// guids; pending lists the sequence numbers of those not yet handled. kv holds one
// bucket for each namespace of [Store.Put].
var (
	deliveriesBucket = []byte("deliveries")
	bodiesBucket     = []byte("bodies")
	pendingBucket    = []byte("pending")
	guidsBucket      = []byte("guids")
	kvBucket         = []byte("kv")
)

// errReplaced is the store's file when it is not the one [Open] checked.
var errReplaced = errors.New("the store's file is not the one checked")

// betweenOpens runs between the check of the store's file and bbolt's open of it; a
// test replaces the file there.
var betweenOpens = func(string) {}

// Store is the open store.
type Store struct {
	db  *bolt.DB
	now func() time.Time
}

// Options are how a store is opened.
type Options struct {
	// Now is the store's clock, when a delivery is received and when a value expires;
	// nil is time.Now.
	Now func() time.Time
}

// Open opens the store in dir, which it makes, 0700, when it does not exist and its
// parent does. dir and the store's file in it, created 0600, must be the user's that
// qory-github runs as and grant group and others no permission, as a private key file
// must. A store another process has open is refused after a second, not waited on.
func Open(dir string, opts Options) (*Store, error) {
	if err := ownerfile.Dir(dir, "the state directory"); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FileName)
	f, err := ownerfile.Open(path, os.O_RDWR|os.O_CREATE, 0o600, "the store")
	if err != nil {
		return nil, err
	}
	checked, err := f.Stat()
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("the store: %w", err)
	}
	// bbolt opens the path again. The file it opens, never through a link, must be the
	// one checked above, so a file put in its place between the two opens is refused.
	open := func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := os.OpenFile(name, flag|syscall.O_NOFOLLOW, perm)
		if errors.Is(err, syscall.ELOOP) {
			return nil, errReplaced
		}
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil || !os.SameFile(info, checked) {
			f.Close()
			return nil, errReplaced
		}
		return f, nil
	}
	betweenOpens(path)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, OpenFile: open})
	if errors.Is(err, errReplaced) {
		return nil, fmt.Errorf("the store %s was replaced while it was opened", path)
	}
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("the store %s is open in another process; one qory-github serve runs on a state directory", path)
	}
	if err != nil {
		return nil, fmt.Errorf("the store %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{deliveriesBucket, bodiesBucket, pendingBucket, guidsBucket, kvBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("the store %s: %w", path, err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}, nil
}

// Close closes the store. A call that is under way finishes first; one made after
// fails.
func (s *Store) Close() error { return s.db.Close() }

// State is where a delivery is in its handling.
type State string

// The states of a delivery: pending until it is handled, then done, or failed when its
// handler failed every attempt.
const (
	Pending State = "pending"
	Done    State = "done"
	Failed  State = "failed"
)

// Delivery is one webhook delivery GitHub sent, as the store keeps it.
type Delivery struct {
	// Seq is the store's number for it, in the order deliveries arrived.
	Seq uint64 `json:"seq"`
	// GUID is GitHub's id for the delivery, the header X-GitHub-Delivery.
	GUID string `json:"guid"`
	// Event is the event's name, the header X-GitHub-Event, such as issues.
	Event string `json:"event"`
	// Action is the payload's action, such as opened, or empty when it has none.
	Action string `json:"action,omitempty"`
	// InstallationID is the payload's installation.id, the App's installation the event
	// is for, or zero when it has none.
	InstallationID int64 `json:"installation_id,omitempty"`
	// Received is when the store took it.
	Received time.Time `json:"received"`
	// State is where it is in its handling.
	State State `json:"state"`
	// Body is the payload as GitHub sent it, which [Store.Load] returns alone, and only
	// until the delivery is done.
	Body []byte `json:"-"`
}

// AddDelivery keeps d as pending, its body among it, with the next sequence number
// and the store's time as when it was received, and returns it so. A delivery whose
// GUID the store knows is not kept: it returns the one kept before and false.
func (s *Store) AddDelivery(d Delivery) (Delivery, bool, error) {
	if d.GUID == "" || d.Event == "" {
		return Delivery{}, false, errors.New("a delivery has a GUID and an event")
	}
	added := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		guids := tx.Bucket(guidsBucket)
		if seq := guids.Get([]byte(d.GUID)); seq != nil {
			var err error
			d, err = record(tx, seq)
			return err
		}
		deliveries := tx.Bucket(deliveriesBucket)
		n, err := deliveries.NextSequence()
		if err != nil {
			return err
		}
		d.Seq, d.Received, d.State = n, s.now().UTC(), Pending
		key := seqKey(n)
		meta, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if err := deliveries.Put(key, meta); err != nil {
			return err
		}
		if err := tx.Bucket(bodiesBucket).Put(key, d.Body); err != nil {
			return err
		}
		if err := tx.Bucket(pendingBucket).Put(key, nil); err != nil {
			return err
		}
		added = true
		return guids.Put([]byte(d.GUID), key)
	})
	if err != nil {
		return Delivery{}, false, err
	}
	if !added {
		d.Body = nil
	}
	return d, added, nil
}

// Pending is every pending delivery, in the order they arrived, without their bodies.
func (s *Store) Pending() ([]Delivery, error) {
	var out []Delivery
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(pendingBucket).ForEach(func(seq, _ []byte) error {
			d, err := record(tx, seq)
			if err != nil {
				return err
			}
			out = append(out, d)
			return nil
		})
	})
	return out, err
}

// Load is the delivery numbered seq with its body, the body nil once it is done.
func (s *Store) Load(seq uint64) (Delivery, error) {
	var d Delivery
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		if d, err = record(tx, seqKey(seq)); err != nil {
			return err
		}
		if b := tx.Bucket(bodiesBucket).Get(seqKey(seq)); b != nil {
			d.Body = append([]byte(nil), b...)
		}
		return nil
	})
	return d, err
}

// Lookup is the delivery GitHub numbered guid, without its body.
func (s *Store) Lookup(guid string) (Delivery, error) {
	var d Delivery
	err := s.db.View(func(tx *bolt.Tx) error {
		seq := tx.Bucket(guidsBucket).Get([]byte(guid))
		if seq == nil {
			return ErrNotFound
		}
		var err error
		d, err = record(tx, seq)
		return err
	})
	return d, err
}

// MarkDone marks the delivery numbered seq done and drops its body.
func (s *Store) MarkDone(seq uint64) error { return s.settle(seq, Done) }

// MarkFailed marks the delivery numbered seq failed. Its body is kept until it expires.
func (s *Store) MarkFailed(seq uint64) error { return s.settle(seq, Failed) }

// settle takes the delivery numbered seq off the pending list in state.
func (s *Store) settle(seq uint64, state State) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := seqKey(seq)
		d, err := record(tx, key)
		if err != nil {
			return err
		}
		d.State = state
		meta, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if err := tx.Bucket(deliveriesBucket).Put(key, meta); err != nil {
			return err
		}
		if state == Done {
			if err := tx.Bucket(bodiesBucket).Delete(key); err != nil {
				return err
			}
		}
		return tx.Bucket(pendingBucket).Delete(key)
	})
}

// Sweep drops what has expired: each delivery that is done or failed and was received
// [DeliveryRetention] ago or longer, its GUID with it, and each value whose expiry has
// passed. It returns how many deliveries it dropped.
func (s *Store) Sweep() (int, error) {
	now := s.now()
	dropped := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		deliveries, bodies, guids := tx.Bucket(deliveriesBucket), tx.Bucket(bodiesBucket), tx.Bucket(guidsBucket)
		var expired []Delivery
		err := deliveries.ForEach(func(key, meta []byte) error {
			var d Delivery
			if err := json.Unmarshal(meta, &d); err != nil {
				return fmt.Errorf("the delivery %d: %w", binary.BigEndian.Uint64(key), err)
			}
			if d.State != Pending && !now.Before(d.Received.Add(DeliveryRetention)) {
				expired = append(expired, d)
			}
			return nil
		})
		if err != nil {
			return err
		}
		// A bucket is changed only once its walk is over.
		for _, d := range expired {
			key := seqKey(d.Seq)
			if err := deliveries.Delete(key); err != nil {
				return err
			}
			if err := bodies.Delete(key); err != nil {
				return err
			}
			if err := guids.Delete([]byte(d.GUID)); err != nil {
				return err
			}
		}
		dropped = len(expired)
		return tx.Bucket(kvBucket).ForEachBucket(func(name []byte) error {
			ns := tx.Bucket(kvBucket).Bucket(name)
			var gone [][]byte
			err := ns.ForEach(func(k, v []byte) error {
				if expiredAt(v, now) {
					gone = append(gone, append([]byte(nil), k...))
				}
				return nil
			})
			if err != nil {
				return err
			}
			for _, k := range gone {
				if err := ns.Delete(k); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return dropped, err
}

// Put keeps value under key in the namespace ns, in place of what was there, until ttl
// from now, or for good when ttl is zero. ns and key are not empty.
func (s *Store) Put(ns, key string, value []byte, ttl time.Duration) error {
	if ns == "" || key == "" {
		return errors.New("a value is kept under a namespace and a key, neither empty")
	}
	if ttl < 0 {
		return errors.New("a value's time to live is not negative")
	}
	v := make([]byte, 8, 8+len(value))
	if ttl > 0 {
		binary.BigEndian.PutUint64(v, uint64(s.now().Add(ttl).UnixNano()))
	}
	v = append(v, value...)
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.Bucket(kvBucket).CreateBucketIfNotExists([]byte(ns))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), v)
	})
}

// Get is the value under key in the namespace ns, or [ErrNotFound] when there is none
// or it expired.
func (s *Store) Get(ns, key string) ([]byte, error) {
	now := s.now()
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(kvBucket).Bucket([]byte(ns))
		if b == nil {
			return ErrNotFound
		}
		v := b.Get([]byte(key))
		if v == nil || expiredAt(v, now) {
			return ErrNotFound
		}
		out = append([]byte{}, v[8:]...)
		return nil
	})
	return out, err
}

// Delete drops the value under key in the namespace ns, if there is one.
func (s *Store) Delete(ns, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(kvBucket).Bucket([]byte(ns))
		if b == nil || key == "" {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// expiredAt is whether a value as [Store.Put] keeps it, its expiry first, has expired
// at now. An expiry of zero is none.
func expiredAt(v []byte, now time.Time) bool {
	if len(v) < 8 {
		return true
	}
	at := binary.BigEndian.Uint64(v[:8])
	return at != 0 && now.UnixNano() >= int64(at)
}

// record is the delivery kept under the sequence number seq, without its body.
func record(tx *bolt.Tx, seq []byte) (Delivery, error) {
	meta := tx.Bucket(deliveriesBucket).Get(seq)
	if meta == nil {
		return Delivery{}, ErrNotFound
	}
	var d Delivery
	if err := json.Unmarshal(meta, &d); err != nil {
		return Delivery{}, fmt.Errorf("the delivery %d: %w", binary.BigEndian.Uint64(seq), err)
	}
	return d, nil
}

// seqKey is a sequence number as a key, big-endian, so the keys sort as the numbers do.
func seqKey(n uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, n)
}
