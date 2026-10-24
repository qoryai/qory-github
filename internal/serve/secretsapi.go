package serve

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
)

// routeSecrets is where serve stores its secrets in Qory Apiary, POST, and reads them
// back, GET: contracts' adapter-secrets.schema.json and adapter-secrets-answer.schema.json.
const routeSecrets = "/v1/adapter/secrets"

// codeUnknownServerKey is Qory Apiary's refusal, 400, of an upload sealed to a server
// key it does not hold.
const codeUnknownServerKey = "unknown_server_key"

// maxSecretsAnswer is the most bytes of an answer to GET /v1/adapter/secrets that serve
// reads: 16 secrets of 16384 bytes each, sealed and in base64url, fit in it.
const maxSecretsAnswer = 1 << 20

// secretNameShape is a secret's name, contracts' definitions.schema.json secret_name.
var secretNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// sealSuite is the suite of a sealed value, [contracts.SealSuite]: RFC 9180 base mode
// with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
func sealSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// sealToServer seals pt to the server key server of Qory Apiary, as
// adapter-secrets.schema.json says: to the key's X25519 form, which
// [accesskey.PublicKey.X25519] returns, with a fresh ephemeral key, info
// [contracts.SecretsUploadInfo] of the key as the pin writes it, and aad
// [contracts.SecretsAAD] of the adapter id and the access key id that signs the
// request. An error never contains pt.
func sealToServer(pt []byte, server accesskey.PublicKey, adapterID, keyID string) (contracts.SealedToServer, error) {
	u, err := server.X25519()
	if err != nil {
		return contracts.SealedToServer{}, err
	}
	kem, kdf, aead := sealSuite()
	pub, err := kem.NewPublicKey(u)
	if err != nil {
		return contracts.SealedToServer{}, err
	}
	enc, s, err := hpke.NewSender(pub, kdf, aead, contracts.SecretsUploadInfo(server.String()))
	if err != nil {
		return contracts.SealedToServer{}, err
	}
	ct, err := s.Seal(contracts.SecretsAAD(adapterID, keyID), pt)
	if err != nil {
		return contracts.SealedToServer{}, err
	}
	return contracts.SealedToServer{
		Suite: contracts.SealSuite, ServerKey: server.String(),
		Enc: base64.RawURLEncoding.EncodeToString(enc), CT: base64.RawURLEncoding.EncodeToString(ct),
	}, nil
}

// openSealed opens a value sealed to the access key key, whose id is keyID, as
// adapter-secrets-answer.schema.json says: info [contracts.SecretsInfo] of keyID and
// aad [contracts.SecretsAAD] of adapterID and keyID, both built from serve's
// enrolment, never from the answer. enc and ct are strict base64url without padding.
func openSealed(enc, ct string, key *accesskey.Key, adapterID, keyID string) ([]byte, error) {
	encBytes, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || len(encBytes) != 32 {
		return nil, errors.New("its enc is not 32 bytes in base64url")
	}
	ctBytes, err := base64.RawURLEncoding.Strict().DecodeString(ct)
	if err != nil || len(ctBytes) < 16 {
		return nil, errors.New("its ct is not a ciphertext and a tag in base64url")
	}
	kem, kdf, aead := sealSuite()
	scalar := key.X25519PrivateKey()
	defer clear(scalar)
	priv, err := kem.NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(encBytes, priv, kdf, aead, contracts.SecretsInfo(keyID))
	if err != nil {
		return nil, errors.New("its seal does not open with this adapter's access key")
	}
	pt, err := r.Open(contracts.SecretsAAD(adapterID, keyID), ctBytes)
	if err != nil {
		return nil, errors.New("its seal does not open with this adapter's access key")
	}
	return pt, nil
}

// current is the enrolment a request is signed with and its answer checked under:
// serve's, see [Apiary.creds], or else KeyID, Key, Pin and AdapterID.
func (a *Apiary) current() enrolment {
	if a.creds != nil {
		return a.creds.get()
	}
	return enrolment{keyID: a.KeyID, key: a.Key, pin: a.Pin, adapterID: a.AdapterID}
}

// UploadSecrets sends POST /v1/adapter/secrets: the secrets p, which replace every
// secret Qory Apiary stores for the adapter, sealed to a server key of the pin, see
// [sealToServer]. As adapter-secrets.schema.json:5 says, each upload is sealed first to
// the pinned key that verified the latest signed answer serve received before it,
// since Qory Apiary holds that key's private half, see [sealOrder]. Only a signed 400
// unknown_server_key, Qory Apiary's answer to a seal to a key it does not hold, makes
// serve seal the upload again, anew, to the next pinned key it has not tried for this
// upload; once every key is tried, the upload fails. No other refusal changes the key,
// 400 invalid_request among them. One enrolment signs every request and is in every
// seal's aad. An error never contains a value.
func (a *Apiary) UploadSecrets(ctx context.Context, p contracts.AdapterSecretsPlaintext) error {
	const what = "storing the GitHub App in Qory Apiary"
	if err := p.Check(); err != nil {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return Permanent(fmt.Errorf("%s: the secrets could not be written as JSON", what))
	}
	defer clear(pt)
	e := a.current()
	keys := sealOrder(e.pin.Keys(), a)
	if len(keys) == 0 {
		return Permanent(fmt.Errorf("%s: the pin lists no key to seal the secrets to", what))
	}
	for _, server := range keys {
		sealed, err := sealToServer(pt, server, e.adapterID, e.keyID)
		if err != nil {
			return Permanent(fmt.Errorf("%s: sealing the secrets to the server key %s failed", what, server.String()))
		}
		err = a.postWith(ctx, &e, what, routeSecrets, "", "", func(t string) any {
			return contracts.AdapterSecrets{Version: contracts.Version, Time: t, Sealed: sealed}
		})
		if !refusedAs(err, http.StatusBadRequest, codeUnknownServerKey) || server == keys[len(keys)-1] {
			return err
		}
	}
	return nil
}

// sealOrder is keys with the key that verified Qory Apiary's latest signed answer
// first, when keys contain it, and the others in the pin's order, as
// adapter-secrets.schema.json:5 orders them.
func sealOrder(keys []accesskey.PublicKey, a *Apiary) []accesskey.PublicKey {
	signer, ok := a.lastSigner()
	i := slices.Index(keys, signer)
	if !ok || i <= 0 {
		return keys
	}
	return append([]accesskey.PublicKey{signer}, slices.Delete(slices.Clone(keys), i, i+1)...)
}

// Secrets reads the secrets Qory Apiary stores for the adapter, GET
// /v1/adapter/secrets, and opens them. The answer is used only once its signature
// under the pin, bound to this request's, is checked, see [Apiary.judge], and then its
// version, its revision, its suite and that it is sealed to the access key that signed
// the request, see [openSecrets]. A 429 is waited out as a POST's is. The secrets are
// none before the App setup.
func (a *Apiary) Secrets(ctx context.Context) (contracts.AdapterSecretsPlaintext, error) {
	const what = "reading the GitHub App from Qory Apiary"
	for try := 1; ; try++ {
		e := a.current()
		ans, err := a.sendWith(ctx, e, what, http.MethodGet, routeSecrets, nil, maxSecretsAnswer, postTimeout)
		if err == nil {
			err = a.judge(what, ans, "", "")
		}
		if wait, ok := retryWait(err); ok && try < rateLimitedTries {
			if err := a.sleep(ctx, wait); err != nil {
				return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("%s: %w", what, err)
			}
			continue
		}
		if err != nil {
			return contracts.AdapterSecretsPlaintext{}, err
		}
		p, err := openSecrets(ans.body, e)
		if err != nil {
			return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("%s: %w", what, err)
		}
		return p, nil
	}
}

// openSecrets reads the answer body, whose signature is checked already, and opens its
// secrets with the enrolment e that signed the request. It refuses an answer that is
// not adapter-secrets-answer.schema.json, of version 1 and the contract's revision; one
// of another suite; one sealed to another access key than e's; one whose seal does not
// open; and a plaintext that is not adapter-secrets-plaintext.schema.json, see
// [contracts.AdapterSecretsPlaintext.Check]. An error never contains a value.
func openSecrets(body []byte, e enrolment) (contracts.AdapterSecretsPlaintext, error) {
	var doc struct {
		Version  *int `json:"version"`
		Revision *int `json:"revision"`
		Sealed   *struct {
			Suite       *string `json:"suite"`
			AccessKeyID *string `json:"access_key_id"`
			Enc         *string `json:"enc"`
			CT          *string `json:"ct"`
		} `json:"sealed"`
	}
	if !strictObject(body, &doc) || doc.Version == nil || doc.Revision == nil || doc.Sealed == nil || doc.Sealed.Suite == nil ||
		doc.Sealed.AccessKeyID == nil || doc.Sealed.Enc == nil || doc.Sealed.CT == nil {
		return contracts.AdapterSecretsPlaintext{}, errors.New("the answer is not the secrets' document")
	}
	s := doc.Sealed
	switch {
	case *doc.Version != contracts.Version:
		return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("the answer is not of version %d", contracts.Version)
	case *doc.Revision != contracts.Revision:
		return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("the answer is not of the contract's revision %d", contracts.Revision)
	case *s.Suite != contracts.SealSuite:
		return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("the answer is not sealed with the suite %s", contracts.SealSuite)
	case *s.AccessKeyID != e.keyID:
		return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("the answer is sealed to another access key than %s, which signed the request", e.keyID)
	}
	pt, err := openSealed(*s.Enc, *s.CT, e.key, e.adapterID, e.keyID)
	if err != nil {
		return contracts.AdapterSecretsPlaintext{}, fmt.Errorf("the answer is refused: %w", err)
	}
	defer clear(pt)
	var plain struct {
		Version *int `json:"version"`
		Secrets *[]struct {
			Name  *string `json:"name"`
			Value *string `json:"value"`
		} `json:"secrets"`
	}
	if !strictObject(pt, &plain) || plain.Version == nil || *plain.Version != contracts.Version || plain.Secrets == nil || len(*plain.Secrets) > contracts.SecretsMax {
		return contracts.AdapterSecretsPlaintext{}, errors.New("the opened secrets are not the plaintext's document")
	}
	p := contracts.AdapterSecretsPlaintext{Version: *plain.Version}
	for _, entry := range *plain.Secrets {
		if entry.Name == nil || entry.Value == nil || !secretNameShape.MatchString(*entry.Name) {
			return contracts.AdapterSecretsPlaintext{}, errors.New("the opened secrets are not the plaintext's document")
		}
		p.Secrets = append(p.Secrets, contracts.SecretEntry{Name: *entry.Name, Value: *entry.Value})
	}
	if err := p.Check(); err != nil {
		return contracts.AdapterSecretsPlaintext{}, err
	}
	return p, nil
}
