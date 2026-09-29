package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// ParseKey reads an App's private key from PEM: PKCS #1, the form GitHub hands out, or
// PKCS #8. The error never contains the key.
func ParseKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key is neither PKCS #1 nor PKCS #8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA key")
	}
	return rk, nil
}

// maxKeyFile is the most of a key file that is read: an RSA key in PEM is a few
// kilobytes.
const maxKeyFile = 64 << 10

// ReadKeyFile reads an App's private key from a file that only its owner may read. It
// opens the file once, never through a symbolic link and without waiting on a pipe, and
// reads what it opened: a file that is not a regular one, that grants group or others
// any permission, that belongs to another user than the one the program runs as, or
// that is larger than a key is refused, before it is read.
func ReadKeyFile(path string) (*rsa.PrivateKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("the private key file %s is a symbolic link; use the path of the file itself", path)
	}
	if err != nil {
		return nil, fmt.Errorf("the private key file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("the private key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the private key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the private key file %s is %s: others may read it; make it 0600", path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("the private key file %s belongs to another user than the one qory-github runs as", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("the private key file: %w", err)
	}
	if len(b) > maxKeyFile {
		return nil, fmt.Errorf("the private key file %s is larger than a key", path)
	}
	return ParseKey(b)
}

// jwtLeeway is how far back a token's issue time is set, for a clock behind GitHub's,
// and jwtLife how long it is valid: GitHub takes ten minutes at most.
const (
	jwtLeeway = 60 * time.Second
	jwtLife   = 9 * time.Minute
)

// AppJWT is the JSON Web Token an App authenticates to GitHub's API with, signed with
// RS256: issued a minute before now, valid for nine minutes after it, issued by the App,
// its numeric id or its client id.
func AppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-jwtLeeway).Unix(),
		"exp": now.Add(jwtLife).Unix(),
		"iss": appID,
	})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("signing the App's token: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// existsError is a key file that exists; it matches [fs.ErrExist].
type existsError string

// Error is the file that exists and what to do about it.
func (e existsError) Error() string {
	return "the key file " + string(e) + " exists; choose another or move it away"
}

// Is matches [fs.ErrExist].
func (e existsError) Is(target error) bool { return target == fs.ErrExist }

// writeKeyFile writes a private key where only its owner reads it, and never over a file
// that exists.
func writeKeyFile(path string, pemBytes []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return existsError(path)
		}
		return fmt.Errorf("the key file: %w", err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("the key file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("the key file: %w", err)
	}
	return nil
}
