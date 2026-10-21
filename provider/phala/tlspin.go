package phala

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// ErrTLSPinMismatch is returned when the server's TLS key is not one the
// attestation bound. The request body is never sent in that case.
var ErrTLSPinMismatch = errors.New("tls spki does not match the attested pin")

var errRedirect = errors.New("redirects are not followed")

// SPKIHash is the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIHash(rawSPKI []byte) string {
	sum := sha256.Sum256(rawSPKI)
	return hex.EncodeToString(sum[:])
}

// peerPinned reports whether the leaf certificate's SPKI is one of pins.
func peerPinned(cs *tls.ConnectionState, pins []string) bool {
	return cs != nil && len(cs.PeerCertificates) > 0 &&
		slices.Contains(pins, SPKIHash(cs.PeerCertificates[0].RawSubjectPublicKeyInfo))
}

// checkTransport rejects base transports that would bypass the TLS checks:
// custom TLS dialers skip VerifyConnection, and InsecureSkipVerify drops
// certificate validation.
func checkTransport(t *http.Transport) error {
	if t.DialTLS != nil || t.DialTLSContext != nil {
		return errors.New("phala: transports with a custom TLS dialer are not supported")
	}
	if t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return errors.New("phala: InsecureSkipVerify is not allowed")
	}
	return nil
}

// pinnedTransport keeps normal certificate validation and additionally
// requires the leaf SPKI to be one of pins before any request bytes are
// written. An existing VerifyConnection still runs first.
func pinnedTransport(base *http.Transport, pins []string) *http.Transport {
	t := base.Clone()
	cfg := &tls.Config{}
	if t.TLSClientConfig != nil {
		cfg = t.TLSClientConfig.Clone()
	}
	prev := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		if !peerPinned(&cs, pins) {
			return fmt.Errorf("%w for %s", ErrTLSPinMismatch, cs.ServerName)
		}
		return nil
	}
	t.TLSClientConfig = cfg
	return t
}

// newClient never follows redirects: a redirect could lead away from the
// attested host.
func newClient(t http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     t,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}
