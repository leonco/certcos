package cert

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/leonco/certcos/cos"
	cryptopkg "github.com/leonco/certcos/crypto"
)

// RenewalThreshold is how many days before expiry we renew (default 30).
const RenewalThreshold = 30 * 24 * time.Hour

// certResourceMeta is the JSON we store for renewal (CertURL, CertStableURL, Domains).
type certResourceMeta struct {
	Domain        string   `json:"domain"`
	CertURL       string   `json:"certUrl"`
	CertStableURL string   `json:"certStableUrl"`
	Domains       []string `json:"domains,omitempty"` // all SANs for this cert, used when falling back to obtain
}

// Manager handles obtain/renew and COS persistence.
type Manager struct {
	store  *cos.Store
	encKey []byte
	client *lego.Client
}

// NewManager creates a cert manager.
func NewManager(store *cos.Store, encKey []byte, client *lego.Client) *Manager {
	return &Manager{store: store, encKey: encKey, client: client}
}

// EnsureCertificate ensures a valid certificate covering all domains (one cert, multiple SANs).
// Storage uses the first domain as the path key. Returns whether the cert was obtained/renewed.
func (m *Manager) EnsureCertificate(ctx context.Context, domains []string) (bool, error) {
	if len(domains) == 0 {
		return false, errors.New("at least one domain required")
	}
	storageKey := domains[0]

	certPem, err := m.store.Get(ctx, cos.CertPath(storageKey))
	if err != nil {
		return false, fmt.Errorf("get cert: %w", err)
	}
	keyEnc, err := m.store.Get(ctx, cos.CertKeyPath(storageKey))
	if err != nil {
		return false, fmt.Errorf("get key: %w", err)
	}

	// No cert or no key: obtain new (one cert for all domains)
	if len(certPem) == 0 || len(keyEnc) == 0 {
		res, err := m.obtain(ctx, domains)
		if err != nil {
			return false, err
		}
		if err := m.saveCert(ctx, storageKey, res); err != nil {
			return false, err
		}
		return true, nil
	}

	// Parse cert to check expiry
	block, _ := pem.Decode(certPem)
	if block == nil {
		return false, errors.New("invalid cert PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse cert: %w", err)
	}
	if time.Until(parsed.NotAfter) > RenewalThreshold {
		return false, nil // already valid
	}

	// Renew
	res, err := m.renew(ctx, storageKey, certPem, keyEnc)
	if err != nil {
		return false, err
	}
	if err := m.saveCert(ctx, storageKey, res); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) obtain(ctx context.Context, domains []string) (*certificate.Resource, error) {
	storageKey := domains[0]
	var privKeyPEM []byte
	keyEnc, err := m.store.Get(ctx, cos.CertKeyPath(storageKey))
	if err == nil && len(keyEnc) > 0 {
		privKeyPEM, err = cryptopkg.Decrypt(m.encKey, keyEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt existing key: %w", err)
		}
	}
	var key crypto.PrivateKey
	if len(privKeyPEM) > 0 {
		block, _ := pem.Decode(privKeyPEM)
		if block != nil {
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			}
			if err != nil {
				return nil, fmt.Errorf("parse existing key: %w", err)
			}
		}
	}
	req := certificate.ObtainRequest{
		Domains:    domains,
		Bundle:     true,
		PrivateKey: key,
	}
	res, err := m.client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m *Manager) renew(ctx context.Context, domain string, certPem, keyEnc []byte) (*certificate.Resource, error) {
	keyPem, err := cryptopkg.Decrypt(m.encKey, keyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key: %w", err)
	}
	meta, err := m.loadResourceMeta(ctx, domain)
	if err != nil || meta.CertURL == "" {
		// No meta: treat as obtain
		domains := meta.Domains
		if len(domains) == 0 {
			domains = []string{domain}
		}
		return m.obtain(ctx, domains)
	}
	res := &certificate.Resource{
		Domain:           domain,
		CertURL:          meta.CertURL,
		CertStableURL:    meta.CertStableURL,
		PrivateKey:       keyPem,
		Certificate:      certPem,
		IssuerCertificate: m.getIssuerBytes(ctx, domain),
	}
	newRes, err := m.client.Certificate.RenewWithOptions(*res, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return nil, err
	}
	return newRes, nil
}

func (m *Manager) loadResourceMeta(ctx context.Context, domain string) (certResourceMeta, error) {
	var meta certResourceMeta
	data, err := m.store.Get(ctx, cos.CertResourcePath(domain))
	if err != nil || len(data) == 0 {
		return meta, err
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func (m *Manager) getIssuerBytes(ctx context.Context, domain string) []byte {
	b, _ := m.store.Get(ctx, cos.CertIssuerPath(domain))
	return b
}

func (m *Manager) saveCert(ctx context.Context, domain string, res *certificate.Resource) error {
	if err := m.store.Put(ctx, cos.CertPath(domain), res.Certificate); err != nil {
		return fmt.Errorf("put cert: %w", err)
	}
	if len(res.IssuerCertificate) > 0 {
		if err := m.store.Put(ctx, cos.CertIssuerPath(domain), res.IssuerCertificate); err != nil {
			return fmt.Errorf("put issuer: %w", err)
		}
	}
	enc, err := cryptopkg.Encrypt(m.encKey, res.PrivateKey)
	if err != nil {
		return err
	}
	if err := m.store.Put(ctx, cos.CertKeyPath(domain), enc); err != nil {
		return fmt.Errorf("put key: %w", err)
	}
	domainsFromCert := domainsFromCertificate(res.Certificate)
	if len(domainsFromCert) == 0 {
		domainsFromCert = []string{res.Domain}
	}
	meta := certResourceMeta{
		Domain:        res.Domain,
		CertURL:       res.CertURL,
		CertStableURL: res.CertStableURL,
		Domains:       domainsFromCert,
	}
	metaData, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return m.store.Put(ctx, cos.CertResourcePath(domain), metaData)
}

// domainsFromCertificate parses the first certificate in pemBytes and returns DNSNames (and CN if not in DNSNames).
func domainsFromCertificate(pemBytes []byte) []string {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	names := make(map[string]struct{})
	for _, n := range c.DNSNames {
		names[n] = struct{}{}
	}
	if c.Subject.CommonName != "" {
		names[c.Subject.CommonName] = struct{}{}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	return out
}
