package cos

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	cosapi "github.com/tencentyun/cos-go-sdk-v5"
)

// Store provides COS object read/write with path conventions for account and certs.
type Store struct {
	client *cosapi.Client
}

// Config holds COS connection parameters (from env).
type Config struct {
	Bucket    string // COS_BUCKET
	Region    string // COS_REGION
	AppID     string // COS_APPID
	SecretID  string
	SecretKey string
}

// NewStore creates a COS store. Bucket URL format: https://<bucket>-<appid>.cos.<region>.myqcloud.com
func NewStore(cfg Config) (*Store, error) {
	u, err := url.Parse(fmt.Sprintf("https://%s-%s.cos.%s.myqcloud.com", cfg.Bucket, cfg.AppID, cfg.Region))
	if err != nil {
		return nil, err
	}
	b := &cosapi.BaseURL{BucketURL: u}
	client := cosapi.NewClient(b, &http.Client{
		Timeout: 100 * time.Second,
		Transport: &cosapi.AuthorizationTransport{
			SecretID:  cfg.SecretID,
			SecretKey: cfg.SecretKey,
		},
	})
	return &Store{client: client}, nil
}

// SanitizeEmail returns a path-safe string for email (e.g. admin@example.com -> admin_example_com).
func SanitizeEmail(email string) string {
	return strings.ReplaceAll(strings.ReplaceAll(email, "@", "_"), ".", "_")
}

// SanitizeDomain returns a path-safe string for domain (e.g. example.com -> example_com).
func SanitizeDomain(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}

// Paths for account and certs.
func AccountKeyPath(email string) string   { return "account/" + SanitizeEmail(email) + "/private_key.enc" }
func AccountRegPath(email string) string  { return "account/" + SanitizeEmail(email) + "/registration.json" }
func CertPath(domain string) string       { return "certs/" + SanitizeDomain(domain) + "/cert.pem" }
func CertKeyPath(domain string) string    { return "certs/" + SanitizeDomain(domain) + "/key.enc" }
func CertIssuerPath(domain string) string { return "certs/" + SanitizeDomain(domain) + "/issuer.pem" }
func CertResourcePath(domain string) string { return "certs/" + SanitizeDomain(domain) + "/resource.json" }

// Get reads object at key. Returns nil, nil if object does not exist.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.client.Object.Get(ctx, key, nil)
	if err != nil {
		if cosapi.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	return readAll(resp.Body)
}

// Put writes data to key.
func (s *Store) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.client.Object.Put(ctx, key, bytes.NewReader(data), nil)
	return err
}

// Exists returns true if object exists.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.Object.Head(ctx, key, nil)
	if err != nil {
		if cosapi.IsNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r)
	return b.Bytes(), err
}
