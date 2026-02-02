package account

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
	"github.com/leonco/certcos/cos"
	cryptopkg "github.com/leonco/certcos/crypto"
)

// User implements registration.User and persists account key + registration to COS.
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// LoadOrCreateUser loads existing user from COS or creates a new account and saves to COS.
// encKey is the 32-byte AES key for decrypting/encrypting private key.
func LoadOrCreateUser(ctx context.Context, store *cos.Store, email string, encKey []byte) (*User, error) {
	keyPath := cos.AccountKeyPath(email)
	regPath := cos.AccountRegPath(email)

	enc, err := store.Get(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("get account key: %w", err)
	}
	if len(enc) > 0 {
		// Existing account: decrypt key and load registration
		pemBytes, err := cryptopkg.Decrypt(encKey, enc)
		if err != nil {
			return nil, fmt.Errorf("decrypt account key: %w", err)
		}
		key, err := parsePrivateKeyPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse account key: %w", err)
		}
		regData, err := store.Get(ctx, regPath)
		if err != nil {
			return nil, fmt.Errorf("get registration: %w", err)
		}
		if len(regData) == 0 {
			return nil, errors.New("registration.json missing for existing account")
		}
		var reg registration.Resource
		if err := json.Unmarshal(regData, &reg); err != nil {
			return nil, fmt.Errorf("parse registration: %w", err)
		}
		return &User{Email: email, Registration: &reg, key: key}, nil
	}

	// New account: generate key (ECDSA P-256 as in lego)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u := &User{Email: email, key: key}
	// Caller will Register and set u.Registration, then call SaveUser
	return u, nil
}

// SaveUser persists account private key (encrypted) and registration JSON to COS.
func SaveUser(ctx context.Context, store *cos.Store, u *User, encKey []byte) error {
	if u.Registration == nil {
		return errors.New("registration is nil, register first")
	}
	pemBytes, err := marshalPrivateKeyPEM(u.key)
	if err != nil {
		return err
	}
	enc, err := cryptopkg.Encrypt(encKey, pemBytes)
	if err != nil {
		return err
	}
	if err := store.Put(ctx, cos.AccountKeyPath(u.Email), enc); err != nil {
		return fmt.Errorf("put account key: %w", err)
	}
	regData, err := json.Marshal(u.Registration)
	if err != nil {
		return err
	}
	if err := store.Put(ctx, cos.AccountRegPath(u.Email), regData); err != nil {
		return fmt.Errorf("put registration: %w", err)
	}
	return nil
}

func parsePrivateKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func marshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	default:
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
}
