package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

const (
	aesKeySize   = 32
	gcmNonceSize = 12
)

// KeyFromBase64 decodes a 32-byte AES-256 key from base64.
// Returns error if decoded length is not 32.
func KeyFromBase64(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(key) != aesKeySize {
		return nil, errors.New("encryption key must be 32 bytes after base64 decode")
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM. Output format: nonce(12) || ciphertext || tag(16).
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != aesKeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data produced by Encrypt (nonce || ciphertext || tag).
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != aesKeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	const gcmTagSize = 16
	if len(ciphertext) < gcmNonceSize+gcmTagSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:gcmNonceSize]
	payload := ciphertext[gcmNonceSize:]
	return aead.Open(nil, nonce, payload, nil)
}
