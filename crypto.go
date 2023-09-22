// Package crypto provides utilities for working with cryptographic operations
// such as key generation, signing, and verification.
package rutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// KeyPair represents a client with a private key, public key, and address.
type KeyPair struct {
	privateKey *PrivateKey
	publicKey  *PublicKey
	Address    string
}

// PrivateKey represents a cryptographic private key.
type PrivateKey struct {
	key *ecdsa.PrivateKey
}

// PublicKey represents a cryptographic public key.
type PublicKey struct {
	key *ecdsa.PublicKey
}

// SignToString signs a message and returns the base64-encoded signature as a string.
func (pk *PrivateKey) EncodeSignature(msg string) (string, error) {
	sig, err := pk.Sign(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// NewPrivateKey generates a new cryptographic private key.
func NewPrivateKey() (*PrivateKey, error) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: privKey}, nil
}

// String returns the hexadecimal representation of the private key with "0x" prefix.
func (pk *PrivateKey) String() string {
	return "0x" + hex.EncodeToString(crypto.FromECDSA(pk.key))
}

// String returns the hexadecimal representation of the public key with "0x" prefix.
func (pub *PublicKey) String() string {
	return "0x" + hex.EncodeToString(crypto.CompressPubkey(pub.key))
}

// PublicKey returns the corresponding public key.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{key: &pk.key.PublicKey}
}

// Address returns the Ethereum-style address derived from the public key.
func (pub *PublicKey) Address() string {
	addressBytes := crypto.PubkeyToAddress(*pub.key).Bytes()
	return "0x" + hex.EncodeToString(addressBytes)
}

// Verify verifies a message signature using the public key.
func (pub *PublicKey) VerifySignature(msg string, signature []byte) bool {
	hashedMsg := HashString(msg)

	// Convert the public key to a byte slice
	pubKeyBytes := elliptic.Marshal(crypto.S256(), pub.key.X, pub.key.Y)

	valid := crypto.VerifySignature(pubKeyBytes, hashedMsg, signature)
	return valid
}

// RecoverPublicKeyFromSignature recovers a public key from a message signature.
func RecoverPublicKeyFromSignature(message string, signature string) (*PublicKey, error) {
	sigBytes, err := DecodeSignature(signature)
	if err != nil {
		return nil, err
	}
	hashedMsg := HashString(message)
	pubKey, err := crypto.SigToPub(hashedMsg, sigBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: pubKey}, nil
}

// NewKeyPair creates a new KeyPair with a generated private key.
func NewKeyPair() *KeyPair {
	privateKey, err := NewPrivateKey()
	if err != nil {
		log.Fatal(err)
		return nil
	}
	publicKey := privateKey.PublicKey()
	return &KeyPair{
		privateKey: privateKey,
		publicKey:  publicKey,
		Address:    publicKey.Address(),
	}
}

// KeyPairFromPK creates a new KeyPair from a private key string.
func KeyPairFromPK(key string) *KeyPair {
	privateKey, err := DecodePrivateKey(key)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	publicKey := privateKey.PublicKey()
	return &KeyPair{
		privateKey: privateKey,
		publicKey:  publicKey,
		Address:    publicKey.Address(),
	}
}

// hashString computes the SHA-256 hash of the input string and returns the result as a byte slice.
func HashString(data string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashedMessage := hasher.Sum(nil)
	return hashedMessage
}

// Sign signs a message using the private key and returns the signature as a byte slice.
func (pk *PrivateKey) Sign(msg string) ([]byte, error) {
	hashedMsg := HashString(msg)
	signature, err := crypto.Sign(hashedMsg, pk.key)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Sign signs a transaction using the client's private key and returns the signature as a string.
func (skc *KeyPair) Sign(tx string) string {
	sig, err := skc.privateKey.EncodeSignature(tx)
	if err != nil {
		log.Fatal(err)
		return "nil"
	}
	return sig
}

// StringToSignature decodes a hexadecimal encoded signature string into a byte slice.
func DecodeSignature(encodedSig string) ([]byte, error) {
	return hex.DecodeString(encodedSig)
}

// NewPublicKeyFromStr creates a new PublicKey instance from a hexadecimal encoded string.
func DecodePublicKey(encoded string) (*PublicKey, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil {
		return nil, err
	}
	var pubKey ecdsa.PublicKey
	pubKey.X, pubKey.Y = new(big.Int).SetBytes(data[:32]), new(big.Int).SetBytes(data[32:])
	return &PublicKey{key: &pubKey}, nil
}

// NewPrivateKeyFromStr creates a new PrivateKey instance from a hexadecimal encoded string.
func DecodePrivateKey(encoded string) (*PrivateKey, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil {
		return nil, err
	}
	privKey, err := crypto.ToECDSA(data)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: privKey}, nil
}
