package kx

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const SeedBytes = 32
const SecretKeyBytes = 32
const PublicKeyBytes = 32
const SessionKeyBytes = 32
const scalarMultBytes = 32

var invalidSeed = errors.New("invalid seed")
var cryptoError = errors.New("crypto error")
var notImplemented = errors.New("not implemented")

type KeyPair struct {
	pk []byte
	sk []byte
}

func NewKeyPair() (*KeyPair, error) {
	var err error
	seed := make([]byte, SeedBytes)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return newKeyPairFromSeed(seed)
}

func newKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	var err error
	kp := new(KeyPair)

	hash, _ := blake2b.New(SecretKeyBytes, nil)
	hash.Write(seed)
	kp.sk = hash.Sum(nil)

	if len(kp.sk) != SecretKeyBytes {
		return nil, cryptoError
	}

	kp.pk, err = curve25519.X25519(kp.sk, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	if len(kp.pk) != PublicKeyBytes {
		return nil, cryptoError
	}
	return kp, nil
}

func (pair *KeyPair) ClientSessionKeys(server_pk []byte) (rx []byte, tx []byte, err error) {
	q, err := curve25519.X25519(pair.sk, server_pk)
	if err != nil {
		return nil, nil, err
	}

	h, err := blake2b.New(2*SessionKeyBytes, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, b := range [][]byte{q, pair.pk, server_pk} {
		if _, err = h.Write(b); err != nil {
			return nil, nil, err
		}
	}

	keys := h.Sum(nil)

	return keys[:SessionKeyBytes], keys[SecretKeyBytes:], nil

}

func (pair *KeyPair) ServerSessionKeys(client_pk []byte) (rx []byte, tx []byte, err error) {

	q, err := curve25519.X25519(pair.sk, client_pk)
	if err != nil {
		return nil, nil, err
	}

	h, err := blake2b.New(2*SessionKeyBytes, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, b := range [][]byte{q, client_pk, pair.pk} {
		if _, err = h.Write(b); err != nil {
			return nil, nil, err
		}
	}

	keys := h.Sum(nil)

	return keys[SessionKeyBytes:], keys[:SecretKeyBytes], nil
}
