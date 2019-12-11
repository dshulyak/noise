package noise

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

func GenerateKey(rng io.Reader) (priv [32]byte, pub [32]byte) {
	if rng == nil {
		rng = rand.Reader
	}
	rng.Read(priv[:])
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub
}

func DH(priv, pub [32]byte) (rst [32]byte) {
	curve25519.ScalarMult(&rst, &priv, &pub)
	return rst
}

func GenerateSignagure(pkey, message, buf []byte) []byte {
	return append(buf, ed25519.Sign(ed25519.PrivateKey(pkey), message)...)
}

func VerifySignature(pubkey, message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pubkey), message, sig)
}
