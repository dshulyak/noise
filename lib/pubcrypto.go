package noise

import (
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
