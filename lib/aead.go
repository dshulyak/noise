package noise

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewCipher(key [32]byte) (Cipher, error) {
	cipher, err := chacha20poly1305.New(key[:])
	return Cipher{cipher}, err
}

type Cipher struct {
	cipher.AEAD
}

func (c Cipher) Encrypt(nonce uint64, data, plain []byte, cipher []byte) ([]byte, error) {
	n12 := c.getNonce(nonce)
	return c.Seal(cipher, n12[:], plain, data), nil
}

func (c Cipher) Decrypt(nonce uint64, data, cipher []byte, plain []byte) ([]byte, error) {
	n12 := c.getNonce(nonce)
	return c.Open(plain, n12[:], cipher, data)
}

func (c Cipher) getNonce(nonce uint64) (rst [12]byte) {
	binary.LittleEndian.PutUint64(rst[4:], nonce)
	return
}

func (c Cipher) String() string {
	return "ChaChaPoly"
}
