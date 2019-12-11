package noise

import (
	"crypto/hmac"
	"crypto/sha256"
)

func hmacHash(key []byte, material ...[]byte) (rst [32]byte) {
	mac := hmac.New(sha256.New, key)
	for _, single := range material {
		mac.Write(single)
	}
	_ = mac.Sum(rst[:0])
	return
}

func genHash(data ...[]byte) (rst [32]byte) {
	h := sha256.New()
	for _, item := range data {
		h.Write(item)
	}
	_ = h.Sum(rst[:0])
	return
}

func hkdf2(key [32]byte, material []byte) ([32]byte, [32]byte) {
	tmp := hmacHash(key[:], material)
	out1 := hmacHash(tmp[:], []byte{1})
	out2 := hmacHash(tmp[:], out1[:], []byte{2})
	return out1, out2
}

func hkdf3(key [32]byte, material []byte) ([32]byte, [32]byte, [32]byte) {
	tmp := hmacHash(key[:], material)
	out1 := hmacHash(tmp[:], []byte{1})
	out2 := hmacHash(tmp[:], out1[:], []byte{2})
	out3 := hmacHash(tmp[:], out2[:], []byte{3})
	return out1, out2, out3
}
