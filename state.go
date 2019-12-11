package noise

import (
	"crypto/sha256"
	"errors"
)

const (
	Overhead   = 16 // it should be configurable
	RekeyNonce = ^uint64(0)
	MaxNonce   = RekeyNonce - 1
	MaxMsgSize = int(^uint16(0)) - Overhead
)

var (
	ErrNonceOverlow = errors.New("nonce overlow")
	ErrMsgTooBig    = errors.New("message too big")
)

type CipherState struct {
	key    [32]byte
	nonce  uint64
	cipher Cipher
}

func (state *CipherState) InitKey(key [32]byte) (err error) {
	state.key = key
	state.nonce = 0
	state.cipher, err = NewCipher(key)
	return err
}

func (state *CipherState) HasKey() bool {
	return state.key != [32]byte{}
}

func (state *CipherState) SetNonce(nonce uint64) {
	state.nonce = nonce
}

func (state *CipherState) Encrypt(data, plaintext, buf []byte) (rst []byte, err error) {
	if len(plaintext) > MaxMsgSize {
		return buf, ErrMsgTooBig
	}
	if state.nonce > MaxNonce {
		return buf, ErrNonceOverlow
	}
	if state.key == [32]byte{} {
		buf = append(buf, plaintext...)
		return buf, nil
	}
	rst, err = state.cipher.Encrypt(state.nonce, data, plaintext, buf)
	state.nonce++
	return rst, err
}

func (state *CipherState) Decrypt(adata, ciphertext, buf []byte) (rst []byte, err error) {
	if len(ciphertext) > MaxMsgSize {
		return buf, ErrMsgTooBig
	}
	if state.nonce > MaxNonce {
		return buf, ErrNonceOverlow
	}
	if state.key == [32]byte{} {
		buf = append(buf, ciphertext...)
		return buf, nil
	}
	rst, err = state.cipher.Decrypt(state.nonce, adata, ciphertext, buf)
	state.nonce++
	return rst, err
}

func (state *CipherState) Rekey() error {
	var (
		buf   = make([]byte, 48)
		err   error
		zeros = [32]byte{}
	)
	buf, err = state.cipher.Encrypt(RekeyNonce, nil, zeros[:], buf)
	if err != nil {
		return err
	}
	copy(state.key[:], buf)
	return nil
}

func (state *CipherState) Nonce() uint64 {
	return state.nonce
}

type SymmetricState struct {
	chainingKey, hash [32]byte
	cstate            CipherState
}

func (sym *SymmetricState) Initialize(protocol string) {
	if len(protocol) <= 32 {
		copy(sym.hash[:], protocol)
	} else {
		_ = sha256.Sum256(sym.hash[:])
	}
	sym.chainingKey = sym.hash
}

func (sym *SymmetricState) MixKey(keyMaterial []byte) {
	ck, tempk := hkdf2(sym.chainingKey, keyMaterial)
	sym.chainingKey = ck
	sym.cstate.InitKey(tempk)
}

func (sym *SymmetricState) MixHash(data []byte) {
	sym.hash = genHash(sym.hash[:], data)
}

func (sym *SymmetricState) MixKeyAndHash(keyMaterial []byte) {
	ck, temph, tempk := hkdf3(sym.chainingKey, keyMaterial)
	sym.chainingKey = ck
	sym.MixHash(temph[:])
	sym.cstate.InitKey(tempk)
}

func (sym *SymmetricState) GetHandshakeHash() [32]byte {
	return sym.hash
}

func (sym *SymmetricState) EncryptAndHash(plaintext, buf []byte) (rst []byte, err error) {
	rst, err = sym.cstate.Encrypt(sym.hash[:], plaintext, buf)
	if err != nil {
		return rst, err
	}
	sym.MixHash(rst[len(buf):])
	return rst, nil
}

func (sym *SymmetricState) DecryptAndHash(ciphertext, buf []byte) (rst []byte, err error) {
	rst, err = sym.cstate.Decrypt(sym.hash[:], ciphertext, buf)
	if err != nil {
		return rst, err
	}
	sym.MixHash(ciphertext)
	return rst, nil
}

func (sym *SymmetricState) Split() (c1 CipherState, c2 CipherState) {
	tempk1, tempk2 := hkdf2(sym.chainingKey, nil)
	c1.InitKey(tempk1)
	c2.InitKey(tempk2)
	return
}

func (sym *SymmetricState) HasKey() bool {
	return sym.cstate.HasKey()
}
