package noise

import (
	"crypto/rand"
	"errors"
)

var (
	ErrPSKReuse              = errors.New("potential PSK reuse, please mix ephemeral before encrypting with mixed PSK")
	ErrSigVerificationFailed = errors.New("signature verification failed")
)

type HandshakeState struct {
	Initiator bool

	localEphemeralPub, localStaticPub, remoteEphemeralPub, remoteStaticPub [32]byte
	localEphemeralPriv, localStaticPriv                                    [32]byte

	pattern     PatternType
	patternStep int

	prologue string

	sstate SymmetricState

	pskEnabled               bool
	pskMaterial              [32]byte
	mixedPsk, mixedEphemeral bool // encryption is disallowed if sentPsk is true but sentEphemeral is false
}

func NewHandshakeI(pattern PatternType) HandshakeState {
	return HandshakeState{Initiator: true, pattern: pattern}
}

func NewHandshake(pattern PatternType) HandshakeState {
	return HandshakeState{pattern: pattern}
}

func (h HandshakeState) WithLocalStatic(priv, pub [32]byte) HandshakeState {
	h.localStaticPriv = priv
	h.localStaticPub = pub
	return h
}

func (h HandshakeState) WithRemoteStatic(pub [32]byte) HandshakeState {
	h.remoteStaticPub = pub
	return h
}

func (h HandshakeState) WithPrologue(prologue string) HandshakeState {
	h.prologue = prologue
	return h
}

func (h HandshakeState) WithPSK(psk [32]byte) HandshakeState {
	h.pskEnabled = true
	h.pskMaterial = psk
	return h
}

func (h HandshakeState) Init() HandshakeState {
	h.sstate.Initialize("Noise_XK_25519_ChaChaPoly_SHA256")
	h.sstate.MixHash([]byte(h.prologue))
	pattern := GetPattern(h.pattern)
	for i, msg := range pattern.PreMessages {
		switch msg {
		case s:
			if i == 0 {
				if h.Initiator {
					h.sstate.MixHash(h.remoteStaticPub[:])
				} else {
					h.sstate.MixHash(h.localStaticPub[:])
				}
			}
			if i == 1 {
				if h.Initiator {
					h.sstate.MixHash(h.localStaticPub[:])
				} else {
					h.sstate.MixHash(h.remoteStaticPub[:])
				}
			}
		}
	}
	return h
}

func (h *HandshakeState) WriteMessage(payload, buf []byte) ([]byte, error) {
	var err error
	pattern := GetPattern(h.pattern)
	if h.patternStep >= pattern.Len() {
		return nil, errors.New("handshake already finished")
	}
	for _, step := range pattern.Steps[h.patternStep] {
		switch step {
		case e:
			h.localEphemeralPriv, h.localEphemeralPub = GenerateKey(rand.Reader)
			h.sstate.MixHash(h.localEphemeralPub[:])
			buf = append(buf, h.localEphemeralPub[:]...)
			if h.pskEnabled {
				h.sstate.MixKey(h.localEphemeralPub[:])
				h.mixedEphemeral = true
			}
		case s:
			buf, err = h.sstate.EncryptAndHash(h.localStaticPub[:], buf)
			if err != nil {
				return buf, err
			}
		case ee:
			rst := DH(h.localEphemeralPriv, h.remoteEphemeralPub)
			h.sstate.MixKey(rst[:])
		case es:
			rst := [32]byte{}
			if h.Initiator {
				rst = DH(h.localEphemeralPriv, h.remoteStaticPub)
			} else {
				rst = DH(h.localStaticPriv, h.remoteEphemeralPub)
			}
			h.sstate.MixKey(rst[:])
		case se:
			rst := [32]byte{}
			if h.Initiator {
				rst = DH(h.localStaticPriv, h.remoteEphemeralPub)
			} else {
				rst = DH(h.localEphemeralPriv, h.remoteStaticPub)
			}
			h.sstate.MixKey(rst[:])
		case ss:
			rst := DH(h.localStaticPriv, h.remoteStaticPub)
			h.sstate.MixKey(rst[:])
		case psk:
			h.mixedPsk = true
			h.sstate.MixKeyAndHash(h.pskMaterial[:])
		case sig:
			// FIXME should store keys of arbitrary lengths
			key := [64]byte{}
			copy(key[:], h.localStaticPriv[:])
			copy(key[32:], h.localEphemeralPub[:])
			hash := h.sstate.GetHandshakeHash()
			sig := [64]byte{}
			_ = GenerateSignagure(key[:], hash[:], sig[:0])
			buf, err = h.sstate.EncryptAndHash(sig[:], buf)
			if err != nil {
				return nil, err
			}
		}
	}
	if h.mixedPsk && !h.mixedEphemeral {
		return nil, ErrPSKReuse
	}
	h.patternStep++
	return h.sstate.EncryptAndHash(payload, buf)
}

func (h *HandshakeState) ReadMessage(message, buf []byte) ([]byte, error) {
	var err error
	pattern := GetPattern(h.pattern)
	if h.patternStep == pattern.Len() {
		return nil, errors.New("handshake already finished")
	}
	for _, step := range pattern.Steps[h.patternStep] {
		switch step {
		case e:
			copy(h.remoteEphemeralPub[:], message)
			h.sstate.MixHash(h.remoteEphemeralPub[:])
			message = message[32:]
			if h.pskEnabled {
				h.sstate.MixKey(h.remoteEphemeralPub[:])
				h.mixedEphemeral = true
			}
		case s:
			var temp []byte
			if h.sstate.HasKey() {
				temp = message[:48]
				message = message[48:]
			} else {
				temp = message[:32]
				message = message[32:]
			}
			_, err = h.sstate.DecryptAndHash(temp, h.remoteStaticPub[:0])
			if err != nil {
				return nil, err
			}
		case ee:
			rst := DH(h.localEphemeralPriv, h.remoteEphemeralPub)
			h.sstate.MixKey(rst[:])
		case es:
			var rst [32]byte
			if h.Initiator {
				rst = DH(h.localEphemeralPriv, h.remoteStaticPub)
			} else {
				rst = DH(h.localStaticPriv, h.remoteEphemeralPub)
			}
			h.sstate.MixKey(rst[:])
		case se:
			var rst [32]byte
			if h.Initiator {
				rst = DH(h.localStaticPriv, h.remoteEphemeralPub)
			} else {
				rst = DH(h.localEphemeralPriv, h.remoteStaticPub)
			}
			h.sstate.MixKey(rst[:])
		case ss:
			rst := DH(h.localStaticPriv, h.remoteStaticPub)
			h.sstate.MixKey(rst[:])
		case psk:
			h.mixedPsk = true
			h.sstate.MixKeyAndHash(h.pskMaterial[:])
		case sig:
			cSig := message[:80]
			sig := make([]byte, 64)
			sig, err = h.sstate.DecryptAndHash(cSig, sig)
			if err != nil {
				return nil, err
			}
			hash := h.sstate.GetHandshakeHash()
			if !VerifySignature(h.remoteStaticPub[:], hash[:], sig) {
				return nil, ErrSigVerificationFailed
			}
			message = message[80:]
		}
	}
	h.patternStep++
	return h.sstate.DecryptAndHash(message, buf)
}

func (h *HandshakeState) Complete() bool {
	pattern := GetPattern(h.pattern)
	return h.patternStep == pattern.Len()
}

func (h *HandshakeState) Split() (CipherState, CipherState) {
	r, w := h.sstate.Split()
	if !h.Initiator {
		return w, r
	}
	return r, w
}
