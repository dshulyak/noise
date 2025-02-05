package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	var (
		k1Priv, k1Pub = GenerateKey(nil)
		k2Priv, k2Pub = GenerateKey(nil)
		err           error
	)

	hi := NewHandshakeI(XK).WithLocalStatic(k1Priv, k1Pub).WithRemoteStatic(k2Pub).Init()
	h := NewHandshake(XK).WithLocalStatic(k2Priv, k2Pub).Init()

	require.Equal(t, hi.sstate.hash, h.sstate.hash)

	buf := make([]byte, 48)
	buf, err = hi.WriteMessage(nil, buf[:0])
	require.NoError(t, err)

	_, err = h.ReadMessage(buf, nil)
	require.NoError(t, err)

	require.Equal(t, hi.sstate.hash, h.sstate.hash)

	buf, err = h.WriteMessage(nil, buf[:0])
	require.NoError(t, err)

	_, err = hi.ReadMessage(buf, nil)
	require.NoError(t, err)

	require.Equal(t, hi.sstate.hash, h.sstate.hash)

	buf = make([]byte, 64)
	buf, err = hi.WriteMessage(nil, buf[:0])
	require.NoError(t, err)

	_, err = h.ReadMessage(buf, nil)
	require.NoError(t, err)

	require.True(t, hi.Complete())
	require.True(t, h.Complete())

	r1, w1 := hi.Split()
	r2, w2 := h.Split()

	require.Equal(t, r1, w2)
	require.Equal(t, r2, w1)

	msg := []byte("hello")
	cipher, err := r1.Encrypt(nil, msg, nil)
	require.NoError(t, err)
	require.Len(t, cipher, len(msg)+16)

	plain, err := w2.Decrypt(nil, cipher, nil)
	require.NoError(t, err)
	require.Equal(t, msg, plain)

}
