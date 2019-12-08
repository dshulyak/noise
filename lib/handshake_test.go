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

	hi := NewHandshakeI(xk).WithLocalStatic(k1Priv, k1Pub).WithRemoteStatic(k2Pub)
	hi.Init()
	h := NewHandshake(xk).WithLocalStatic(k2Priv, k2Pub)
	h.Init()

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

	hiC1, hiC2 := hi.Split()
	hC1, hC2 := h.Split()

	require.Equal(t, hiC1, hC1)
	require.Equal(t, hiC2, hC2)
}
