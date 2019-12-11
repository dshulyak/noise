package noise

import (
	"fmt"
	"io"
	"log"
	"sync"
)

func initiator(h *HandshakeState, rw io.ReadWriter) {
	var (
		buf = make([]byte, 48)
		err error
	)
	buf, err = h.WriteMessage(nil, buf[:0])
	if err != nil {
		log.Fatalf("intitiator step 1: %v", err)
	}
	_, err = rw.Write(buf)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.ReadFull(rw, buf)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = h.ReadMessage(buf, nil)
	if err != nil {
		log.Fatalf("intitiator step 2: %v", err)
	}
	buf = make([]byte, 64)
	buf, err = h.WriteMessage(nil, buf[:0])
	if err != nil {
		log.Fatalf("intitiator step 3: %v", err)
	}
	_, err = rw.Write(buf)
	if err != nil {
		log.Fatalln(err)
	}
	_, sw := h.Split()
	message := []byte("hello")
	buf, err = sw.Encrypt(nil, message, buf[:0])
	if err != nil {
		log.Fatalf("initiator msg encr: %v", err)
	}
	rw.Write(buf)
}

func responder(h *HandshakeState, rw io.ReadWriter) {
	var (
		buf = make([]byte, 48)
		err error
	)
	_, err = io.ReadFull(rw, buf)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = h.ReadMessage(buf, nil)
	if err != nil {
		log.Fatalf("responder step 1: %v", err)
	}
	buf, err = h.WriteMessage(nil, buf[:0])
	if err != nil {
		log.Fatalf("responder step 2: %v", err)
	}
	_, err = rw.Write(buf)
	if err != nil {
		log.Fatalln(err)
	}
	buf = make([]byte, 64)
	_, err = io.ReadFull(rw, buf)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = h.ReadMessage(buf, nil)
	if err != nil {
		log.Fatalf("responder step 3: %v", err)
	}
	sr, _ := h.Split()
	buf = buf[:21]
	_, err = io.ReadFull(rw, buf)
	msg := make([]byte, 5)
	msg, err = sr.Decrypt(nil, buf, msg[:0])
	if err != nil {
		log.Fatalf("responder msg decr: %v", err)
	}
	fmt.Println(string(msg))
}

type Conn struct {
	io.Reader
	io.Writer
}

func PipeConn() (*Conn, *Conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &Conn{r1, w2}, &Conn{r2, w1}
}

func ExampleSendHello() {
	var (
		k1Priv, k1Pub = GenerateKey(nil)
		k2Priv, k2Pub = GenerateKey(nil)
		wg            sync.WaitGroup
	)
	p1, p2 := PipeConn()

	hi := NewHandshakeI(XK).WithLocalStatic(k1Priv, k1Pub).WithRemoteStatic(k2Pub).Init()
	h := NewHandshake(XK).WithLocalStatic(k2Priv, k2Pub).Init()

	wg.Add(2)
	go func() {
		initiator(&hi, p1)
		wg.Done()
	}()
	go func() {
		responder(&h, p2)
		wg.Done()
	}()
	wg.Wait()
	// Output: hello
}
