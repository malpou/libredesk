package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// serveNATSHandshake answers the client's CONNECT and PING like a NATS server would.
func serveNATSHandshake(t *testing.T, c net.Conn) {
	t.Helper()
	fmt.Fprint(c, `INFO {"server_id":"fake","version":"2.10.0","proto":1,"max_payload":1048576}`+"\r\n")
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Errorf("reading handshake: %v", err)
			return
		}
		if strings.HasPrefix(line, "PING") {
			fmt.Fprint(c, "PONG\r\n")
			return
		}
	}
}

// The server can report an expired credential twice on one connection. nats.go then closes the
// connection for good unless told otherwise, which took every login on the desk down.
func TestNATSOptionsReconnectAfterRepeatedAuthExpiry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		first, err := ln.Accept()
		if err != nil {
			return
		}
		serveNATSHandshake(t, first)
		fmt.Fprint(first, "-ERR 'User Authentication Expired'\r\n-ERR 'User Authentication Expired'\r\n")
		first.Close()

		second, err := ln.Accept()
		if err != nil {
			return
		}
		defer second.Close()
		serveNATSHandshake(t, second)
		time.Sleep(10 * time.Second)
	}()

	reconnected := make(chan struct{}, 1)
	opts := append(natsOptions(),
		nats.ReconnectWait(10*time.Millisecond),
		nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }),
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}),
	)
	nc, err := nats.Connect("nats://"+ln.Addr().String(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	select {
	case <-reconnected:
	case <-time.After(5 * time.Second):
		t.Fatalf("no reconnect after repeated auth expiry, closed=%v", nc.IsClosed())
	}
}
