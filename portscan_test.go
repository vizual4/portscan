package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateOpen, "open"},
		{StateClosed, "closed"},
		{StateTimeout, "timeout"},
		{StateUnreachable, "unreachable"},
		{StateCanceled, "canceled"},
		{StateError, "error"},
		{StateUnknown, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func startTestServer(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	return ln, uint16(port)
}

func TestScanOpenPort(t *testing.T) {
	ln, port := startTestServer(t)
	defer ln.Close()

	s, err := New(WithConcurrency(10), WithConnectTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	spec, _ := Ports(port)
	results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, spec)
	if err != nil {
		t.Fatal(err)
	}

	var got []Result
	for r := range results {
		got = append(got, r)
	}

	if len(got) != 1 || got[0].State != StateOpen {
		t.Fatalf("expected 1 open port result, got %v", got)
	}
}
