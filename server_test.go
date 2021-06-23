package socks5

import (
	"errors"
	"net"
	"testing"
)

func TestOpError(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	clientIP := &net.IPAddr{IP: ip}
	err := &OpError{
		Op:   "write",
		VER:  Version5,
		Addr: clientIP,
		Step: "authentication",
		Err:  errors.New("user admin has no password."),
	}

	expected := "socks5 write 127.0.0.1 authentication:user admin has no password."
	if err.Error() != expected {
		t.Errorf("expected: %s\ngot: %s", expected, err.Error())
	}
}
