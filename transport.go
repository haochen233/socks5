package socks5

import (
	"io"
	"net"
)

// Transporter transmit data between client and dest server.
type Transporter interface {
	Transport(client net.Conn, remote net.Conn) error
}

type transport struct {
	BufSize int
	errCh   chan error
}

// Transport use io.CopyBuffer transmit data
func (t *transport) Transport(client net.Conn, remote net.Conn) error {
	if t.errCh == nil {
		t.errCh = make(chan error, 2)
	}

	f := func(dst net.Conn, src net.Conn) {
		inBuf := make([]byte, t.BufSize)
		_, err := io.CopyBuffer(dst, src, inBuf)
		if err != nil {
			if tcpRead, ok := src.(*net.TCPConn); ok {
				tcpRead.CloseRead()
			}
			if tcpWrite, ok := dst.(*net.TCPConn); ok {
				tcpWrite.CloseWrite()
			}
			t.errCh <- err
		}
		t.errCh <- nil
	}
	go f(remote, client)
	go f(client, remote)

	for i := 0; i < 1; i++ {
		err := <-t.errCh
		if err != nil {
			return err
		}
	}
	return nil
}

var DefaultTransporter Transporter = &transport{
	BufSize: 1024,
	errCh:   nil,
}
