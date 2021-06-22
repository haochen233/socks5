package socks5

import (
	"io"
	"net"
)

type Transporter interface {
	Transport(client net.Conn, remote net.Conn) error
}

type transport struct {
	BufSize int
	errCh   chan error
}

func (t *transport) Transport(client net.Conn, remote net.Conn) error {
	if t.errCh == nil {
		t.errCh = make(chan error, 2)
	}

	f := func(dst net.Conn, src net.Conn) {
		inBuf := make([]byte, t.BufSize)
		_, err := io.CopyBuffer(dst, src, inBuf)
		if tcpWrite, ok := client.(*net.TCPConn); ok {
			tcpWrite.CloseWrite()
		}
		if tcpRead, ok := remote.(*net.TCPConn); ok {
			tcpRead.CloseRead()
		}
		t.errCh <- err
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
