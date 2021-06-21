package socks5

import (
	"io"
	"net"
)

type Transport interface {
	Transport(client net.Conn, remote net.Conn) error
}

type Buffer struct {
	Bufsize int
}

func NewBuffer(size int) *Buffer {
	return &Buffer{Bufsize: size}
}

func (b *Buffer) Transport(client net.Conn, remote net.Conn) error {
	buf1 := make([]byte, b.Bufsize)
	io.CopyBuffer(remote, client, buf1)
	return nil
}
