package socks5

import (
	"io"
)

type Transport interface {
	Transport(dst io.Writer, src io.Reader)
}

type Buffer struct {
	buf []byte
}

func NewBuffer(size int) *Buffer {
	return &Buffer{buf: make([]byte, size)}
}

func (b *Buffer) Transport(dst io.Writer, src io.Reader) {
	io.CopyBuffer(dst, src, b.buf)
}
