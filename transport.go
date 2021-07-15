package socks5

import (
	"io"
	"net"
	"strings"
	"sync"
)

// Transporter transmit data between client and dest server.
type Transporter interface {
	TransportTCP(client net.Conn, remote net.Conn) error
	TransportUDP(server *net.UDPConn, request *Request) error
}

type transport struct {
	BufSize int
	errCh   chan error
}

const maxLenOfDataGram = 65507

var transportPoll = &sync.Pool{
	New: func() interface{} {
		return make([]byte, maxLenOfDataGram)
	},
}

// TransportTCP use io.CopyBuffer transmit data.
func (t *transport) TransportTCP(client net.Conn, remote net.Conn) error {
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

// TransportUDP forwarding UDP packet between client and dest.
func (t *transport) TransportUDP(server *net.UDPConn, request *Request) error {
	// Client udp address, limit access to the association.
	clientAddr, err := request.Address.UDPAddr()
	if err != nil {
		return err
	}

	// Record dest address, limit access to the association.
	forwardAddr := make(map[*net.UDPAddr]struct{})
	buf := transportPoll.Get().([]byte)

	for {
		// Receive data from remote.
		n, addr, err := server.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		// Should unpack data when data from client.
		if strings.EqualFold(clientAddr.String(), addr.String()) {
			destAddr, payload, err := UnpackUDPData(buf[:n])
			if err != nil {
				return err
			}

			destUDPAddr, err := destAddr.UDPAddr()
			if err != nil {
				return err
			}
			forwardAddr[destUDPAddr] = struct{}{}

			// send payload to dest address
			_, err = server.WriteTo(payload, destUDPAddr)
			if err != nil {
				return err
			}
		}

		// Should pack data when data from dest client
		if _, ok := forwardAddr[addr]; ok {
			address, err := ParseAddress(addr.String())
			if err != nil {
				return err
			}

			// packed Data
			packedData, err := PackUDPData(address, buf[:n])
			if err != nil {
				return err
			}

			// send payload to client
			_, err = server.WriteTo(packedData, clientAddr)
			if err != nil {
				return err
			}
		}
	}
}

var DefaultTransporter Transporter = &transport{
	BufSize: 1024,
	errCh:   nil,
}
