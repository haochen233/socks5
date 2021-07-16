package socks5

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Transporter transmit data between client and dest server.
type Transporter interface {
	TransportTCP(client *TCPConn, remote *TCPConn) error
	TransportUDP(server *UDPConn, request *Request) error
}

type transport struct {
	// IdleTimeout is the maximum duration for reading from socks client.
	// it's only effective to socks server handshake process.
	//
	// If zero, there is no timeout.
	IdleTimeout time.Duration
}

const maxLenOfDatagram = 65507

var transportPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, maxLenOfDatagram)
	},
}

// TransportTCP use io.CopyBuffer transmit data.
func (t *transport) TransportTCP(client *TCPConn, remote *TCPConn) error {
	defer client.Close()
	defer remote.Close()
	errCh := make(chan error, 2)

	f := func(dst *TCPConn, src *TCPConn) {
		ticker := time.NewTicker(t.IdleTimeout)
		defer ticker.Stop()
		buf := transportPool.Get().([]byte)
		defer transportPool.Put(buf)

		for {
			select {
			default:
				n, err := src.rawConn.Read(buf)
				if err != nil {
					errCh <- err
					return
				}
				src.SetState(StateActive)

				n, err = dst.rawConn.Write(buf[:n])
				if err != nil {
					errCh <- err
					return
				}
				dst.SetState(StateActive)
				ticker.Reset(t.IdleTimeout)
			case <-ticker.C:
				dst.SetState(StateIdle)
				src.SetState(StateIdle)
				ticker.Reset(t.IdleTimeout)
			case <-dst.CloseChan():
				errCh <- nil
				return
			case <-src.CloseChan():
				errCh <- nil
				return
			}
		}
	}
	go f(remote, client)
	go f(client, remote)

	for i := 0; i < 1; i++ {
		err := <-errCh
		if err != nil {
			return err
		}
	}
	return nil
}

// TransportUDP forwarding UDP packet between client and dest.
func (t *transport) TransportUDP(server *UDPConn, request *Request) error {
	// Client udp address, limit access to the association.
	clientAddr, err := request.Address.UDPAddr()
	if err != nil {
		return err
	}

	// Record dest address, limit access to the association.
	forwardAddr := make(map[*net.UDPAddr]struct{})
	buf := transportPool.Get().([]byte)
	defer transportPool.Put(buf)
	ticker := time.NewTicker(t.IdleTimeout)
	defer ticker.Stop()

	defer server.Close()
	for {
		select {
		default:
			// Receive data from remote.
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return err
			}
			server.SetState(StateActive)

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
				_, err = server.WriteToUDP(payload, destUDPAddr)
				if err != nil {
					return err
				}
			}

			// Should pack data when data from dest host
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
				_, err = server.WriteToUDP(packedData, clientAddr)
				if err != nil {
					return err
				}
			}
			ticker.Reset(t.IdleTimeout)
		case <-ticker.C:
			server.SetState(StateIdle)
			ticker.Reset(t.IdleTimeout)
		case <-server.CloseChan():
			return nil
		}
	}
}

var DefaultTransporter Transporter = &transport{
	IdleTimeout: 30 * time.Second,
}
