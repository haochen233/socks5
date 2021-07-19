package socks5

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type ConnState = int32

const (
	StateNew = iota
	StateActive
	StateIdle
	StateClosed
)

// Conn
type Conn interface {
	SetState(state ConnState)

	GetState() ConnState

	// Read reads data from the connection.
	// Read can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	Close()
}

type UDPConn struct {
	mu        sync.Mutex
	udp       *net.UDPConn
	tcp       *net.TCPConn
	state     ConnState
	closeChan chan struct{}
}

func NewUDPConn(udp *net.UDPConn, tcp *net.TCPConn) *UDPConn {
	if udp == nil || tcp == nil {
		return nil
	}

	u := &UDPConn{
		udp:       udp,
		tcp:       tcp,
		state:     StateNew,
		closeChan: make(chan struct{}),
	}

	go func() {
		// guard tcp connection, if it closed should close tcp relay too.
		io.Copy(io.Discard, tcp)
		u.Close()
	}()

	return u
}

func (u *UDPConn) SetState(state ConnState) {
	atomic.StoreInt32(&u.state, state)
}

func (u *UDPConn) GetState() ConnState {
	return atomic.LoadInt32(&u.state)
}

func (u *UDPConn) Read(b []byte) (n int, err error) {
	return u.udp.Read(b)
}

func (u *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return u.udp.WriteToUDP(b, addr)
}

func (u *UDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	return u.udp.ReadFromUDP(b)
}

func (u *UDPConn) Write(b []byte) (n int, err error) {
	return u.udp.Write(b)
}

func (u *UDPConn) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()

	ch := u.getCloseChanLocked()
	select {
	case <-ch:
		return
	default:
		u.SetState(StateClosed)
		u.udp.Close()
		u.tcp.Close()
		close(u.closeChan)
	}
}

func (u *UDPConn) CloseCh() <-chan struct{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.getCloseChanLocked()
}

func (u *UDPConn) getCloseChanLocked() <-chan struct{} {
	if u.closeChan == nil {
		u.closeChan = make(chan struct{})
	}
	return u.closeChan
}

type TCPConn struct {
	mu        sync.Mutex
	base      *net.TCPConn
	state     ConnState
	closeChan chan struct{}
}

func NewTCPConn(tcp *net.TCPConn) *TCPConn {
	if tcp == nil {
		return nil
	}

	t := &TCPConn{
		base:      tcp,
		state:     StateNew,
		closeChan: make(chan struct{}),
	}

	return t
}

func (t *TCPConn) SetState(state ConnState) {
	atomic.StoreInt32(&t.state, state)
}

func (t *TCPConn) GetState() ConnState {
	return atomic.LoadInt32(&t.state)
}

func (t *TCPConn) Read(b []byte) (n int, err error) {
	return t.base.Read(b)
}

func (t *TCPConn) Write(b []byte) (n int, err error) {
	return t.base.Write(b)
}

func (t *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	return t.base.ReadFrom(r)
}

func (t *TCPConn) Close() {
	t.mu.Lock()
	t.mu.Unlock()
	ch := t.getCloseChanLocked()
	select {
	case <-ch:
		return
	default:
		t.SetState(StateClosed)
		t.base.Close()
		close(t.closeChan)
	}
}

func (t *TCPConn) CloseCh() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getCloseChanLocked()
}

func (t *TCPConn) getCloseChanLocked() <-chan struct{} {
	if t.closeChan == nil {
		t.closeChan = make(chan struct{})
	}
	return t.closeChan
}
