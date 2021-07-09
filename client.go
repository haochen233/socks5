package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Client defines parameters for running socks client.
type Client struct {
	// in the form "host:port". If empty, ":1080" (port 1080) is used.
	ProxyAddr string
	ProxyConn net.Conn
	net.Conn
	VER

	// method mapping to the authenticator
	Auth       map[METHOD]interface{}
	UDPTimout  int
	TCPTimeout int

	// Generate by Server.Addr field. For Server internal use only.
	addr *Address

	// ErrorLog specifics an options logger for errors accepting
	// If nil, logging is done via log package's standard logger.
	ErrorLog *log.Logger
}

// MemoryStore store username&password in memory.
// the password is encrypt with hash method.
type PwdStore struct {
	User     string
	Password string
	mu       sync.Mutex
}

// NewMemeryStore return a new MemoryStore
func NewPwdStore() *PwdStore {
	return &PwdStore{}
}

func (m *PwdStore) Set(username string, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.User = username
	m.Password = password
	return nil
}

// NewClient create a client
func NewClient(proxyAddr string, version VER, opts interface{}) *Client {
	c := &Client{
		ProxyAddr: proxyAddr,
		VER:       version,
	}
	if opts != nil {
		switch value := opts.(type) {
		case *PwdStore:
			c.Auth = map[METHOD]interface{}{USERNAME_PASSWORD: value}
		}
	}
	return c
}

func (clt *Client) Close() (err error) {
	if clt.ProxyConn != nil {
		err = clt.ProxyConn.Close()
	}
	if clt.Conn != nil {
		err = clt.Conn.Close()
	}
	return
}

func (clt *Client) connServe() {

}

func (clt *Client) Dial(network, addr string) (net.Conn, error) {
	if network == "tcp" {
		return clt.TCPDial(addr)
	}
	if network == "udp" {
		return clt.UDPDial(nil, addr)
	}
	return nil, errors.New("net support network")
}

func (clt *Client) TCPDial(addr string) (net.Conn, error) {
	proxyConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	clt.ProxyConn = proxyConn
	if _, err := clt.handShake(CONNECT, addr); err != nil {
		clt.Close()
		return nil, err
	}
	return clt.ProxyConn, nil
}

// handShake socks protocol handshake process
func (clt *Client) handShake(command CMD, addr string) (string, error) {
	destAddr, err := ParseAddress(addr)
	if err != nil {
		return "", err
	}
	request := Request{
		VER:     clt.VER,
		CMD:     command,
		Address: destAddr,
	}
	if clt.VER == Version5 {
		err := clt.authentication()
		if err != nil {
			return "", err
		}
		clt.socks5Request(&request)
	} else if clt.VER == Version4 {
		clt.socks4Request(&request)
	}

	reply, err := clt.parseReply(clt.ProxyConn)
	if err != nil {
		return "", err
	}
	if reply.REP != SUCCESSED {
		return "", errors.New("host unreachable")
	}
	return reply.Address.String(), nil
}

func (clt *Client) authentication() error {
	var methods []byte
	methods = append(methods, NO_AUTHENTICATION_REQUIRED)
	if clt.Auth != nil {
		methods = append(methods, USERNAME_PASSWORD)
	}

	_, err := clt.ProxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return nil
	}
	reply, err := ReadNBytes(clt.ProxyConn, 2)

	if err != nil {
		return err
	}
	if reply[0] != Version5 {
		return &VersionError{reply[0]}
	}

	if (reply[1] != USERNAME_PASSWORD) && (reply[1] != NO_AUTHENTICATION_REQUIRED) {
		return &MethodError{reply[1]}
	}
	if reply[1] == USERNAME_PASSWORD {
		var user, pass string
		switch value := clt.Auth[USERNAME_PASSWORD].(type) {
		case *PwdStore:
			user = value.User
			pass = value.Password
		}
		userPassRequest := append([]byte{0x01, byte(len(user))}, []byte(user)...)
		userPassRequest = append(userPassRequest, byte(len(pass)))
		_, err = clt.ProxyConn.Write(append(userPassRequest, []byte(pass)...))
		if err != nil {
			return err
		}
		reply, err = ReadNBytes(clt.ProxyConn, 2)
		if err != nil {
			return err
		}
		if reply[0] != 0x01 {
			return errors.New("not support method")
		}
		if reply[1] != SUCCESSED {
			return fmt.Errorf("user authentication failed")
		}
	}
	return nil
}

func (clt *Client) socks5Request(request *Request) (err error) {
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return err
	}
	b := []byte{request.VER, request.CMD, request.RSV}
	if _, err := clt.ProxyConn.Write(append(b, destAddrByte...)); err != nil {
		return err
	}
	return nil
}

func (clt *Client) socks4Request(request *Request) (err error) {
	destAddrByte, err := request.Address.Bytes(Version4)
	if err != nil {
		return err
	}
	b := []byte{request.VER, request.CMD}
	if _, err := clt.ProxyConn.Write(append(b, destAddrByte...)); err != nil {
		return err
	}
	return nil
}

// parseReply parse to reply from io.Reader
func (clt *Client) parseReply(r io.Reader) (rep Reply, err error) {
	if clt.VER == Version4 {
		// Read the version and command
		tmp, err := ReadNBytes(r, 2)
		if err != nil {
			return rep, fmt.Errorf("failed to get reply version and command, %v", err)
		}
		rep.VER, rep.REP = tmp[0], tmp[1]
		if rep.VER != Version4 {
			return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.VER)
		}
	} else if clt.VER == Version5 {
		// Read the version and command
		tmp, err := ReadNBytes(r, 3)
		if err != nil {
			return rep, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
		}
		rep.VER, rep.REP, rep.RSV = tmp[0], tmp[1], tmp[2]
		if rep.VER != Version5 {
			return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.VER)
		}
	} else {
		return rep, &VersionError{clt.VER}
	}
	// Read address
	serverBoundAddr, _, err := readAddress(r, clt.VER)
	if err != nil {
		return rep, fmt.Errorf("failed to get reply address, %v", err)
	}
	rep.Address = serverBoundAddr
	return rep, nil
}

// underConnect under connect
type underConnect struct {
	*net.TCPConn
	remoteAddress net.Addr // real remote address, not the proxy address
}

func (clt *Client) UDPDial(laddr *net.UDPAddr, raddr string) (net.Conn, error) {
	proxyConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	clt.ProxyConn = proxyConn
	bndAddress, err := clt.handShake(UDP_ASSOCIATE, raddr)
	if err != nil {
		return nil, err
	}
	ra, err := net.ResolveUDPAddr("udp", bndAddress)
	if err != nil {
		clt.Close()
		return nil, err
	}
	if laddr == nil {
		ad := clt.ProxyConn.LocalAddr().(*net.TCPAddr)
		laddr = &net.UDPAddr{
			IP:   ad.IP,
			Port: ad.Port,
			Zone: ad.Zone,
		}
	}
	udpConn, err := net.DialUDP("udp", laddr, ra)
	if err != nil {
		clt.Close()
		return nil, err
	}
	destAddr, err := NewAddrByteFromString(raddr)
	//remoteAddress, err := net.ResolveUDPAddr(network, raddr)
	if err != nil {
		return nil, err
	}
	return &SocksUDPConn{
		UDPConn: udpConn,
		dstAddr: destAddr,
		timeout: time.Duration(clt.UDPTimout) * time.Second,
	}, nil
}

func NewAddrByteFromString(s string) (AddrByte, error) {
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("bindAddr:%s SplitHostPort %v", s, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = IPV4_ADDRESS
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = IPV6_ADDRESS
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host:%s too long", host)
		}

		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = DOMAINNAME
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port:%s ParseUint %v", port, err)
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portNum>>8), byte(portNum)
	return addr, nil
}

type SocksUDPConn struct {
	*net.UDPConn
	dstAddr AddrByte
	timeout time.Duration
}

const socketBufSize = 64 * 1024

func (p *SocksUDPConn) Read(b []byte) (int, error) {
	if p.timeout != 0 {
		p.UDPConn.SetReadDeadline(time.Now().Add(p.timeout))
	}

	buf := make([]byte, socketBufSize)
	n, err := p.UDPConn.Read(buf)
	if err != nil {
		return 0, err
	}
	d, err := NewUDPDatagramFromBytes(buf[0:n])
	if err != nil {
		return 0, err
	}
	if len(b) < len(d.Data) {
		return 0, errors.New("buff too small")
	}
	n = copy(b, d.Data)
	return n, nil
}

func (p *SocksUDPConn) Write(b []byte) (int, error) {
	d := NewUDPDatagram(p.dstAddr, b)
	payload := d.ToBytes()
	n, err := p.UDPConn.Write(payload)
	if err != nil {
		return 0, err
	}
	if len(payload) != n {
		return 0, errors.New("not write full")
	}
	return len(b), nil
}

func NewUDPDatagramFromBytes(b []byte) (*UDPDatagram, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("bad request")
	}

	bAddr, err := NewAddrByteFromByte(b[3:])
	if err != nil {
		return nil, err
	}

	data := b[3+len(bAddr):]
	return NewUDPDatagram(bAddr, data), nil
}

const PortLen = 2

func NewAddrByteFromByte(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("bad request")
	}
	var startPos int = 1
	var addrLen int
	switch b[0] {
	case DOMAINNAME:
		if len(b) < 2 {
			return nil, fmt.Errorf("bad request")
		}
		startPos++
		addrLen = int(b[1])
	case IPV4_ADDRESS:
		addrLen = net.IPv4len
	case IPV6_ADDRESS:
		addrLen = net.IPv6len
	default:
		return nil, fmt.Errorf("Unrecognized address type")
	}

	endPos := startPos + addrLen + PortLen

	if len(b) < endPos {
		return nil, fmt.Errorf("bad request")
	}
	return b[:endPos], nil
}

type UDPDatagram struct {
	Rsv     []byte //0x00,0x00
	Frag    byte
	AType   byte
	DstAddr []byte
	DstPort []byte
	Data    []byte
}

func NewUDPDatagram(addrByte AddrByte, data []byte) *UDPDatagram {
	atype, addr, port := addrByte.Split()
	return &UDPDatagram{
		Rsv:     []byte{0, 0},
		Frag:    0,
		AType:   atype,
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}
}

type AddrByte []byte

func (a AddrByte) Split() (aType byte, addr []byte, port []byte) {
	aType = IPV4_ADDRESS
	addr = []byte{0, 0, 0, 0}
	port = []byte{0, 0}

	if a != nil {
		aType = a[0]
		addr = a[1 : len(a)-2]
		port = a[len(a)-2:]
	}
	return
}

func (p *UDPDatagram) ToBytes() []byte {
	b := []byte{}
	b = append(b, p.Rsv...)
	b = append(b, p.Frag)
	b = append(b, p.AType)
	b = append(b, p.DstAddr...)
	b = append(b, p.DstPort...)
	b = append(b, p.Data...)
	return b
}
