package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Client struct {
	ProxyAddr string
	ProxyConn net.Conn
	net.Conn
	Auth       map[METHOD]interface{}
	UDPTimout  int
	TCPTimeout int
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
func NewClient(proxyAddr string, opts interface{}) *Client {
	c := &Client{
		ProxyAddr: proxyAddr,
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

func (clt *Client) Dial(network, addr string) (net.Conn, error) {
	if network == "tcp" {
		return clt.TCPDial(network, addr)
	}
	if network == "udp" {
		return clt.UDPDial(network, nil, addr)
	}
	return nil, errors.New("net support network")
}

func (clt *Client) TCPDial(network, addr string) (net.Conn, error) {
	remoteAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	clt.ProxyConn, err = net.Dial(network, clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if _, err := clt.HandShake(CONNECT, addr); err != nil {
		clt.Close()
		return nil, err
	}
	clt.Conn = &underConnect{
		clt.ProxyConn.(*net.TCPConn),
		remoteAddr,
	}
	return &Connect{clt}, nil
}

func (clt *Client) HandShake(command CMD, addr string) (string, error) {
	var methods []byte
	methods = append(methods, NO_AUTHENTICATION_REQUIRED)
	if clt.Auth != nil {
		methods = append(methods, USERNAME_PASSWORD)
	}
	//_, err := clt.ProxyConn.Write(NewMethodRequest(Version5, []byte{methods}).Bytes())
	_, err := clt.ProxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return "", nil
	}
	reply, err := ReadNBytes(clt.ProxyConn, 2)

	//reply, err := ParseMethodReply(clt.ProxyConn)
	if err != nil {
		return "", err
	}
	if reply[0] != Version5 {
		return "", &VersionError{reply[0]}
	}

	if (reply[1] != USERNAME_PASSWORD) && (reply[1] != NO_AUTHENTICATION_REQUIRED) {
		return "", &MethodError{reply[1]}
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
			return "", err
		}
		reply, err = ReadNBytes(clt.ProxyConn, 2)
		if err != nil {
			return "", err
		}
		if reply[0] != 0x01 {
			return "", errors.New("not support method")
		}
		if reply[1] != SUCCESSED {
			return "", fmt.Errorf("user authentication failed")
		}
	}
	a, err := ParseAddrSpec(addr)
	if err != nil {
		return "", err
	}
	reqHead := Request1{
		Version: Version5,
		Command: command,
		DstAddr: a,
	}
	if _, err := clt.ProxyConn.Write(reqHead.Bytes()); err != nil {
		return "", err
	}
	rspHead, err := ParseReply(clt.ProxyConn)
	if err != nil {
		return "", err
	}
	if rspHead.Response != SUCCESSED {
		return "", errors.New("host unreachable")
	}
	return rspHead.BndAddr.String(), nil
}

type UserPassRequest struct {
	VER
	Ulen uint8
	Plen uint8
	User []byte
	Pass []byte
}

func NewUserPassRequest(ver VER, user, pass []byte) UserPassRequest {
	return UserPassRequest{
		ver,
		byte(len(user)),
		byte(len(pass)),
		user,
		pass,
	}
}

func ParseAddrSpec(addr string) (as AddrSpec, err error) {
	var host, port string

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return
	}
	as.Port, err = strconv.Atoi(port)
	if err != nil {
		return
	}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		as.AddrType, as.IP = IPV4_ADDRESS, ip
	} else if ip6 := ip.To16(); ip6 != nil {
		as.AddrType, as.IP = IPV6_ADDRESS, ip
	} else {
		as.AddrType, as.FQDN = DOMAINNAME, host
	}
	return
}

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
	// private stuff set when Request parsed
	AddrType byte
}

type Request1 struct {
	// Version of socks protocol for message
	Version byte
	// Socks Command "connect","bind","associate"
	Command byte
	// Reserved byte
	Reserved byte
	// DstAddr in socks message
	DstAddr AddrSpec
}

// Bytes returns a slice of request
func (h Request1) Bytes() (b []byte) {
	var addr []byte

	length := 6
	if h.DstAddr.AddrType == IPV4_ADDRESS {
		length += net.IPv4len
		addr = h.DstAddr.IP.To4()
	} else if h.DstAddr.AddrType == IPV6_ADDRESS {
		length += net.IPv6len
		addr = h.DstAddr.IP.To16()
	} else { // ATYPDomain
		length += 1 + len(h.DstAddr.FQDN)
		addr = []byte(h.DstAddr.FQDN)
	}

	b = make([]byte, 0, length)
	b = append(b, h.Version, h.Command, h.Reserved, h.DstAddr.AddrType)
	if h.DstAddr.AddrType == DOMAINNAME {
		b = append(b, byte(len(h.DstAddr.FQDN)))
	}
	b = append(b, addr...)
	b = append(b, byte(h.DstAddr.Port>>8), byte(h.DstAddr.Port))
	return b
}

// ParseReply parse to reply from io.Reader
func ParseReply(r io.Reader) (rep Reply2, err error) {
	// Read the version and command
	tmp := []byte{0, 0}
	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("failed to get reply version and command, %v", err)
	}
	rep.Version, rep.Response = tmp[0], tmp[1]
	if rep.Version != Version5 {
		return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.Version)
	}
	// Read reserved and address type
	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("failed to get reply RSV and address type, %v", err)
	}
	rep.Reserved, rep.BndAddr.AddrType = tmp[0], tmp[1]

	switch rep.BndAddr.AddrType {
	case DOMAINNAME:
		if _, err = io.ReadFull(r, tmp[:1]); err != nil {
			return rep, fmt.Errorf("failed to get reply, %v", err)
		}
		domainLen := int(tmp[0])
		addr := make([]byte, domainLen+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get reply, %v", err)
		}
		rep.BndAddr.FQDN = string(addr[:domainLen])
		rep.BndAddr.Port = int(binary.BigEndian.Uint16(addr[domainLen:]))
	case IPV4_ADDRESS:
		addr := make([]byte, net.IPv4len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get reply, %v", err)
		}
		rep.BndAddr.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		rep.BndAddr.Port = int(binary.BigEndian.Uint16(addr[net.IPv4len:]))
	case IPV6_ADDRESS:
		addr := make([]byte, net.IPv6len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get reply, %v", err)
		}
		rep.BndAddr.IP = addr[:net.IPv6len]
		rep.BndAddr.Port = int(binary.BigEndian.Uint16(addr[net.IPv6len:]))
	default:
		return rep, &AtypeError{rep.BndAddr.AddrType}
	}
	return rep, nil
}

// Reply represents the SOCKS5 reply, it contains everything that is not payload
// The SOCKS5 reply is formed as follows:
//	+-----+-----+-------+------+----------+-----------+
//	| VER | REP |  RSV  | ATYP | BND.ADDR | BND].PORT |
//	+-----+-----+-------+------+----------+-----------+
//	|  1  |  1  | X'00' |  1   | Variable |    2      |
//	+-----+-----+-------+------+----------+-----------+
type Reply2 struct {
	// Version of socks protocol for message
	Version byte
	// Socks Response status"
	Response byte
	// Reserved byte
	Reserved byte
	// Bind Address in socks message
	BndAddr AddrSpec
}

func (sf *AddrSpec) String() string {
	if len(sf.IP) != 0 {
		return net.JoinHostPort(sf.IP.String(), strconv.Itoa(sf.Port))
	}
	return net.JoinHostPort(sf.FQDN, strconv.Itoa(sf.Port))
}

// underConnect under connect
type underConnect struct {
	*net.TCPConn
	remoteAddress net.Addr // real remote address, not the proxy address
}

type Connect struct {
	*Client
}

func (clt *Client) UDPDial(network string, laddr *net.UDPAddr, raddr string) (net.Conn, error) {
	bRemoteAddr, err := NewAddrByteFromString(raddr)

	//remoteAddress, err := net.ResolveUDPAddr(network, raddr)
	if err != nil {
		return nil, err
	}
	clt.ProxyConn, err = net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	bndAddress, err := clt.HandShake(UDP_ASSOCIATE, raddr)
	if err != nil {
		return nil, err
	}
	ra, err := net.ResolveUDPAddr(network, bndAddress)
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
	udpConn, err := net.DialUDP(network, laddr, ra)
	if err != nil {
		clt.Close()
		return nil, err
	}
	return &SocksUDPConn{
		UDPConn: udpConn,
		dstAddr: bRemoteAddr,
		timeout: time.Duration(clt.UDPTimout) * time.Second,
	}, nil
}

func NewAddrByteFromString(s string) (AddrByte, error) {
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("addr:%s SplitHostPort %v", s, err)
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
