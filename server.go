package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

// SocksProcedure includes socks protocol process
type SocksProcedure interface {
	ServeConn(ctx context.Context, client net.Conn)
	HandShake(ctx context.Context, in io.Reader, out io.Writer) (*Request, error)
	Authentication(in io.Reader, out io.Writer) error
	ProcessSocks4Request(in io.Reader, out io.Writer) error
	ProcessSocks5Request(in io.Reader, out io.Writer) error
	IsAllowNoAuthRequired() bool
	Establish(req *Request) (client net.Conn, dest net.Conn, err error)
}

type Server struct {
	Addr            net.IP
	Port            uint16
	Atype           ATYPE
	supportMethods  map[METHOD]Authenticator
	supportCommands []CMD
	ln              net.Listener
}

// NewServer return socks server
func NewServer(atype ATYPE, addr net.IP, port uint16, supportMethods map[METHOD]Authenticator,
	supportCommands []CMD) *Server {
	return &Server{
		Atype:           atype,
		Addr:            addr,
		Port:            port,
		supportMethods:  supportMethods,
		supportCommands: supportCommands,
	}
}

// Address return server address like
// Examples:
//	127.0.0.1:80
//	example.com:443
//  [fe80::1%lo0]:80
func (s *Server) Address() string {
	if s.Atype == DOMAINNAME {
		return net.JoinHostPort(string(s.Addr), strconv.Itoa(int(s.Port)))
	}
	return net.JoinHostPort(s.Addr.String(), strconv.Itoa(int(s.Port)))
}

// Listen server start listen
func (s *Server) Listen() error {
	var err error
	s.ln, err = net.Listen("tcp", s.Address())
	if err != nil {
		return err
	}

	return nil
}

// Serve every client connection
func (s *Server) Serve() error {
	for {
		client, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(context.Background(), client)
	}
}

// ServeConn Access client connections
func (s *Server) ServeConn(ctx context.Context, client net.Conn) {
	req, err := s.HandShake(ctx, client, client)
	if err != nil {
		log.Println(err)
		client.Close()
		return
	}

	remote, err := s.Establish(req)
	if err != nil {
		log.Println(err)
		client.Close()
		return
	}

	out := NewBuffer(1024)
	go out.Transport(remote, client)
	in := NewBuffer(1024)
	go in.Transport(client, remote)
}

// HandShake socks protocol handshake process
func (s *Server) HandShake(ctx context.Context, in io.Reader, out io.Writer) (*Request, error) {
	//validate socks version message
	version, err := CheckVersion(in)
	if err != nil {
		return nil, err
	}

	//socks4 protocol process
	if version == Version4 {
		if !s.IsAllowNoAuthRequired() {
			//send server reject reply
			reply, err := SerializeSocks4Reply(REJECT, net.IPv4zero, 0)
			if err != nil {
				return nil, err
			}
			_, err = out.Write(reply)
			if err != nil {
				return nil, err
			}
		}

		return s.ProcessSocks4Request(in, out)
	}

	//socks5 protocol authentication
	err = s.Authentication(in, out)
	if err != nil {
		return nil, err
	}

	//handle socks request
	return s.ProcessSocks5Request(in, out)

	return nil, err
}

var errNoMethodAvailable = errors.New("there is no method available")

// Authentication socks5 authentication process
func (s *Server) Authentication(in io.Reader, out io.Writer) error {
	//get nMethods
	nMethods := make([]byte, 1)
	_, err := io.ReadAtLeast(in, nMethods, 1)
	if err != nil {
		return err
	}

	//Get methods
	methods := make([]byte, nMethods[0])
	_, err = io.ReadAtLeast(in, methods, int(nMethods[0]))
	if err != nil {
		return err
	}

	//Select method to authenticate, then send selected method to client.
	for _, method := range methods {
		//Preferred to use NO_AUTHENTICATION_REQUIRED method
		if method == NO_AUTHENTICATION_REQUIRED && s.IsAllowNoAuthRequired() {
			reply := []byte{Version5, NO_AUTHENTICATION_REQUIRED}
			_, err := out.Write(reply)
			if err != nil {
				return err
			}
			return nil
		}
		for m := range s.supportMethods {
			//Select the first matched method to authenticate
			if m == method {
				reply := []byte{Version5, USERNAME_PASSWORD}
				_, err := out.Write(reply)
				if err != nil {
					return err
				}
				return s.supportMethods[m].Authenticate(in, out)
			}
		}
	}

	//There are no Methods can use
	reply := []byte{Version5, NO_ACCEPTABLE_METHODS}
	_, err = out.Write(reply)
	if err != nil {
		return err
	}
	return nil
	return errNoMethodAvailable
}

// ProcessSocks4Request receive socks4 protol client request and
// send back a reply.
func (s *Server) ProcessSocks4Request(in io.Reader, out io.Writer) (*Request, error) {
	reply := &Reply{
		VER:      Version4,
		BindAddr: s.Addr,
		BindPort: s.Port,
	}
	req := &Request{
		VER:   Version4,
		ATYPE: IPV4_ADDRESS,
	}

	cmd := make([]byte, 1)
	_, err := io.ReadAtLeast(in, cmd, 1)
	if err != nil {
		return nil, err
	}
	req.CMD = cmd[0]

	destPort := make([]byte, 2)
	_, err = io.ReadAtLeast(in, destPort, 2)
	if err != nil {
		return nil, err
	}
	req.DestPort = binary.BigEndian.Uint16(destPort)

	//todo: should support socks4a
	destIP := make([]byte, 4)
	_, err = io.ReadAtLeast(in, destIP, 4)
	if err != nil {
		return nil, err
	}
	req.DestAddr = destIP

	//Discard later bytes until read EOF
	//Please see socks4 request format at(http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol)
	err = ReadAndDiscardNotNullByte(in)
	if err != nil {
		return nil, err
	}

	//Socks4a extension
	// +----+----+----+----+----+----+----+----+----+----++----++-----+-----++----+
	// | VN | CD | DSTPORT |      DSTIP        | USERID   |NULL|  HOSTNAME   |NULL|
	// +----+----+----+----+----+----+----+----+----+----++----++-----+-----++----+
	//    1    1      2              4           variable    1    variable    1
	//The client sets the first three bytes of DSTIP to NULL and
	//the last byte to non-zero. The corresponding IP address is
	//0.0.0.x, where x is non-zero
	if destIP[0] == 0 && destIP[1] == 0 && destIP[2] == 0 &&
		destIP[3] != 0 {
		destIP, err = ReadNotNull(in)
		if err != nil {
			return nil, err
		}
		req.DestAddr = destIP
		req.ATYPE = DOMAINNAME
	}

	switch req.CMD {
	case CONNECT:
		reply.REP = PERMIT
		err = s.SendReply(out, reply)
		if err != nil {
			return nil, err
		}
	default:
		reply.REP = REJECT
		reply.BindAddr = net.IPv4zero
		reply.BindPort = 0
		err = s.SendReply(out, reply)
		if err != nil {
			return nil, err
		}
		return nil, &CMDError{req.CMD}
	}

	return req, nil
}

// ProcessSocks5Request receive socks5 protol client request and
// send back a reply.
func (s *Server) ProcessSocks5Request(in io.Reader, out io.Writer) (*Request, error) {
	reply := &Reply{
		VER:      Version5,
		ATYPE:    s.Atype,
		BindAddr: s.Addr,
		BindPort: s.Port,
	}
	req := &Request{}
	//[]byte{ver, cmd, rsv, atype}
	cmd := make([]byte, 4)
	_, err := io.ReadAtLeast(in, cmd, len(cmd))
	if err != nil {
		return nil, err
	}
	req.VER = cmd[0]
	req.CMD = cmd[1]
	req.RSV = cmd[2]
	req.ATYPE = cmd[3]

	//Get dest addr
	var destAddr []byte
	switch req.ATYPE {
	case IPV4_ADDRESS:
		destAddr = make([]byte, 4)
	case IPV6_ADDRESS:
		destAddr = make([]byte, 16)
	case DOMAINNAME:
		fqdnLength := make([]byte, 1)
		_, err := io.ReadAtLeast(in, fqdnLength, len(fqdnLength))
		if err != nil {
			return nil, err
		}
		destAddr = make([]byte, fqdnLength[0])
	default:
		reply.REP = ADDRESS_TYPE_NOT_SUPPORTED
		err = s.SendReply(out, reply)
		if err != nil {
			return nil, err
		}
		return nil, &AtypeError{req.ATYPE}
	}
	_, err = io.ReadAtLeast(in, destAddr, len(destAddr))
	if err != nil {
		return nil, err
	}
	req.DestAddr = destAddr

	//Get dest port
	destPort := make([]byte, 2)
	_, err = io.ReadAtLeast(in, destPort, 2)
	if err != nil {
		return nil, err
	}
	req.DestPort = binary.BigEndian.Uint16(destPort)

	switch req.CMD {
	case CONNECT, UDP_ASSOCIATE:
		reply.REP = SUCCESSED
		err = s.SendReply(out, reply)
		if err != nil {
			return nil, err
		}
	default:
		reply.REP = COMMAND_NOT_SUPPORTED
		err = s.SendReply(out, reply)
		if err != nil {
			return nil, err
		}

		return nil, &CMDError{req.CMD}
	}

	return req, nil
}

// IsAllowNoAuthRequired  is server enable NO_AUTHENTICATION_REQUIRED method.
// If enabled return true. otherwise return false.
func (s *Server) IsAllowNoAuthRequired() bool {
	for method := range s.supportMethods {
		if method == NO_AUTHENTICATION_REQUIRED {
			return true
		}
	}
	return false
}

var errNotEstablish = errors.New("unable to establish a connection to the remote server")

// Establish dial to the target address of the client
func (s *Server) Establish(req *Request) (dest net.Conn, err error) {
	switch req.CMD {
	case CONNECT:
		dest, err = net.Dial("tcp", req.Address())
	case UDP_ASSOCIATE:
		dest, err = net.Dial("udp", req.Address())
	default:
		dest, err = nil, errNotEstablish
	}
	return
}

// SendReply Server send socks protocol reply to client
func (s *Server) SendReply(out io.Writer, r *Reply) error {
	var reply []byte
	var err error
	if r.VER == Version4 {
		reply, err = SerializeSocks4Reply(r.REP, r.BindAddr, r.BindPort)
		if err != nil {
			return err
		}
	} else if r.VER == Version5 {
		reply, err = SerializeSocks5Reply(r.REP, r.ATYPE, r.BindAddr, r.BindPort)
		if err != nil {
			return err
		}
	} else {
		return &VersionError{r.VER}
	}

	_, err = out.Write(reply)
	return err
}

// CheckVersion check version is 4 or 5.
func CheckVersion(in io.Reader) (VER, error) {
	version := make([]VER, 1)
	_, err := io.ReadAtLeast(in, version, 1)
	if err != nil {
		return 0, err
	}

	if (version[0] != Version5) && (version[0] != Version4) {
		return 0, &VersionError{version[0]}
	}
	return version[0], nil
}

// ReadAndDiscardNotNullByte Read all not Null byte and discard.
// Until read first Null byte(all zero bits)
func ReadAndDiscardNotNullByte(reader io.Reader) error {
	b := make([]byte, 1)
	for {
		_, err := reader.Read(b)
		if err != nil {
			return err
		}
		if b[0] == 0 {
			return nil
		}
	}
}

// ReadNotNull Read all not Null byte.
// Until read first Null byte(all zero bits)
func ReadNotNull(reader io.Reader) ([]byte, error) {
	data := &bytes.Buffer{}
	b := make([]byte, 1)
	for {
		_, err := reader.Read(b)
		if err != nil {
			return nil, err
		}

		if b[0] == 0 {
			return data.Bytes(), nil
		}
		data.WriteByte(b[0])
	}
}
