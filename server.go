package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
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
	Address         string
	supportMethods  map[METHOD]Authenticator
	supportCommands []CMD
	ln              net.Listener
}

// NewServer return socks server
func NewServer(addr string, supportMethods map[METHOD]Authenticator,
	supportCommands []CMD) *Server {
	return &Server{
		Address:         addr,
		supportMethods:  supportMethods,
		supportCommands: supportCommands,
	}
}

// Listen server start listen
func (s *Server) Listen() error {
	var err error
	s.ln, err = net.Listen("tcp", s.Address)
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
		client.Close()
		return
	}

	remote, err := s.Establish(req)
	if err != nil {
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
			reply := SerializeSocks4Reply(REJECT, net.IPv4zero, 0)
			_, err := out.Write(reply)
			if err != nil {
				return nil, err
			}
		}

		s.ProcessSocks4Request(in, out)
	}

	//socks5 protocol authentication
	s.Authentication(in, out)

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
				return s.supportMethods[m].Authenticate(in, out)
			}
		}
	}

	//There are no Methods can use
	return errNoMethodAvailable
}

func (s *Server) ProcessSocks4Request(in io.Reader, out io.Writer) (*Request, error) {
	cmd := make([]byte, 1)
	_, err := io.ReadAtLeast(in, cmd, 1)
	if err != nil {
		return nil, err
	}

	destPort := make([]byte, 2)
	_, err = io.ReadAtLeast(in, destPort, 2)
	if err != nil {
		return nil, err
	}

	destIP := make([]byte, 4)
	_, err = io.ReadAtLeast(in, destIP, 4)
	if err != nil {
		return nil, err
	}

	//Discard later bytes until read EOF
	_, err = io.ReadAll(in)
	if err != io.EOF {
		return nil, err
	}

	switch cmd[0] {
	case CONNECT:
		reply := SerializeSocks4Reply(PERMIT, net.IPv4zero, 0)
		_, err := out.Write(reply)
		if err != nil {
			return nil, err
		}
	case BIND:
		return nil, &CMDError{BIND}
	default:
		return nil, &CMDError{cmd[0]}
	}

	return &Request{
		VER:      Version4,
		CMD:      cmd[0],
		RSV:      0,
		ATYPE:    0,
		DestAddr: destIP,
		DestPort: binary.BigEndian.Uint16(destPort),
	}, nil
}

func (s *Server) ProcessSocks5Request(in io.Reader, out io.Writer) (*Request, error) {
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
	case CONNECT:
		reply := SerializeSocks5Reply()
		_, err := out.Write(reply)
		if err != nil {
			return nil, err
		}
	case BIND:
		return nil, &CMDError{BIND}
	case UDP_ASSOCIATE:
		return nil, &CMDError{UDP_ASSOCIATE}
	default:
		return nil, &CMDError{cmd[0]}
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
