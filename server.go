package socks5

import (
	"context"
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
}

type Server struct {
	supportMethos  map[METHOD]Authenticator
	supportMethods map[CMD]int
}

func (s *Server) ServeConn(ctx context.Context, client net.Conn) {
	panic("implement me")
}

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
		}
		for m := range s.supportMethos {
			//Select the first matched method to authenticate
			if m == method {
				return s.supportMethos[m].Authenticate(in, out)
			}
		}
	}

	//There are no Methods can use
	return errNoMethodAvailable
}

func (s *Server) ProcessSocks4Request(in io.Reader, out io.Writer) error {
	cmd := make([]byte, 1)
	_, err := io.ReadAtLeast(in, cmd, 1)
	if err != nil {
		return err
	}

	destPort := make([]byte, 2)
	_, err = io.ReadAtLeast(in, destPort, 2)
	if err != nil {
		return err
	}

	destIP := make([]byte, 4)
	_, err = io.ReadAtLeast(in, destIP, 4)
	if err != nil {
		return err
	}

	//Discard later bytes until read EOF
	_, err = io.ReadAll(in)
	if err != io.EOF {
		return err
	}

	switch {

	}
	SerializeSocks4Reply(PERMIT, destIP, destPort)
}

func (s *Server) ProcessSocks5Request(in io.Reader, out io.Writer) error {
	panic("implement me")
}

// IsAllowNoAuthRequired  is server enable NO_AUTHENTICATION_REQUIRED method.
// If enabled return true. otherwise return false.
func (s *Server) IsAllowNoAuthRequired() bool {
	for method := range s.supportMethos {
		if method == NO_AUTHENTICATION_REQUIRED {
			return true
		}
	}
	return false
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
