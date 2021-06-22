package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// checkVersion check version is 4 or 5.
func checkVersion(in io.Reader) (VER, error) {
	version, err := ReadNBytes(in, 1)
	if err != nil {
		return 0, err
	}

	if (version[0] != Version5) && (version[0] != Version4) {
		return 0, &VersionError{version[0]}
	}
	return version[0], nil
}

// Server defines parameters for running socks server.
// The zero value for Server is a valid configuration(tcp listen on :1080).
type Server struct {
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":1080" (port 1080) is used.
	Addr string

	// todo
	// Unused in currently
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// method mapping to the authenticator
	// if nil server provide NO_AUTHENTICATION_REQUIRED method by default
	Authenticators map[METHOD]Authenticator

	// The server select method to use policy
	//MethodSelector

	// Server transmit data between client and dest server.
	// if nil, DefaultTransport is used.
	Transporter

	// ErrorLog specifics an options logger for errors accepting
	// connections, unexpected socks protocol handshake process,
	// and server to remote connection errors.
	// If nil, logging is done via log package's standard logger.
	ErrorLog *log.Logger

	// DisableSocks4, disable socks4 server, default enable socks4 compatible.
	DisableSocks4 bool

	// Server host type. It can be IPV4_ADDRESS. DOMAINNAME. IPV6_ADDRESS.
	// parse from field Addr.
	atype ATYPE

	// The server listen host.
	// parse from field Addr.
	host net.IP

	// The server listen port.
	// parse from field Addr.
	port uint16
}

// ListenAndServe listens on the TCP network address srv.Addr and then
// calls serve to handle requests on incoming connections.
//
// If srv.Addr is blank, ":1080" is used.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = "0.0.0.0:1080"
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		srv.atype = DOMAINNAME
		srv.host = []byte(host)
	} else if ip.To4() != nil {
		srv.atype = IPV4_ADDRESS
		srv.host = ip.To4()
	} else if ip.To16() != nil {
		srv.atype = IPV6_ADDRESS
		srv.host = ip.To16()
	}
	atoi, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	srv.port = uint16(atoi)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.serve(ln)
}

// serve accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutine select client
// list methods and reply client. Then process authentication and reply
// to them. At then end of handshake, read socks request from client and
// establish a connection to the target.
func (srv *Server) serve(l net.Listener) error {
	for {
		client, err := l.Accept()
		if err != nil {
			return err
		}
		go srv.serveconn(client)
	}
}

func (srv *Server) serveconn(client net.Conn) {
	// handshake
	request, err := srv.handShake(client)
	if err != nil {
		srv.logf()(err.Error())
		client.Close()
		return
	}
	// establish connection to remote
	remote, err := srv.establish(request)
	if err != nil {
		srv.logf()(err.Error())
		client.Close()
		return
	}
	// transport data
	err = srv.transport().Transport(client, remote)
	if err != nil {
		srv.logf()(err.Error())
	}
}

func (srv *Server) transport() Transporter {
	if srv.Transporter == nil {
		return DefaultTransporter
	}
	return srv.Transporter
}

var errDisableSocks4 = errors.New("socks4 server has been disabled")

// HandShake socks protocol handshake process
func (srv *Server) handShake(client net.Conn) (*Request, error) {
	//validate socks version message
	version, err := checkVersion(client)
	if err != nil {
		return nil, err
	}

	//socks4 protocol process
	if version == Version4 {
		if srv.DisableSocks4 {
			//send server reject reply
			reply, err := SerializeSocks4Reply(REJECT, net.IPv4zero, 0)
			if err != nil {
				return nil, err
			}
			_, err = client.Write(reply)
			if err != nil {
				return nil, err
			}
			return nil, errDisableSocks4
		}

		//handle socks4 request
		return srv.processSocks4Request(client)
	}

	//socks5 protocol authentication
	err = srv.authentication(client)
	if err != nil {
		return nil, err
	}

	//handle socks5 request
	return srv.processSocks5Request(client)
}

// Authentication socks5 authentication process
func (srv *Server) authentication(client net.Conn) error {
	//get nMethods
	nMethods, err := ReadNBytes(client, 1)
	if err != nil {
		return err
	}

	//Get methods
	methods, err := ReadNBytes(client, int(nMethods[0]))
	if err != nil {
		return err
	}

	return srv.MethodSelect(methods, client)
}

// processSocks4Request receive socks4 protocol client request and
// send back a reply.
func (srv *Server) processSocks4Request(client net.Conn) (*Request, error) {
	reply := &Reply{
		VER:      Version4,
		ATYPE:    srv.atype,
		BindAddr: srv.host,
		BindPort: srv.port,
	}
	req := &Request{
		VER:   Version4,
		ATYPE: IPV4_ADDRESS,
	}

	cmd, err := ReadNBytes(client, 1)
	if err != nil {
		return nil, err
	}
	req.CMD = cmd[0]

	destPort, err := ReadNBytes(client, 2)
	if err != nil {
		return nil, err
	}
	req.DestPort = binary.BigEndian.Uint16(destPort)

	//todo: should support socks4a
	destIP, err := ReadNBytes(client, 4)
	if err != nil {
		return nil, err
	}
	req.DestAddr = destIP

	//Discard later bytes until read EOF
	//Please see socks4 request format at(http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol)
	_, err = ReadUntilNULL(client)
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
		destIP, err = ReadUntilNULL(client)
		if err != nil {
			return nil, err
		}
		req.DestAddr = destIP
		req.ATYPE = DOMAINNAME
	}

	switch req.CMD {
	case CONNECT:
		reply.REP = PERMIT
		err = srv.SendReply(client, reply)
		if err != nil {
			return nil, err
		}
	default:
		reply.REP = REJECT
		reply.BindAddr = net.IPv4zero
		reply.BindPort = 0
		err = srv.SendReply(client, reply)
		if err != nil {
			return nil, err
		}
		return nil, &CMDError{req.CMD}
	}

	return req, nil
}

// processSocks5Request receive socks5 protocol client request and
// send back a reply.
func (srv *Server) processSocks5Request(client net.Conn) (*Request, error) {
	reply := &Reply{
		VER:      Version5,
		ATYPE:    srv.atype,
		BindAddr: srv.host,
		BindPort: srv.port,
	}
	req := &Request{}
	//[]byte{ver, cmd, rsv, atype}
	cmd, err := ReadNBytes(client, 4)
	if err != nil {
		return nil, err
	}
	req.VER = cmd[0]
	req.CMD = cmd[1]
	req.RSV = cmd[2]
	req.ATYPE = cmd[3]

	//Get dest addr
	var addrLen int
	switch req.ATYPE {
	case IPV4_ADDRESS:
		addrLen = 4
	case IPV6_ADDRESS:
		addrLen = 16
	case DOMAINNAME:
		fqdnLength, err := ReadNBytes(client, 1)
		if err != nil {
			return nil, err
		}
		addrLen = int(fqdnLength[0])
	default:
		reply.REP = ADDRESS_TYPE_NOT_SUPPORTED
		err = srv.SendReply(client, reply)
		if err != nil {
			return nil, err
		}
		return nil, &AtypeError{req.ATYPE}
	}
	destAddr, err := ReadNBytes(client, addrLen)
	if err != nil {
		return nil, err
	}
	req.DestAddr = destAddr

	//Get dest port
	destPort, err := ReadNBytes(client, 2)
	if err != nil {
		return nil, err
	}
	req.DestPort = binary.BigEndian.Uint16(destPort)

	switch req.CMD {
	case CONNECT, UDP_ASSOCIATE:
		reply.REP = SUCCESSED
		err = srv.SendReply(client, reply)
		if err != nil {
			return nil, err
		}
	default:
		reply.REP = COMMAND_NOT_SUPPORTED
		err = srv.SendReply(client, reply)
		if err != nil {
			return nil, err
		}

		return nil, &CMDError{req.CMD}
	}

	return req, nil
}

// IsAllowNoAuthRequired  is server enable NO_AUTHENTICATION_REQUIRED method.
// If enabled return true or the server don no Authenticator return true.
// Otherwise return false.
func (srv *Server) IsAllowNoAuthRequired() bool {
	if len(srv.Authenticators) == 0 {
		return true
	}
	for method := range srv.Authenticators {
		if method == NO_AUTHENTICATION_REQUIRED {
			return true
		}
	}
	return false
}

var errUnknowNetwork = errors.New("server unknown network")

func (srv *Server) establish(req *Request) (dest net.Conn, err error) {
	switch req.CMD {
	case CONNECT:
		dest, err = net.Dial("tcp", req.Address())
	case UDP_ASSOCIATE:
		dest, err = net.Dial("udp", req.Address())
	default:
		dest, err = nil, errUnknowNetwork
	}
	return
}

var errErrorATPE = errors.New("socks4 server bind address type should be ipv4")

// SendReply The server send socks protocol reply to client
func (srv *Server) SendReply(out io.Writer, r *Reply) error {
	var reply []byte
	var err error
	if r.VER == Version4 {
		if r.ATYPE != IPV4_ADDRESS {
			return errErrorATPE
		}
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

//// MethodSelector select authentication method and reply to client.
//type MethodSelector interface {
//	MethodSelector(methods []CMD, client io.Writer) error
//}

var errNoMethodAvailable = errors.New("there is no method available")

// MethodSelect select authentication method and reply to client.
// select NO_AUTHENTICATION_REQUIRED method if client provide 0x00 and
// server provides nothing or provides NO_AUTHENTICATION_REQUIRED.
func (srv *Server) MethodSelect(methods []CMD, client net.Conn) error {
	//Select method to authenticate, then send selected method to client.
	for _, method := range methods {
		//Preferred to use NO_AUTHENTICATION_REQUIRED method
		if method == NO_AUTHENTICATION_REQUIRED && srv.IsAllowNoAuthRequired() {
			reply := []byte{Version5, NO_AUTHENTICATION_REQUIRED}
			_, err := client.Write(reply)
			if err != nil {
				return err
			}
			return nil
		}
		for m := range srv.Authenticators {
			//Select the first matched method to authenticate
			if m == method {
				reply := []byte{Version5, USERNAME_PASSWORD}
				_, err := client.Write(reply)
				if err != nil {
					return err
				}
				return srv.Authenticators[m].Authenticate(client, client)
			}
		}
	}

	//There are no Methods can use
	reply := []byte{Version5, NO_ACCEPTABLE_METHODS}
	_, err := client.Write(reply)
	if err != nil {
		return err
	}
	return errNoMethodAvailable
}

func (srv *Server) logf() func(format string, args ...interface{}) {
	if srv.ErrorLog == nil {
		return log.Printf
	}
	return srv.ErrorLog.Printf
}
