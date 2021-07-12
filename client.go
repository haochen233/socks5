package socks5

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

// Client defines parameters for running socks client.
type Client struct {
	// in the form "host:port". If empty, ":1080" (port 1080) is used.
	ProxyAddr string

	// method mapping to the authenticator
	Auth map[METHOD]interface{}

	// Generate by Server.Addr field. For Server internal use only.
	bindAddr *Address

	// ErrorLog specifics an options logger for errors accepting
	// If nil, logging is done via log package's standard logger.
	ErrorLog *log.Logger

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

// Set store username and password
func (m *PwdStore) Set(username string, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.User = username
	m.Password = password
	return nil
}

// NewSimpleClient simple create a client
func NewSimpleClient(proxyAddr string) *Client {
	return &Client{
		ProxyAddr: proxyAddr,
	}
}

// DialTCP when command is CONNECT and BIND,use tcp dail
// return a TCPConn
func (clt *Client) DialTCP(request *Request) *net.TCPConn {
	if request.CMD == UDP_ASSOCIATE {
		clt.logf()("command should not be udp_associate")
		return nil
	}
	conn, err := clt.handShake(request)
	if err != nil {
		clt.logf()(err.Error())
		return nil
	}
	if tcpConn, ok := conn.(*net.TCPConn); !ok {
		conn.Close()
		clt.logf()("conn should be TCP conn")
		return nil
	} else {
		return tcpConn
	}
}

// handShake socks protocol handshake process
func (clt *Client) handShake(request *Request) (conn net.Conn, err error) {
	proxyTCPConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if request.VER == Version5 {
		conn, err = clt.handShake5(request, proxyTCPConn)
	} else if request.VER == Version4 {
		conn, err = clt.handShake4(request, proxyTCPConn)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// handShake5 Socks 5 version of the connection handshake
func (clt *Client) handShake5(request *Request, proxyTCPConn net.Conn) (net.Conn, error) {
	err := clt.authentication(proxyTCPConn)
	if err != nil {
		return proxyTCPConn, err
	}
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return proxyTCPConn, err
	}
	// The SOCKS request is formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := proxyTCPConn.Write(append([]byte{request.VER, request.CMD, request.RSV}, destAddrByte...)); err != nil {
		return proxyTCPConn, err
	}
	// reply formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	reply := &Reply{}
	tmp, err := ReadNBytes(proxyTCPConn, 3)
	if err != nil {
		return proxyTCPConn, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
	}
	reply.VER, reply.REP, reply.RSV = tmp[0], tmp[1], tmp[2]
	if reply.VER != Version5 {
		return proxyTCPConn, fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
	}
	// read address
	serverBoundAddr, _, err := readAddress(proxyTCPConn, request.VER)
	if err != nil {
		return proxyTCPConn, fmt.Errorf("failed to get reply address, %v", err)
	}
	reply.Address = serverBoundAddr
	if reply.REP != SUCCESSED {
		return proxyTCPConn, errors.New("host unreachable")
	}
	// UDP_ASSOCIATE also need to
	if request.CMD == UDP_ASSOCIATE {
		serverBoundUDPAddr, err := net.ResolveUDPAddr("udp", reply.Address.String())
		if err != nil {
			return proxyTCPConn, err
		}
		// Get local UDP addr
		localTCPAddr := proxyTCPConn.LocalAddr().(*net.TCPAddr)
		localUDPAddr := &net.UDPAddr{
			IP:   localTCPAddr.IP,
			Port: localTCPAddr.Port,
			Zone: localTCPAddr.Zone,
		}
		// Get UDP Conn
		proxyUDPConn, err := net.DialUDP("udp", localUDPAddr, serverBoundUDPAddr)
		if err != nil {
			return proxyTCPConn, err
		}
		// TCP conn are no longer needed,close
		proxyTCPConn.Close()
		return proxyUDPConn, nil
	}
	return proxyTCPConn, nil
}

// authentication
func (clt *Client) authentication(proxyConn net.Conn) error {
	var methods []byte
	methods = append(methods, NO_AUTHENTICATION_REQUIRED)
	if clt.Auth != nil {
		methods = append(methods, USERNAME_PASSWORD)
	}
	// The client connects to the server, and sends a version identifier/method selection message:
	//    +----+----------+----------+
	//    |VER | NMETHODS | METHODS  |
	//    +----+----------+----------+
	//    | 1  |    1     | 1 to 255 |
	//    +----+----------+----------+
	_, err := proxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return nil
	}
	//Get reply, a METHOD selection message:
	//    +----+--------+
	//    |VER | METHOD |
	//    +----+--------+
	//    | 1  |   1    |
	//    +----+--------+
	reply, err := ReadNBytes(proxyConn, 2)
	if err != nil {
		return err
	}
	if reply[0] != Version5 {
		return &VersionError{reply[0]}
	}
	// Currently only USERNAME_PASSWORD and NO_AUTHENTICATION_REQUIRED authentication modes are supported
	if (reply[1] != USERNAME_PASSWORD) && (reply[1] != NO_AUTHENTICATION_REQUIRED) {
		return &MethodError{reply[1]}
	}
	// USERNAME_PASSWORD authentication modes
	if reply[1] == USERNAME_PASSWORD {
		err = clt.userPassAuthentication(proxyConn)
		if err != nil {
			return err
		}
	}
	return nil
}

//userPassAuthentication Username/Password Authentication for SOCKS V5
func (clt *Client) userPassAuthentication(proxyConn net.Conn) (err error) {
	var user, pass string
	switch value := clt.Auth[USERNAME_PASSWORD].(type) {
	case *PwdStore:
		user = value.User
		pass = value.Password
	}
	//This begins with the client producing a Username/Password request:
	//    +----+------+----------+------+----------+
	//    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	//    +----+------+----------+------+----------+
	//    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	//    +----+------+----------+------+----------+
	_, err = proxyConn.Write(append(append(append([]byte{0x01, byte(len(user))}, []byte(user)...), byte(len(pass))), []byte(pass)...))
	if err != nil {
		return err
	}
	//Get reply, the following response:

	//    +----+--------+
	//    |VER | STATUS |
	//    +----+--------+
	//    | 1  |   1    |
	//    +----+--------+
	tmp, err := ReadNBytes(proxyConn, 2)
	if err != nil {
		return err
	}
	if tmp[0] != 0x01 {
		return errors.New("not support method")
	}
	if tmp[1] != SUCCESSED {
		return errors.New("user authentication failed")
	}
	return
}

// handShake4 Socks 4 version of the connection handshake
func (clt *Client) handShake4(request *Request, proxyConn net.Conn) (net.Conn, error) {
	switch request.CMD {
	case CONNECT:
		destAddrByte, err := request.Address.Bytes(Version4)
		if err != nil {
			return proxyConn, err
		}
		// The client connects to the SOCKS server and sends a CONNECT request when it wants to establish a connection to an application server.
		// The client includes in the request packet the IP address and the port number of the destination host, and userid, in the following format.
		//    +----+----+----+----+----+----+----+----+----+----+....+----+
		//    | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		//    +----+----+----+----+----+----+----+----+----+----+....+----+
		//      1    1      2              4           variable       1
		if _, err := proxyConn.Write(append([]byte{request.VER, request.CMD}, destAddrByte...)); err != nil {
			return proxyConn, err
		}
		// A reply packet is sent to the client when this connection is established,or when the request is rejected or the operation fails.
		//    +----+----+----+----+----+----+----+----+
		//    | VN | CD | DSTPORT |      DSTIP        |
		//    +----+----+----+----+----+----+----+----+
		//       1    1      2              4
		tmp, err := ReadNBytes(proxyConn, 2)
		if err != nil {
			return proxyConn, fmt.Errorf("failed to get reply version and command, %v", err)
		}
		if tmp[0] != 0 {
			return proxyConn, fmt.Errorf("response VN wrong[%d]", tmp[0])
		}
		if tmp[1] != Granted {
			return proxyConn, errors.New("host unreachable")
		}
		// Read address
		_, _, err = readAddress(proxyConn, request.VER)
		if err != nil {
			return nil, fmt.Errorf("failed to get reply address, %v", err)
		}
		return proxyConn, nil
	case BIND:
		return proxyConn, fmt.Errorf("temporarily does not support the cmmand bind")
	default:
		return proxyConn, fmt.Errorf("does not support the cmmand %s", cmd2Str[request.CMD])
	}
}

// DialUDP when command is UDP_ASSOCIATE,use UDP dail
// return a UDPConn
func (clt *Client) DialUDP(request *Request) *net.UDPConn {
	if request.CMD != UDP_ASSOCIATE {
		clt.logf()("command should be udp_associate")
		return nil
	}
	conn, err := clt.handShake(request)
	if err != nil {
		clt.logf()(err.Error())
		return nil
	}
	if udpConn, ok := conn.(*net.UDPConn); !ok {
		conn.Close()
		clt.logf()("conn should be TCP conn")
		return nil
	} else {
		return udpConn
	}
}

// logf Logging is done using the client's errorlog
func (clt *Client) logf() func(format string, args ...interface{}) {
	if clt.ErrorLog == nil {
		return log.Printf
	}
	return clt.ErrorLog.Printf
}
