package socks5

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Client defines parameters for running socks client.
type Client struct {
	// in the form "host:port". If empty, ":1080" (port 1080) is used.
	ProxyAddr string

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, reading the response body.
	//
	// A Timeout of zero means no timeout.
	//
	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	//
	TimeOut time.Duration

	// method mapping to the authenticator
	Auth map[METHOD]interface{}

	// Generate by Server.Addr field. For Server internal use only.
	bindAddr *Address

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

// TCPConnect socks TCP connect,get a tcp connect and reply addr
func (clt *Client) TCPConnect(request *Request) (conn net.Conn, replyAddr *Address) {
	proxyTCPConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		clt.logf()(err.Error())
		return nil, nil
	}
	if clt.TimeOut != 0 {
		err = proxyTCPConn.SetDeadline(time.Now().Add(clt.TimeOut))
		if err != nil {
			clt.logf()(err.Error())
		}
	}
	if request.VER == Version5 {
		replyAddr, err = clt.handShake5(request, proxyTCPConn)
	} else if request.VER == Version4 {
		replyAddr, err = clt.connect4(request, proxyTCPConn)
	} else {
		err := fmt.Errorf("Version %d is not supported", request.VER)
		clt.logf()(err.Error())
	}
	if err != nil {
		proxyTCPConn.Close()
		clt.logf()(err.Error())
		return nil, nil
	}

	return proxyTCPConn, replyAddr
}

// handShake5 Socks 5 version of the connection handshake
func (clt *Client) handShake5(request *Request, proxyTCPConn net.Conn) (*Address, error) {
	err := clt.authentication(proxyTCPConn)
	if err != nil {
		return nil, err
	}
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return nil, err
	}
	// The SOCKS request is formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := proxyTCPConn.Write(append([]byte{request.VER, request.CMD, request.RSV}, destAddrByte...)); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
	}
	reply.VER, reply.REP, reply.RSV = tmp[0], tmp[1], tmp[2]
	if reply.VER != Version5 {
		return nil, fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
	}
	// read address
	serverBoundAddr, _, err := readAddress(proxyTCPConn, request.VER)
	if err != nil {
		return nil, fmt.Errorf("failed to get reply address, %v", err)
	}
	reply.Address = serverBoundAddr
	if reply.REP != SUCCESSED {
		return nil, errors.New("server refuse client request")
	}
	return reply.Address, nil
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
func (clt *Client) connect4(request *Request, proxyConn net.Conn) (*Address, error) {
	destAddrByte, err := request.Address.Bytes(Version4)
	if err != nil {
		return nil, err
	}
	// The client connects to the SOCKS server and sends a CONNECT request when it wants to establish a connection to an application server.
	// The client includes in the request packet the IP address and the port number of the destination host, and userid, in the following format.
	//    +----+----+----+----+----+----+----+----+----+----+....+----+
	//    | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	//    +----+----+----+----+----+----+----+----+----+----+....+----+
	//      1    1      2              4           variable       1
	if _, err := proxyConn.Write(append([]byte{request.VER, request.CMD}, destAddrByte...)); err != nil {
		return nil, err
	}
	// A reply packet is sent to the client when this connection is established,or when the request is rejected or the operation fails.
	//    +----+----+----+----+----+----+----+----+
	//    | VN | CD | DSTPORT |      DSTIP        |
	//    +----+----+----+----+----+----+----+----+
	//       1    1      2              4
	tmp, err := ReadNBytes(proxyConn, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to get reply version and command, %v", err)
	}
	if tmp[0] != 0 {
		return nil, fmt.Errorf("response VN wrong[%d]", tmp[0])
	}
	if tmp[1] != Granted {
		return nil, errors.New("server refuse client request")
	}
	// Read address
	replyAddr, _, err := readAddress(proxyConn, request.VER)
	if err != nil {
		return nil, fmt.Errorf("failed to get reply address, %v", err)
	}
	return replyAddr, nil
}

// UDPForward socks UDP forward, get a udp connect
func (clt *Client) UDPForward(request *Request) *net.UDPConn {
	if request.CMD != UDP_ASSOCIATE {
		clt.logf()("command should be udp_associate")
		return nil
	}
	proxyTCPConn, udpserverBoundAddr := clt.TCPConnect(request)
	if proxyTCPConn == nil {
		clt.logf()("TCP conn failure")
		return nil
	}
	// TCP conn are no longer needed,close
	defer proxyTCPConn.Close()
	serverBoundUDPAddr, err := net.ResolveUDPAddr("udp", udpserverBoundAddr.String())
	if err != nil {
		clt.logf()(err.Error())
		return nil
	}
	// Get local UDP addr
	localTCPAddr := proxyTCPConn.LocalAddr().(*net.TCPAddr)
	localUDPAddr := &net.UDPAddr{
		IP:   request.Addr,
		Port: int(request.Port),
		Zone: localTCPAddr.Zone,
	}
	// Get UDP Conn
	proxyUDPConn, err := net.DialUDP("udp", localUDPAddr, serverBoundUDPAddr)
	if err != nil {
		clt.logf()(err.Error())
		return nil
	}
	if clt.TimeOut != 0 {
		err = proxyUDPConn.SetDeadline(time.Now().Add(clt.TimeOut))
		if err != nil {
			clt.logf()(err.Error())
		}
	}
	return proxyUDPConn
}

//Bind socks bind cmd, get socks serve Listening bind addr,second time reply err,bind connect
func (clt *Client) Bind(ver VER, destAddr *Address) (*Address, <-chan error, net.Conn) {
	request := &Request{
		Address: destAddr,
		CMD:     BIND,
		VER:     ver,
	}
	proxyBindConn, err := net.Dial("tcp", clt.ProxyAddr)
	if err != nil {
		clt.logf()(err.Error())
		return nil, nil, nil
	}
	if clt.TimeOut != 0 {
		err = proxyBindConn.SetDeadline(time.Now().Add(clt.TimeOut))
		if err != nil {
			clt.logf()(err.Error())
		}
	}
	switch request.VER {
	case Version4:
		serverBoundAddr, secondAcceptance, proxyBindConn, err := clt.bind4(request, proxyBindConn)
		if err != nil {
			proxyBindConn.Close()
			clt.logf()(err.Error())
			return serverBoundAddr, secondAcceptance, nil
		}
		return serverBoundAddr, secondAcceptance, proxyBindConn
	case Version5:
		serverBoundAddr, secondAcceptance, proxyBindConn, err := clt.bind5(request, proxyBindConn)
		if err != nil {
			proxyBindConn.Close()
			clt.logf()(err.Error())
			return serverBoundAddr, secondAcceptance, nil
		}
		return serverBoundAddr, secondAcceptance, proxyBindConn
	default:
		err := fmt.Errorf("Version %d is not supported", request.VER)
		clt.logf()(err.Error())
		return nil, nil, nil
	}
}

// bind5 socks5 bind
func (clt *Client) bind5(request *Request, proxyBindConn net.Conn) (*Address, <-chan error, net.Conn, error) {
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return nil, nil, proxyBindConn, err
	}
	// The SOCKS request is formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := proxyBindConn.Write(append([]byte{request.VER, request.CMD, request.RSV}, destAddrByte...)); err != nil {
		return nil, nil, proxyBindConn, err
	}
	// reply formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	reply := &Reply{}
	tmp, err := ReadNBytes(proxyBindConn, 3)
	if err != nil {
		return nil, nil, proxyBindConn, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
	}
	reply.VER, reply.REP, reply.RSV = tmp[0], tmp[1], tmp[2]
	if reply.VER != Version5 {
		return nil, nil, proxyBindConn, fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
	}
	// read address
	serverBoundAddr, _, err := readAddress(proxyBindConn, request.VER)
	if err != nil {
		return nil, nil, proxyBindConn, fmt.Errorf("failed to get reply address, %v", err)
	}
	reply.Address = serverBoundAddr
	if reply.REP != SUCCESSED {
		return nil, nil, proxyBindConn, errors.New("server refuse client request,when first time reply")
	}
	errorChan := make(chan error)
	go func() {
		reply2 := &Reply{}
		// The second time reply formed as follows:
		//    +----+-----+-------+------+----------+----------+
		//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		//    +----+-----+-------+------+----------+----------+
		//    | 1  |  1  | X'00' |  1   | Variable |    2     |
		//    +----+-----+-------+------+----------+----------+
		tmp, err := ReadNBytes(proxyBindConn, 3)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply version and command and reserved, %v", err)
			proxyBindConn.Close()
		}
		reply2.VER, reply2.REP, reply2.RSV = tmp[0], tmp[1], tmp[2]
		if reply2.VER != Version5 {
			errorChan <- fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
			proxyBindConn.Close()
		}
		// read address
		serverBoundAddr, _, err := readAddress(proxyBindConn, request.VER)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply address, %v", err)
			proxyBindConn.Close()
		}
		reply2.Address = serverBoundAddr
		if reply2.REP != SUCCESSED {
			errorChan <- errors.New("server refuse client request,when second time reply")
			proxyBindConn.Close()
		}
		errorChan <- nil
	}()
	return serverBoundAddr, errorChan, proxyBindConn, err
}

// bind4 socks4 bind
func (clt *Client) bind4(request *Request, proxyBindConn net.Conn) (*Address, <-chan error, net.Conn, error) {
	destAddrByte, err := request.Address.Bytes(Version4)
	if err != nil {
		return nil, nil, proxyBindConn, err
	}
	// The client connects to the SOCKS server and sends a CONNECT request when it wants to establish a connection to an application server.
	// The client includes in the request packet the IP address and the port number of the destination host, and userid, in the following format.
	//    +----+----+----+----+----+----+----+----+----+----+....+----+
	//    | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	//    +----+----+----+----+----+----+----+----+----+----+....+----+
	//      1    1      2              4           variable       1
	if _, err := proxyBindConn.Write(append([]byte{request.VER, request.CMD}, destAddrByte...)); err != nil {
		return nil, nil, proxyBindConn, err
	}
	// A reply packet is sent to the client when this connection is established,or when the request is rejected or the operation fails.
	//    +----+----+----+----+----+----+----+----+
	//    | VN | CD | DSTPORT |      DSTIP        |
	//    +----+----+----+----+----+----+----+----+
	//       1    1      2              4
	tmp, err := ReadNBytes(proxyBindConn, 2)
	if err != nil {
		return nil, nil, proxyBindConn, fmt.Errorf("failed to get reply version and command, %v", err)
	}
	if tmp[0] != 0 {
		return nil, nil, proxyBindConn, fmt.Errorf("response VN wrong[%d]", tmp[0])
	}
	// Read address
	serverBoundAddr, _, err := readAddress(proxyBindConn, request.VER)
	if err != nil {
		return nil, nil, proxyBindConn, fmt.Errorf("failed to get reply address, %v", err)
	}
	if tmp[1] != Granted {
		return nil, nil, proxyBindConn, errors.New("server refuse client request,when first time reply")
	}
	errorChan := make(chan error)
	go func() {
		// A reply packet is sent to the client,or when the request is rejected or the operation fails.
		//    +----+----+----+----+----+----+----+----+
		//    | VN | CD | DSTPORT |      DSTIP        |
		//    +----+----+----+----+----+----+----+----+
		//       1    1      2              4
		tmp, err := ReadNBytes(proxyBindConn, 2)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply version and command, %v", err)
			proxyBindConn.Close()
		}
		if tmp[0] != 0 {
			errorChan <- fmt.Errorf("response VN wrong[%d]", tmp[0])
			proxyBindConn.Close()
		}
		// read address
		_, _, err = readAddress(proxyBindConn, request.VER)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply address, %v", err)
			proxyBindConn.Close()
		}

		if tmp[1] != Granted {
			errorChan <- errors.New("server refuse client request,when second time reply")
			proxyBindConn.Close()
		}
		errorChan <- nil
	}()
	return serverBoundAddr, errorChan, proxyBindConn, err
}

// logf Logging is done using the client's errorlog
func (clt *Client) logf() func(format string, args ...interface{}) {
	if clt.ErrorLog == nil {
		return log.Printf
	}
	return clt.ErrorLog.Printf
}
