package socks5

import (
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"strconv"
	"testing"
)

func runLocalServer(addr string, bindIP string) {
	// create socks server.
	srv := &Server{
		// socks server listen address.
		Addr: addr,
		// UDP assocaite and bind command listen ip.
		// Don't need port, the port will automatically chosen.
		BindIP: bindIP,
		// if nil server will provide no authentication required method.
		Authenticators: nil,
	}

	// start listen
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func TestClient_UDPForward(t *testing.T) {
	go runLocalServer("127.0.0.1:1080", "127.0.0.1")
	c := Client{
		ProxyAddr: "127.0.0.1:1080",
		Timeout:   0,
		Auth: map[METHOD]Authenticator{
			USERNAME_PASSWORD:          &UserPasswd{Username: "admin", Password: "123456"},
			NO_AUTHENTICATION_REQUIRED: NoAuth{},
		},
	}

	local := "127.0.0.1:19999"

	_, err := c.UDPForward(local)
	if err != nil {
		log.Println(err)
		return
	}
}

func TestClient_Connect(t *testing.T) {
	go runLocalServer("127.0.0.1:1080", "127.0.0.1")
	c := Client{
		ProxyAddr: "127.0.0.1:1080",
		Auth: map[METHOD]Authenticator{
			USERNAME_PASSWORD: &UserPasswd{
				Username: "admin",
				Password: "123456",
			},
			NO_AUTHENTICATION_REQUIRED: &NoAuth{},
		},
	}

	// socks4 connect
	dest := "www.baidu.com:80"
	conn, err := c.Connect(Version4, dest)
	if err != nil {
		t.Fatal(err)
		return
	}

	// send http Get request via socks proxy.
	req, err := http.NewRequest("GET", "http://www.baidu.com", nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	err = req.WriteProxy(conn)
	if err != nil {
		t.Fatal(err)
	}

	// socks5 connect
	conn5, err := c.Connect(Version5, dest)
	if err != nil {
		t.Fatal(err)
	}

	err = req.WriteProxy(conn5)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClient_Bind(t *testing.T) {
	socksServerAddr := "127.0.0.1:1080"
	socksServerBindIP := "127.0.0.1"
	go runLocalServer(socksServerAddr, socksServerBindIP)

	destServerAddr := "127.0.0.1:9000"
	destServerLaddr := "127.0.0.1:9001"
	go runDestServer(destServerAddr, destServerLaddr)

	c := Client{
		ProxyAddr: socksServerAddr,
		Auth: map[METHOD]Authenticator{
			USERNAME_PASSWORD: &UserPasswd{
				Username: "admin",
				Password: "123456",
			},
			NO_AUTHENTICATION_REQUIRED: &NoAuth{},
		},
	}

	// connect
	conn1, err := c.Connect(5, destServerAddr)
	if err != nil {
		t.Fatal(err)
	}

	// bind
	bindAddr, errors, conn, err := c.Bind(4, destServerLaddr)
	if err != nil {
		t.Fatal(err)
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, bindAddr.Port)
	conn1.Write(append(bindAddr.Addr, port...))

	err = <-errors
	if err != nil {
		t.Fatal(err)
	}

	// success
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	if string(buf) != "hi" {
		t.Errorf("want hi but get %s", string(buf))
	}
}

// bindAddr is tcp listen address
// laddr is which address connect to socks bind server.
func runDestServer(bindAddr, laddr string) {
	ListenAddr, _ := net.ResolveTCPAddr("tcp", bindAddr)
	ln, err := net.ListenTCP("tcp", ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	localAddr, _ := net.ResolveTCPAddr("tcp", laddr)

	conn, err := ln.AcceptTCP()
	if err != nil {
		log.Fatal(err)
	}

	addr := make([]byte, 6)
	_, err = conn.Read(addr)
	if err != nil {
		log.Fatal(err)
	}

	ip := addr[:4]
	portBytes := addr[4:]

	IP := net.IPv4(ip[0], ip[1], ip[2], ip[3])
	port := binary.BigEndian.Uint16(portBytes)
	portStr := strconv.Itoa(int(port))

	address := net.JoinHostPort(IP.To4().String(), portStr)
	raddr, _ := net.ResolveTCPAddr("tcp", address)

	tcpConn, err := net.DialTCP("tcp", localAddr, raddr)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	_, err = tcpConn.Read(buf)
	if err != nil {
		log.Fatal()
	}

	_, err = tcpConn.Write([]byte("hi"))
	if err != nil {
		log.Fatal(err)
	}
}
