# socks5
This is a Golang implementation of the SOCKS5 protocol.   
To see in this [SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928.html).

# Features
- socks4, don't support socks4 authentication 
- sock4a 
- socks5 support.
    - Username/Password authentication.

# Install
`go get "github.com/haochen233/socks5"`

# Server usage
### simple(no authentication):
```go
package main

import (
  "log"
  "github.com/haochen233/socks5"
)

func main() {
  srv := &socks5.Server{
    Addr: "127.0.0.1:1080",
  }

  err := srv.ListenAndServe()
  if err != nil {
    log.Fatal(err)
  }
}


```
### use memory username/password authentication:
```go
package main

import (
  "crypto/md5"
  "log"

  "github.com/haochen233/socks5"
)

func main() {
  // create a store.
  var userStorage socks5.UserPwdStore = socks5.NewMemeryStore(md5.New(), "secret")
  // set a pair of username/password.
  userStorage.Set("admin", "123456")

  //composite server
  srv := &socks5.Server{
    Addr: "127.0.0.1:1080",
    Authenticators: map[socks5.METHOD]socks5.Authenticator{
      socks5.USERNAME_PASSWORD: socks5.UserPwdAuth{userStorage},
    },
  }

  //start listen
  err := srv.ListenAndServe()
  if err != nil {
    log.Fatal(err)
  }
  
}
```

### Make one's own transporter to transmit data between client and remote.
```go
package main

import (
  "log"
  "net"

  "github.com/haochen233/socks5"
)

// simulate to impl socks5.Transporter interafce.
// transport encrypted data.
type cryptTransport struct {
}

func (c *cryptTransport) Transport(client net.Conn, remote net.Conn) error {
  //encrypt data and send to remote

  //decrypt data and send to client
  return nil
}

func main() {
  server := &socks5.Server{
    Addr:        "127.0.0.1:1080",
    Transporter: &cryptTransport{},
  }
  err := server.ListenAndServe()
  if err != nil {
    log.Fatal(err)
  }
}
```

# Client usage
### simple:
```go
package main

import (
	"time"

	"github.com/haochen233/socks5"
)

func main() {
	var userStorage = socks5.NewPwdStore()
	userStorage.Set("admin", "123456")
	// Get a clinet
	client := socks5.NewSimpleClient("127.0.0.1:1080")
	// Add username/password authentication
	client.Auth = map[socks5.METHOD]interface{}{socks5.USERNAME_PASSWORD: userStorage}
	// The default read-write timeout is 15 minutes
	client.TimeOut = 15 * time.Minute
	// Add the client property as follows
	//client.ErrorLog = log.Logger

	// The address of the remote host to connect to
	destAddr, err := socks5.ParseAddress("example.com:8010")
	if err != nil {
		panic(err)
	}
	// one request example,a connection to TCP,CMD is CONNECT
	request := &Request{
		Address: destAddr,
		CMD:     socks5.CONNECT,
		VER:     socks5.Version5,
	}
	tcpconn, _ := client.TCPConnect(request)
	if tcpconn == nil {
		panic("TCP conn failure")
	}
	// Write to the tcpconn
	tcpconn.Write([]byte("hello"))
	time.Sleep(time.Second)

	// one request example,a connection to TCP,CMD is BIND
	request = &Request{
		Address: destAddr,
		CMD:     socks5.CONNECT,
		VER:     socks5.Version5,
	}
	tcpconn, _ = client.TCPConnect(request)
	if tcpconn == nil {
		panic("TCP conn failure")
	}
	serverBoundAddr, secondAcceptance, proxyBindConn := client.Bind(socks5.Version5, destAddr)
	if proxyBindConn == nil {
		panic("TCP conn failure")
	}

	// FTP client sends the serverBoundAddr address information to the FTP serve via tcpconn
	serverBoundAddrByte, err := serverBoundAddr.Bytes(socks5.Version5)
	if err != nil {
		panic(err)
	}
	// ftp data
	var ftpdataByte []byte
	ftpFormatByte := append(ftpdataByte, serverBoundAddrByte...)
	tcpconn.Write(ftpFormatByte)
	// Wait for secondAcceptance channel to receive a second return message
	for data := range secondAcceptance {
		if data != nil {
			panic(data)
		} else {
			break
		}
	}
	// Write to the bind conn
	proxyBindConn.Write([]byte("hello"))
	time.Sleep(time.Second)

	//another example request, a connection to UDP,CMD is UDP_ASSOCIATE
	// The address of the localhost to send udp
	localSendUDPAddr, err := socks5.ParseAddress("192.168.1.2:8013")
	if err != nil {
		panic(err)
	}
	request = &Request{
		Address: localSendUDPAddr,
		CMD:     socks5.UDP_ASSOCIATE,
		VER:     socks5.Version5,
	}
	udpconn := client.UDPForward(request)
	if udpconn == nil {
		panic("UDP conn failure")
	}
	payload := []byte("hello")
	udpData, err := PackUDPData(destAddr, payload)
	if err != nil {
		panic(err)
	}
	// Write to the udpconn
	udpconn.Write(udpData)
	time.Sleep(time.Second)
}

```