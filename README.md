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