# socks5
This is a Golang implementation of the SOCKS5 protocol.   
To see in this [SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928.html).

# Features
- socks4, don't support socks4 authentication 
- sock4a 
- socks5 support.
    - Username/Password authentication.
  
# Server usage
### simple:
```go
package main

import (
  "github.com/haochen233/socks5"
)

func main() {
  srv := &socks5.Server{
    Addr: "127.0.0.1:1080",
  }

  srv.ListenAndServe()
}


```
### use memory username/password authentication:
```go
package main

import (
  "crypto/md5"

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
  srv.ListenAndServe()
}
```