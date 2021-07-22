package socks5

import (
	"log"
	"net/http"
	"testing"
)

func TestClient_UDPForward(t *testing.T) {
	c := Client{
		ProxyAddr: "172.16.1.28:1080",
		TimeOut:   0,
		Auth: map[METHOD]Authenticator{USERNAME_PASSWORD: &UserPasswd{
			username: "admin",
			passwrod: "123456",
		}},
	}

	local := "127.0.0.1:19999"

	udp, err := c.UDPForward(local)
	if err != nil {
		log.Println(err)
		return
	}

	dest, _ := ParseAddress("127.0.0.1:9190")
	data, err := PackUDPData(dest, []byte("hello"))
	if err != nil {
		t.Error(err)
	}

	udp.Write(data)
}

func TestClient_Connect(t *testing.T) {
	c := Client{
		ProxyAddr: "172.16.1.28:1080",
		Auth: map[METHOD]Authenticator{
			USERNAME_PASSWORD: &UserPasswd{
				username: "admin",
				passwrod: "123456",
			},
			NO_AUTHENTICATION_REQUIRED: &NoAuth{},
		},
	}

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
}
