package socks5

import (
	"net"
	"testing"
)

var addressTests = []struct {
	*Address
	String string
	Bytes  []byte
}{
	// ipv4
	{
		&Address{net.IPv4(127, 0, 0, 1).To4(), IPV4_ADDRESS, 1080},
		"127.0.0.1:1080",
		[]byte{0x01, 127, 0, 0, 1, 0x04, 0x38},
	},
	{
		&Address{net.IPv4(172, 16, 1, 1).To4(), IPV4_ADDRESS, 1080},
		"172.16.1.1:1080",
		[]byte{0x01, 172, 16, 1, 1, 0x04, 0x38},
	},
	{
		&Address{net.IPv4(192, 168, 1, 1).To4(), IPV4_ADDRESS, 1080},
		"192.168.1.1:1080",
		[]byte{0x01, 192, 168, 1, 1, 0x04, 0x38},
	},
	{
		&Address{net.IPv4(0, 0, 0, 0).To4(), IPV4_ADDRESS, 1080},
		"0.0.0.0:1080",
		[]byte{0x01, 0, 0, 0, 0, 0x04, 0x38},
	},
	// ipv6
	{
		&Address{net.IPv6zero, IPV6_ADDRESS, 1080},
		"[::]:1080",
		[]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x38},
	},
	{&Address{net.IP{0x20, 0x01, 0x48, 0x60, 0, 0, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x68}, IPV6_ADDRESS, 1080},
		"[2001:4860:0:2001::68]:1080",
		[]byte{0x01, 0x20, 0x01, 0x48, 0x60, 0, 0, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x68, 0x04, 0x38},
	},
	// domain name
	{
		&Address{[]byte("localhost"), DOMAINNAME, 1080},
		"localhost:1080",
		[]byte{},
	},
}

func TestAddress_String(t *testing.T) {
	for _, a := range addressTests {
		if a.Address.String() != a.String {
			t.Errorf("get: %s, want: %s", a.Address.String(), a.String)
		}
	}
}
