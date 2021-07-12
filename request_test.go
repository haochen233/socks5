package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestPackUDPData(t *testing.T) {
	data := []byte("udp")
	addr := &Address{
		Addr:  net.IPv4(1, 1, 1, 1).To4(),
		ATYPE: IPV4_ADDRESS,
		Port:  1080,
	}
	udpData, err := PackUDPData(addr, data)
	if err != nil {
		t.Error(err)
	}

	if len(udpData) != 13 {
		t.Errorf("get length: %d, want length: %d", len(udpData), 13)
	}

	bytes.Equal(udpData, []byte{0x00, 0x00, 0x00, 1, 1, 1, 1, 1, 0x04, 0x38})
}

func TestUnpackUDPData(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 1, 1, 1, 1, 1, 0x04, 0x38, 'a', 'b', 'c'}
	wantAddr := net.IPv4(1, 1, 1, 1)
	wantPayload := []byte{'a', 'b', 'c'}
	wantATYPE := IPV4_ADDRESS
	var wantPort uint16 = 1080
	addr, payload, err := UnpackUDPData(data)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("want: %v get %v", wantPayload, payload)
	}

	if !addr.Addr.Equal(wantAddr) {
		t.Errorf("want: %s get %s", wantAddr.String(), addr.Addr.String())
	}

	if wantATYPE != addr.ATYPE {
		t.Errorf("want: %#x get %#x", wantATYPE, addr.ATYPE)
	}

	if addr.Port != wantPort {
		t.Errorf("want: %d get %d", wantATYPE, addr.Port)
	}
}
