package socks5

import (
	"log"
	"testing"
)

func TestGetRandomPort(t *testing.T) {
	// right tcp network
	for i := 0; i < 50; i++ {
		err, port := GetRandomPort("tcp")
		if err != nil {
			t.Error(err)
		}
		log.Printf("get tcp port: %d", port)
	}

	// right udp network
	for i := 0; i < 50; i++ {
		err, port := GetRandomPort("udp")
		if err != nil {
			t.Error(err)
		}
		log.Printf("get udp port: %d", port)
	}
}

func TestGetRandomPort_Err(t *testing.T) {
	err, _ := GetRandomPort("kcp")
	if err.Error() != "unknown network type kcp" {
		t.Error(err)
	}
}