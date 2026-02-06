package main

import (
	"bytes"
	"crypto/rand"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func createConnectedPair(t *testing.T) (*core.Core, *core.Core) {
	t.Helper()
	logger := log.New(os.Stderr, "", 0)
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	nodeA, err := core.New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := core.New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("tcp://localhost:0")
	listener, err := nodeA.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	peerURL, _ := url.Parse("tcp://" + listener.Addr().String())
	if err := nodeB.CallPeer(peerURL, ""); err != nil {
		t.Fatal(err)
	}

	// Wait for tree convergence
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			time.Sleep(3 * time.Second)
			return nodeA, nodeB
		}
	}
	t.Fatal("nodes did not connect")
	return nil, nil
}

func TestCoreWriteToReadFrom(t *testing.T) {
	nodeA, nodeB := createConnectedPair(t)
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Build packet: same format as core_test.go
	msgLen := 1500
	msg := make([]byte, msgLen)
	rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())

	// Echo listener on A
	done := make(chan struct{})
	go func() {
		buf := make([]byte, msgLen)
		n, from, err := nodeA.ReadFrom(buf)
		if err != nil {
			t.Error("A ReadFrom:", err)
			return
		}
		t.Logf("A received %d bytes from %v", n, from)
		// Echo back with swapped addresses
		res := make([]byte, n)
		copy(res, buf[:n])
		copy(res[8:24], buf[24:40])
		copy(res[24:40], buf[8:24])
		nodeA.WriteTo(res, from)
		done <- struct{}{}
	}()

	// Send from B
	_, err := nodeB.WriteTo(msg, nodeA.LocalAddr())
	if err != nil {
		t.Fatal("B WriteTo:", err)
	}

	// Read echo on B
	buf := make([]byte, msgLen)
	n, _, err := nodeB.ReadFrom(buf)
	if err != nil {
		t.Fatal("B ReadFrom:", err)
	}
	if !bytes.Equal(msg[40:], buf[40:n]) {
		t.Fatal("payload mismatch")
	}
	t.Log("echo verified!")
	<-done
}
