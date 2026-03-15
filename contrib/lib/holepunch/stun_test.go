package holepunch

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildSTUNResponse(txID [12]byte, ip net.IP, port int, useXOR bool) []byte {
	var attrType uint16
	var attrValue []byte

	if useXOR {
		attrType = stunAttrXORMapped
		if len(ip) == 4 || ip.To4() != nil {
			ip4 := ip.To4()
			attrValue = make([]byte, 8)
			attrValue[1] = 0x01 // IPv4
			xport := uint16(port) ^ uint16(stunMagicCookie>>16)
			binary.BigEndian.PutUint16(attrValue[2:4], xport)
			xip := binary.BigEndian.Uint32(ip4) ^ stunMagicCookie
			binary.BigEndian.PutUint32(attrValue[4:8], xip)
		} else {
			attrValue = make([]byte, 20)
			attrValue[1] = 0x02 // IPv6
			xport := uint16(port) ^ uint16(stunMagicCookie>>16)
			binary.BigEndian.PutUint16(attrValue[2:4], xport)
			var xorKey [16]byte
			binary.BigEndian.PutUint32(xorKey[0:4], stunMagicCookie)
			copy(xorKey[4:16], txID[:])
			for i := 0; i < 16; i++ {
				attrValue[4+i] = ip[i] ^ xorKey[i]
			}
		}
	} else {
		attrType = stunAttrMapped
		if len(ip) == 4 || ip.To4() != nil {
			ip4 := ip.To4()
			attrValue = make([]byte, 8)
			attrValue[1] = 0x01
			binary.BigEndian.PutUint16(attrValue[2:4], uint16(port))
			copy(attrValue[4:8], ip4)
		} else {
			attrValue = make([]byte, 20)
			attrValue[1] = 0x02
			binary.BigEndian.PutUint16(attrValue[2:4], uint16(port))
			copy(attrValue[4:20], ip)
		}
	}

	// Build attribute TLV.
	attr := make([]byte, 4+len(attrValue))
	binary.BigEndian.PutUint16(attr[0:2], attrType)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(attrValue)))
	copy(attr[4:], attrValue)

	// Build STUN header.
	resp := make([]byte, stunHeaderSize+len(attr))
	binary.BigEndian.PutUint16(resp[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])
	copy(resp[stunHeaderSize:], attr)
	return resp
}

func TestParseXORMappedAddressIPv4(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	wantIP := net.IPv4(203, 0, 113, 42).To4()
	wantPort := 54321

	// Build XOR-MAPPED-ADDRESS attribute value.
	value := make([]byte, 8)
	value[1] = 0x01
	xport := uint16(wantPort) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(value[2:4], xport)
	xip := binary.BigEndian.Uint32(wantIP) ^ stunMagicCookie
	binary.BigEndian.PutUint32(value[4:8], xip)

	result, err := parseXORMappedAddress(value, txID)
	if err != nil {
		t.Fatalf("parseXORMappedAddress: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestParseXORMappedAddressIPv6(t *testing.T) {
	txID := [12]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	wantIP := net.ParseIP("2001:db8::1")
	wantPort := 9999

	value := make([]byte, 20)
	value[1] = 0x02
	xport := uint16(wantPort) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(value[2:4], xport)
	var xorKey [16]byte
	binary.BigEndian.PutUint32(xorKey[0:4], stunMagicCookie)
	copy(xorKey[4:16], txID[:])
	for i := 0; i < 16; i++ {
		value[4+i] = wantIP[i] ^ xorKey[i]
	}

	result, err := parseXORMappedAddress(value, txID)
	if err != nil {
		t.Fatalf("parseXORMappedAddress: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestParseMappedAddressIPv4(t *testing.T) {
	wantIP := net.IPv4(192, 168, 1, 100).To4()
	wantPort := 12345

	value := make([]byte, 8)
	value[1] = 0x01
	binary.BigEndian.PutUint16(value[2:4], uint16(wantPort))
	copy(value[4:8], wantIP)

	result, err := parseMappedAddress(value)
	if err != nil {
		t.Fatalf("parseMappedAddress: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestParseMappedAddressIPv6(t *testing.T) {
	wantIP := net.ParseIP("fe80::1")
	wantPort := 443

	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(value[2:4], uint16(wantPort))
	copy(value[4:20], wantIP)

	result, err := parseMappedAddress(value)
	if err != nil {
		t.Fatalf("parseMappedAddress: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestParseSTUNAttributesXORPreferred(t *testing.T) {
	// Build attributes with both MAPPED and XOR-MAPPED. XOR should be returned.
	txID := [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	mappedIP := net.IPv4(10, 0, 0, 1).To4()
	xorIP := net.IPv4(203, 0, 113, 1).To4()
	port := 5000

	// XOR-MAPPED-ADDRESS attribute first.
	xorValue := make([]byte, 8)
	xorValue[1] = 0x01
	binary.BigEndian.PutUint16(xorValue[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	binary.BigEndian.PutUint32(xorValue[4:8], binary.BigEndian.Uint32(xorIP)^stunMagicCookie)

	var attrs []byte
	// XOR attr
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], stunAttrXORMapped)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(xorValue)))
	attrs = append(attrs, hdr...)
	attrs = append(attrs, xorValue...)

	// MAPPED attr (should be skipped since XOR comes first)
	mappedValue := make([]byte, 8)
	mappedValue[1] = 0x01
	binary.BigEndian.PutUint16(mappedValue[2:4], uint16(9999))
	copy(mappedValue[4:8], mappedIP)
	binary.BigEndian.PutUint16(hdr[0:2], stunAttrMapped)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(mappedValue)))
	attrs = append(attrs, hdr...)
	attrs = append(attrs, mappedValue...)

	result, err := parseSTUNAttributes(attrs, txID)
	if err != nil {
		t.Fatalf("parseSTUNAttributes: %v", err)
	}
	if !result.IP.Equal(xorIP) {
		t.Errorf("IP = %v, want %v (XOR should be preferred)", result.IP, xorIP)
	}
}

func TestParseSTUNAttributesMappedFallback(t *testing.T) {
	txID := [12]byte{}
	wantIP := net.IPv4(10, 0, 0, 1).To4()
	wantPort := 7777

	mappedValue := make([]byte, 8)
	mappedValue[1] = 0x01
	binary.BigEndian.PutUint16(mappedValue[2:4], uint16(wantPort))
	copy(mappedValue[4:8], wantIP)

	var attrs []byte
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], stunAttrMapped)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(mappedValue)))
	attrs = append(attrs, hdr...)
	attrs = append(attrs, mappedValue...)

	result, err := parseSTUNAttributes(attrs, txID)
	if err != nil {
		t.Fatalf("parseSTUNAttributes: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestParseSTUNAttributesNoAddress(t *testing.T) {
	// Unknown attribute type — should return error.
	attrs := make([]byte, 8)
	binary.BigEndian.PutUint16(attrs[0:2], 0x9999) // unknown
	binary.BigEndian.PutUint16(attrs[2:4], 4)

	_, err := parseSTUNAttributes(attrs, [12]byte{})
	if err == nil {
		t.Fatal("expected error for missing MAPPED-ADDRESS")
	}
}

func TestSTUNResultString(t *testing.T) {
	r := STUNResult{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
	want := "1.2.3.4:5678"
	if got := r.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSTUNResultStringIPv6(t *testing.T) {
	r := STUNResult{IP: net.ParseIP("2001:db8::1"), Port: 443}
	want := "[2001:db8::1]:443"
	if got := r.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestQuerySTUNRoundTrip(t *testing.T) {
	// Spin up a fake STUN server that echoes back a XOR-MAPPED-ADDRESS.
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	wantIP := net.IPv4(85, 1, 2, 3).To4()
	wantPort := 40000

	// Server goroutine: read request, send XOR-MAPPED-ADDRESS response.
	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			return
		}
		// Extract transaction ID from request.
		var txID [12]byte
		copy(txID[:], buf[8:20])

		resp := buildSTUNResponse(txID, wantIP, wantPort, true)
		serverConn.WriteToUDP(resp, clientAddr) //nolint:errcheck
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	result, err := QuerySTUN(clientConn, serverAddr, 2e9) // 2s timeout
	if err != nil {
		t.Fatalf("QuerySTUN: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestQuerySTUNMappedFallback(t *testing.T) {
	// Fake STUN server returning MAPPED-ADDRESS (not XOR).
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	wantIP := net.IPv4(10, 20, 30, 40).To4()
	wantPort := 55555

	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			return
		}
		var txID [12]byte
		copy(txID[:], buf[8:20])
		resp := buildSTUNResponse(txID, wantIP, wantPort, false)
		serverConn.WriteToUDP(resp, clientAddr) //nolint:errcheck
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	result, err := QuerySTUN(clientConn, serverAddr, 2e9)
	if err != nil {
		t.Fatalf("QuerySTUN: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

func TestDiscoverPublicAddrTriesServers(t *testing.T) {
	// First server: no response (will timeout). Second server: valid response.
	// Use a port that nothing is listening on for the "dead" server.
	deadConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen dead: %v", err)
	}
	deadAddr := deadConn.LocalAddr().String()
	deadConn.Close() // close immediately so nothing responds

	liveConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen live: %v", err)
	}
	defer liveConn.Close()
	liveAddr := liveConn.LocalAddr().String()

	wantIP := net.IPv4(1, 2, 3, 4).To4()
	wantPort := 11111

	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, err := liveConn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			return
		}
		var txID [12]byte
		copy(txID[:], buf[8:20])
		resp := buildSTUNResponse(txID, wantIP, wantPort, true)
		liveConn.WriteToUDP(resp, clientAddr) //nolint:errcheck
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	// Short timeout so the dead server fails quickly.
	result, err := DiscoverPublicAddr(clientConn, []string{deadAddr, liveAddr}, 200e6) // 200ms
	if err != nil {
		t.Fatalf("DiscoverPublicAddr: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestXORMappedTooShort(t *testing.T) {
	_, err := parseXORMappedAddress([]byte{0, 1, 0}, [12]byte{})
	if err == nil {
		t.Fatal("expected error for short XOR-MAPPED-ADDRESS")
	}
}

func TestMappedAddressTooShort(t *testing.T) {
	_, err := parseMappedAddress([]byte{0, 1, 0})
	if err == nil {
		t.Fatal("expected error for short MAPPED-ADDRESS")
	}
}

// TestDualStackSTUN verifies that a dual-stack (udp/[::]) socket can
// send to and receive from an IPv4 STUN server.
func TestDualStackSTUN(t *testing.T) {
	// Fake STUN server on IPv4 loopback.
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server (udp4): %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	wantIP := net.IPv4(85, 1, 2, 3).To4()
	wantPort := 40000

	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			t.Logf("server read error: %v (n=%d)", err, n)
			return
		}
		var txID [12]byte
		copy(txID[:], buf[8:20])
		resp := buildSTUNResponse(txID, wantIP, wantPort, true)
		serverConn.WriteToUDP(resp, clientAddr) //nolint:errcheck
	}()

	// Client on dual-stack [::] — this is what holepunch.New() creates.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("listen client (udp/[::]): %v", err)
	}
	defer clientConn.Close()
	t.Logf("client bound to %s", clientConn.LocalAddr())

	result, err := QuerySTUN(clientConn, serverAddr, 2e9)
	if err != nil {
		t.Fatalf("QuerySTUN from dual-stack to IPv4 server: %v", err)
	}
	if !result.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Port != wantPort {
		t.Errorf("Port = %d, want %d", result.Port, wantPort)
	}
}

// TestRealSTUN hits actual public STUN servers from a dual-stack socket.
// Skip in CI / short mode.
func TestRealSTUN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real STUN test in short mode")
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	t.Logf("bound to %s", conn.LocalAddr())

	for _, srv := range DefaultSTUNServers {
		result, err := QuerySTUN(conn, srv, 3e9) // 3s timeout
		if err != nil {
			t.Logf("FAIL %s: %v", srv, err)
			continue
		}
		t.Logf("OK   %s -> %s", srv, result)
		return // at least one worked
	}
	t.Fatal("all STUN servers failed from dual-stack socket")
}

func TestUnknownAddressFamily(t *testing.T) {
	value := make([]byte, 8)
	value[1] = 0x03 // unknown family
	_, err := parseXORMappedAddress(value, [12]byte{})
	if err == nil {
		t.Fatal("expected error for unknown family in XOR")
	}
	_, err = parseMappedAddress(value)
	if err == nil {
		t.Fatal("expected error for unknown family in MAPPED")
	}
}
