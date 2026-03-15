package holepunch

import "net"

func listenTestUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
}
