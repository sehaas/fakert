package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"

	"io/ioutil"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	yaml "gopkg.in/yaml.v3"
)

// FakeConfig stores the config
// Network is used to initilze the routing table
// Routes holds the routes for all configured destinations
type FakeConfig struct {
	Network FakeIPNet
	Routes  map[FakeIP][]FakeIP `yaml:,flow`
}

// FakeIPNet only wraps net.IPNet to provide UnmarshalYAML
type FakeIPNet struct {
	net.IPNet
}

// FakeIP represents an IPv6 address as string
// net.IP can't be used as map-key, so we use a 16-byte string
// https://stackoverflow.com/a/39249045
type FakeIP string

// UnmarshalYAML parses config string to IPv6 network
func (ip *FakeIPNet) UnmarshalYAML(value *yaml.Node) error {
	// fmt.Println("FakeIPNet", value.Value)
	_, tmp, err := net.ParseCIDR(value.Value)
	if err == nil {
		ip.IP = tmp.IP
		ip.Mask = tmp.Mask
	}
	return err
}

// UnmarshalYAML parses IPv6 string to string of bytes
func (ip *FakeIP) UnmarshalYAML(value *yaml.Node) error {
	// fmt.Println("FakeIP", value.Value)
	ipaddr := net.ParseIP(value.Value)
	if ipaddr == nil {
		return fmt.Errorf("could not parse IP address: %s", value.Value)
	}
	*ip = FakeIP(ipaddr.To16())
	return nil
}

// Use net.IP for pretty printing
func (ip FakeIP) String() string {
	return net.IP(ip).String()
}

// Use net.IP for pretty printing
func (ip FakeIPNet) String() string {
	return ip.IPNet.String()
}

func (c *FakeConfig) getConf(filename string) *FakeConfig {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalln("FakeConfig.getConf error:", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalln("FakeConfig.getConf unable to unmarshal:", err)
	}

	if c.Network.IP == nil || c.Network.Mask == nil {
		log.Fatalln("FakeConfig.getConf missing Network configuration:", c.Network)
	}

	return c
}

func main() {
	log.Printf("FakeRT Tun")
	ifacename := flag.String("iface", "fakert0", "the name of the interface")
	confname := flag.String("config", "fakert.yaml", "the name of the config file")
	flag.Parse()

	var c FakeConfig
	c.getConf(*confname)
	log.Println("config: Network", c.Network)
	for k, v := range c.Routes {
		if !c.Network.Contains(net.IP(k)) {
			log.Println("config: IP not in network range", k)
		} else {
			log.Println("config: Route", k)
			for i, h := range v {
				log.Println("config: \t Hop", i, h)
			}
		}
	}

	// setup TUN device
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = *ifacename
	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	// search device
	link, err := netlink.LinkByName(config.Name)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Found device", link.Attrs().Name, link.Type())

	// bring device up
	if e := netlink.LinkSetUp(link); e != nil {
		log.Fatal("Failed to bring interface up:", e)
	}
	network := &c.Network.IPNet
	route := &netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       network,
		LinkIndex: link.Attrs().Index,
	}

	// add route to configured network
	err = netlink.RouteAdd(route)
	if err != nil {
		log.Fatal(err)
	}

	// ready to go, handle incoming data
	for {
		packet := make([]byte, 1500)
		plen, err := ifce.Read(packet)
		if err != nil {
			log.Fatalf("Tun spluttered, Threw back %s on the tun file", err.Error())
		}

		if plen < 40 {
			log.Printf("dropped packet becase it was too small %d bytes", plen)
			continue // packet too small to be real, drop it
		}

		packetType := int(packet[6])
		destIP := FakeIP(packet[24:40])
		hops := c.Routes[destIP]
		TTL := int(packet[7])
		log.Printf("dest: %s | src: %s | TTL: %d | type: %d", destIP, FakeIP(packet[8:24]), TTL, packetType)

		// Handle ICMP Hop limit expired
		returnpacket := make([]byte, plen+8+40)
		returnpacket[0] = 0x60 // IP packet version, Thus it is 6
		// <---> Flow labels and crap like that here, leaving this as zeros
		uintbuf := new(bytes.Buffer)
		binary.Write(uintbuf, binary.BigEndian, uint16(plen+8))
		returnpacket[4] = uintbuf.Bytes()[0] // Packetlength 1/2
		returnpacket[5] = uintbuf.Bytes()[1] // Packetlength 2/2
		returnpacket[6] = 0x3a               // Next header (aka packet content protocol), 0x3a == 58 == ICMPv6
		returnpacket[7] = 0x40               // Hop Limit of the outgoing packet, 0x40 == 64

		// Copy the source address from the incoming packet, and use it as the destination.
		copy(returnpacket[24:], packet[8:24])

		if len(hops) <= TTL {
			// fake response from destination
			copy(returnpacket[8:24], destIP)

			if packetType == 58 { // ICMPv6 (58)
				// for windows or traceroute6 -I
				returnpacket[40] = 0x81 // Echo Reply
				returnpacket[41] = 0x00 // no error
			} else { // UDP (17) and everything else
				// for linux
				returnpacket[40] = 0x01 // Destination Unreachable
				returnpacket[41] = 0x04 // Port unreachable
			}
			// id and sequence number
			copy(returnpacket[44:48], packet[44:48])
		} else {
			// fake hop address
			copy(returnpacket[8:24], hops[TTL-1])

			returnpacket[40] = 0x03 // Time Exceeded
			returnpacket[41] = 0x00 // Hop limit exceeded in transit

			// "Reserved"
			copy(returnpacket[44:48], []byte{0, 0, 0, 0})
		}

		copy(returnpacket[48:48+plen], packet)

		// Oh GOD now here comes a strange CRC dance
		src := net.IP(returnpacket[8 : 8+16])
		dst := net.IP(returnpacket[24 : 24+16])
		crcb := checksum(returnpacket[40:], src, dst)

		returnpacket[42] = crcb[0]
		returnpacket[43] = crcb[1]

		// Aaaaaaaaaaaand that is all folks, Send it out. Ship it.
		ifce.Write(returnpacket)

	}
}

func checksum(body []byte, srcIP, dstIP net.IP) (crc []byte) {
	out := make([]byte, 2)
	// from golang.org/x/net/icmp/message.go
	checksum := func(b []byte) uint16 {
		csumcv := len(b) - 1 // checksum coverage
		s := uint32(0)
		for i := 0; i < csumcv; i += 2 {
			s += uint32(b[i+1])<<8 | uint32(b[i])
		}
		if csumcv&1 == 0 {
			s += uint32(b[csumcv])
		}
		s = s>>16 + s&0xffff
		s = s + s>>16
		return ^uint16(s)
	}

	b := body

	// remember origin length
	l := len(b)
	// generate pseudo header
	psh := icmp.IPv6PseudoHeader(srcIP, dstIP)
	// concat psh with b
	b = append(psh, b...)
	// set length of total packet
	off := 2 * net.IPv6len
	binary.BigEndian.PutUint32(b[off:off+4], uint32(l))
	// calculate checksum
	s := checksum(b)
	// set checksum in bytes and return original Body
	out[0] ^= byte(s)
	out[1] ^= byte(s >> 8)

	return out
}
