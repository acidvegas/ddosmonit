package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	deviceMonitor   = flag.String("d", "eth0", "Device to monitor")
	packetThreshold = flag.Int("c", 5000, "Packets per second threshold to start logging")
	excludeList     = flag.String("x", "", "Comma-separated list of IPs and ports to exclude")
	includeList     = flag.String("i", "", "Comma-separated list of IPs and ports to include")
)

const (
	ColorReset    = "\033[0m"
	ColorDarkGrey = "\033[90m"
	ColorYellow   = "\033[33m"
	ColorRed      = "\033[31m"
	ColorGreen    = "\033[32m"
	ColorPurple   = "\033[35m"
	ColorCyan     = "\033[36m"
	ColorPink     = "\033[95m"
)

type PacketInfo struct {
	Timestamp   string `json:"timestamp"`
	Protocol    string `json:"protocol"`
	SourceIP    net.IP `json:"source_ip"`
	SourcePort  int    `json:"source_port"`
	DestIP      net.IP `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Length      int    `json:"length,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	WindowSize  int    `json:"window_size,omitempty"`
	Checksum    int    `json:"checksum,omitempty"`
	TCPFlags    string `json:"tcp_flags,omitempty"`
	ICMPData    string `json:"icmp_data,omitempty"`
	PayloadData string `json:"payload_data,omitempty"`
}

func main() {
	flag.Parse()

	deviceMAC, err := getInterfaceMAC(*deviceMonitor)
	if err != nil {
		log.Fatalf("Error getting MAC address of %s: %v", *deviceMonitor, err)
	}

	excludeIPs, excludePorts := parseAndValidateIPsAndPorts(*excludeList)
	includeIPs, includePorts := parseAndValidateIPsAndPorts(*includeList)

	snaplen := int32(1600)
	promiscuous := false
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(*deviceMonitor, snaplen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var totalBytes int64
	var packetCount int
	startTime := time.Now()

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			elapsed := time.Since(startTime).Seconds()
			pps := int(float64(packetCount) / elapsed)
			mbps := (float64(totalBytes) / 1e6) / elapsed
			fmt.Print("\033[A\033[K")             // Move up one line and clear it.
			fmt.Println(strings.Repeat(" ", 100)) // Clear the line with 50 spaces (or enough to cover the previous text).
			fmt.Print("\033[A")                   // Move up one line again to overwrite the cleared line.
			fmt.Printf("PP/s: %-7d %.2f MB/s\n", pps, mbps)
			packetCount = 0
			totalBytes = 0
			startTime = time.Now()
		}
	}()

	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernet, _ := ethernetLayer.(*layers.Ethernet)
			if !bytes.Equal(ethernet.DstMAC, deviceMAC) {
				continue
			}
		}

		if shouldProcessPacket(packet, excludeIPs, excludePorts, includeIPs, includePorts) {
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if ipv4Layer != nil && (tcpLayer != nil || udpLayer != nil || icmpLayer != nil) {
				fmt.Print("\033[A\033[K")
				printPacketInfo(packet)

				packetCount++
				totalBytes += int64(packet.Metadata().Length)

				ppsColor := ""
				switch {
				case packetCount > *packetThreshold:
					ppsColor = ColorRed
				case packetCount > *packetThreshold/2:
					ppsColor = ColorYellow
				default:
					ppsColor = ColorReset
				}

				elapsed := time.Since(startTime).Seconds()
				if elapsed > 0 {
					pps := int(float64(packetCount) / elapsed)
					mbps := (float64(totalBytes) * 8) / 1e6 / elapsed
					fmt.Printf("%sPP/s: %-7d %.2f%s MB/s\n", ppsColor, pps, mbps, ColorReset)
				}
			}
		}
	}
}

func printPacketInfo(packet gopacket.Packet) {
	var srcIP, dstIP net.IP
	var srcPort, dstPort int
	var length, ttl, winSize, checksum, icmpCode, icmpType int
	var protocol, tcpFlags, payloadData, icmpData string
	timestamp := time.Now().Format("03:04:05")

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
		length = int(ipv4.Length)
		ttl = int(ipv4.TTL)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		protocol = "TCP"
		checksum = int(tcp.Checksum)
		payloadData = string(tcp.Payload)
		tcpFlags = getTCPFlags(tcp)
		winSize = int(tcp.Window)
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
		protocol = "UDP"
		checksum = int(udp.Checksum)
		payloadData = string(udp.Payload)
	} else if icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		protocol = "ICMP"
		checksum = int(icmp.Checksum)
		payloadData = string(icmp.Payload)
		icmpType = int(icmp.TypeCode >> 8)
		icmpCode = int(icmp.TypeCode & 0xFF)
		icmpData = fmt.Sprintf("%d-%d", icmpType, icmpCode)
	}

	packetInfo := PacketInfo{
		Timestamp:   timestamp,
		Protocol:    protocol,
		SourceIP:    srcIP,
		SourcePort:  srcPort,
		DestIP:      dstIP,
		DestPort:    dstPort,
		Length:      length,
		TTL:         ttl,
		WindowSize:  winSize,
		TCPFlags:    tcpFlags,
		Checksum:    checksum,
		PayloadData: payloadData,
		ICMPData:    icmpData,
	}

	jsonData, err := json.Marshal(packetInfo)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	writeToFile(jsonData)
	printWithColors(packetInfo)
}

func printWithColors(info PacketInfo) {
	payloadDisplay := info.PayloadData
	if len(payloadDisplay) != 0 {
		if isLikelyPlainText([]byte(payloadDisplay)) {
			reg := regexp.MustCompile(`[\s\r\n\v\f]+`)
			payloadDisplay = strings.TrimSpace(reg.ReplaceAllString(payloadDisplay, " "))
			format := "%sPayload: %s%s%s"
			if len(payloadDisplay) > 100 {
				payloadDisplay = fmt.Sprintf(format, ColorCyan, ColorPurple, payloadDisplay[:100]+"... "+fmt.Sprintf("%s(%d)%s", ColorDarkGrey, len(payloadDisplay), ColorReset), ColorReset)
			} else {
				payloadDisplay = fmt.Sprintf(format, ColorCyan, ColorPurple, payloadDisplay, ColorReset)
			}
		} else {
			payloadDisplay = fmt.Sprintf("%sPayload: %sNon-printable data %s(%d)%s", ColorCyan, ColorPurple, ColorDarkGrey, len(payloadDisplay), ColorReset)
		}
	}

	srcPortDisplay := fmt.Sprintf("%d", info.SourcePort)
	dstPortDisplay := fmt.Sprintf("%d", info.DestPort)
	if info.SourcePort == 0 {
		srcPortDisplay = ""
	}
	if info.DestPort == 0 {
		dstPortDisplay = ""
	}

	protocolColorMap := map[string]string{
		"TCP":  ColorGreen,
		"UDP":  ColorYellow,
		"ICMP": ColorPurple,
	}
	protocolColor := protocolColorMap[info.Protocol]

	extraData := "   "
	if info.Protocol == "ICMP" {
		extraData = fmt.Sprintf("%3s", info.ICMPData)
	} else if info.Protocol == "TCP" && info.TCPFlags != "" {
		extraData = info.TCPFlags
	}

	SEP := ColorDarkGrey + "│" + ColorReset
	fmt.Printf("%s %s %s %s %15s %-5s -> %15s %-5s %s %s %5d %s %s %3d %s %s %5d %s %s %5d %s %s %s %s\n",
		ColorDarkGrey+info.Timestamp+ColorReset,
		SEP,
		protocolColor+fmt.Sprintf("%4s", info.Protocol)+ColorReset,
		SEP,
		info.SourceIP,
		srcPortDisplay,
		info.DestIP,
		dstPortDisplay,
		SEP,
		ColorCyan+"Len:"+ColorReset, info.Length,
		SEP,
		ColorCyan+"TTL:"+ColorReset, info.TTL,
		SEP,
		ColorCyan+"Window:"+ColorReset, info.WindowSize,
		SEP,
		ColorCyan+"Checksum:"+ColorReset, info.Checksum,
		SEP,
		extraData,
		SEP,
		payloadDisplay,
	)

}
