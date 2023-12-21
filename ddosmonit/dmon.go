package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

var (
	deviceMonitor   = flag.String("d", "eth0", "Device to monitor")
	packetThreshold = flag.Int("c", 5000, "Packets per second threshold to start logging")
	excludeList     = flag.String("x", "", "Comma-separated list of IPs and ports to exclude")
	includeList     = flag.String("i", "", "Comma-separated list of IPs and ports to include")
)

type PacketInfo struct {
	Timestamp   string `json:"timestamp"`
	Protocol    string `json:"protocol"`
	SourceIP    net.IP `json:"source_ip"`
	DestIP      net.IP `json:"dest_ip"`
	SourcePort  int    `json:"source_port"`
	DestPort    int    `json:"dest_port"`
	Length      int    `json:"length,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	WindowSize  int    `json:"window_size,omitempty"`
	TCPFlags    string `json:"tcp_flags,omitempty"`
	Checksum    int    `json:"checksum,omitempty"`
	PayloadData string `json:"payload_data,omitempty"`
	ICMPData    string `json:"icmp_data,omitempty"`
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

func getInterfaceMAC(interfaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	return iface.HardwareAddr, nil
}

func parseAndValidateIPsAndPorts(list string) ([]net.IP, []int) {
	var ips []net.IP
	var ports []int

	items := strings.Split(list, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if ip := net.ParseIP(item); ip != nil {
			ips = append(ips, ip)
		} else if port, err := strconv.Atoi(item); err == nil {
			ports = append(ports, port)
		}
	}

	return ips, ports
}

func shouldProcessPacket(packet gopacket.Packet, excludeIPs []net.IP, excludePorts []int, includeIPs []net.IP, includePorts []int) bool {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	var srcIP, dstIP net.IP
	var srcPort, dstPort int

	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
	}

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
	}

	if containsIP(excludeIPs, srcIP) || containsIP(excludeIPs, dstIP) || containsPort(excludePorts, srcPort) || containsPort(excludePorts, dstPort) {
		return false
	}

	if len(includeIPs) > 0 || len(includePorts) > 0 {
		return containsIP(includeIPs, srcIP) || containsIP(includeIPs, dstIP) || containsPort(includePorts, srcPort) || containsPort(includePorts, dstPort)
	}

	return true
}

func containsIP(ips []net.IP, ip net.IP) bool {
	for _, listedIP := range ips {
		if ip.Equal(listedIP) {
			return true
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	for _, listedPort := range ports {
		if port == listedPort {
			return true
		}
	}
	return false
}

func isLikelyPlainText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	var printableCount, controlCount int
	for _, runeValue := range string(data) {
		if unicode.IsPrint(runeValue) || unicode.IsSpace(runeValue) {
			printableCount++
		} else if unicode.IsControl(runeValue) {
			controlCount++
		}
	}

	totalChars := len(data)
	printableRatio := float64(printableCount) / float64(totalChars)
	controlRatio := float64(controlCount) / float64(totalChars)

	return printableRatio > 0.7 && controlRatio < 0.3
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
			payloadDisplay = reg.ReplaceAllString(payloadDisplay, " ")
			payloadDisplay = strings.TrimSpace(payloadDisplay)
			if len(payloadDisplay) > 100 {
				payloadDisplay = fmt.Sprintf("%sPayload: %s%s... %s(%d)%s", ColorCyan, ColorPurple, payloadDisplay[:100], ColorDarkGrey, len(payloadDisplay), ColorReset)
			} else {
				payloadDisplay = fmt.Sprintf("%sPayload: %s%s%s", ColorCyan, ColorPurple, payloadDisplay, ColorReset)
			}
		} else {
			payloadDisplay = fmt.Sprintf("%sPayload: %sNon-printable data %s(%d)%s", ColorCyan, ColorPurple, ColorDarkGrey, len(payloadDisplay), ColorReset)
		}
	}

	srcPortDisplay := ""
	if info.SourcePort == 0 {
		srcPortDisplay = ""
	} else {
		srcPortDisplay = fmt.Sprintf("%d", info.SourcePort)
	}

	dstPortDisplay := ""
	if info.DestPort == 0 {
		dstPortDisplay = ""
	} else {
		dstPortDisplay = fmt.Sprintf("%d", info.DestPort)
	}

	protocolColor := ""
	switch info.Protocol {
	case "TCP":
		protocolColor = ColorGreen
	case "UDP":
		protocolColor = ColorYellow
	case "ICMP":
		protocolColor = ColorPurple
	}

	extraData := ""
	if info.Protocol == "ICMP" {
		extraData = fmt.Sprintf("%3s", info.ICMPData)
	} else if info.Protocol == "UDP" {
		extraData = "   "
	} else if info.Protocol == "TCP" {
		if info.TCPFlags == "" {
			extraData = "   "
		} else {
			extraData = info.TCPFlags
		}
	}

	SEP := ColorDarkGrey + "│" + ColorReset
	fmt.Printf("%s %s %s %s %15s %-5s -> %15s %-5s %s %s %4d %s %s %3d %s %s %5d %s %s %5d %s %s %s %s\n",
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

func writeToFile(data []byte) {
	fileName := "packet_info.json"
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	_, err = file.WriteString("\n")
	if err != nil {
		fmt.Println("Error writing newline to file:", err)
		return
	}
}

func getTCPFlags(tcp *layers.TCP) string {
	flagNames := map[bool]string{
		tcp.FIN: "FIN",
		tcp.SYN: "SYN",
		tcp.RST: "RST",
		tcp.PSH: "PSH",
		tcp.ACK: "ACK",
		tcp.URG: "URG",
		tcp.ECE: "ECE",
		tcp.CWR: "CWR",
		tcp.NS:  "NS",
	}

	var flags []string
	for flag, name := range flagNames {
		if flag {
			flags = append(flags, name)
		}
	}

	return strings.Join(flags, ",")
}
