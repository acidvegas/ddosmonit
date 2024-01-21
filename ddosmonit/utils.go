package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

func getInterfaceMAC(interfaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	return iface.HardwareAddr, nil
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
	var srcIP, dstIP net.IP
	var srcPort, dstPort int

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcIP, dstIP = ipv4.SrcIP, ipv4.DstIP
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
	}

	isExcluded := containsIP(excludeIPs, srcIP) || containsIP(excludeIPs, dstIP) ||
		containsPort(excludePorts, srcPort) || containsPort(excludePorts, dstPort)
	isIncluded := (len(includeIPs) == 0 || containsIP(includeIPs, srcIP) || containsIP(includeIPs, dstIP)) &&
		(len(includePorts) == 0 || containsPort(includePorts, srcPort) || containsPort(includePorts, dstPort))

	return !isExcluded && isIncluded
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
