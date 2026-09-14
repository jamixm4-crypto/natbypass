// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// parseSubnetCIDR parses a CIDR string (e.g. 192.168.1.0/24) and returns the IPv4 network address and subnet mask.
func parseSubnetCIDR(subnetCIDR string) (string, string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(subnetCIDR))
	if err != nil {
		return "", "", fmt.Errorf("invalid subnet CIDR %q: %w", subnetCIDR, err)
	}
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return "", "", fmt.Errorf("subnet CIDR %q is not an IPv4 network", subnetCIDR)
	}
	mask := ipNet.Mask
	if len(mask) == 16 {
		mask = mask[12:16]
	}
	if len(mask) != 4 {
		return "", "", fmt.Errorf("invalid IPv4 subnet mask for %q", subnetCIDR)
	}
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	return networkIP.String(), maskStr, nil
}

// GetDestIP extracts Destination IPv4 address from packet header.
func GetDestIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}

// GetSrcIP extracts Source IPv4 address from packet header.
func GetSrcIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15])
}

// CalculateChecksum computes 16-bit internet checksum (RFC 1071).
func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// IsParasiticOrBroadcast checks if an outbound packet is multicast, broadcast, loopback, link-local,
// self-targeted, or local service noise (NetBIOS, LLMNR, SSDP, mDNS, WS-Discovery) that must not
// be encrypted or routed into the NatBypass mesh.
func IsParasiticOrBroadcast(packet []byte, myVirtualIP string) bool {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return true
	}
	srcIP := GetSrcIP(packet)
	destIP := GetDestIP(packet)
	if srcIP == nil || destIP == nil {
		return true
	}

	// Multicast, link-local, unspecified, loopback
	if destIP.IsMulticast() || destIP.IsUnspecified() || destIP.IsLoopback() ||
		destIP.IsLinkLocalUnicast() || destIP.IsLinkLocalMulticast() {
		return true
	}

	destStr := destIP.String()
	// Global broadcast or subnet broadcast/network
	if destStr == "255.255.255.255" || strings.HasSuffix(destStr, ".255") || strings.HasSuffix(destStr, ".0") {
		return true
	}

	// Loopback / self reflection
	cleanVIP := strings.TrimSpace(strings.Split(myVirtualIP, "/")[0])
	if destStr == cleanVIP || srcIP.Equal(destIP) {
		return true
	}

	// Filter common LAN discovery noise: UDP NetBIOS (137, 138), LLMNR (5355), mDNS (5353), SSDP (1900), WS-Discovery (3702)
	if packet[9] == 17 { // UDP
		ihl := int(packet[0]&0x0F) * 4
		if len(packet) >= ihl+8 {
			dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
			switch dstPort {
			case 137, 138, 1900, 3702, 5353, 5355:
				return true
			}
		}
	}

	return false
}

// ClampTCPMSS inspects IPv4 TCP SYN packets and clamps the Maximum Segment Size (MSS) option
// to maxMSS (e.g. 1240 bytes) to prevent IP fragmentation and Path MTU blackholes.
// Returns true if the MSS option was found and modified with checksum updated.
func ClampTCPMSS(packet []byte, maxMSS uint16) bool {
	if len(packet) < 40 || (packet[0]>>4) != 4 || packet[9] != 6 {
		return false
	}
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+20 {
		return false
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen > len(packet) || totalLen < ihl+20 {
		totalLen = len(packet)
	}

	flags := packet[ihl+13]
	if flags&0x02 == 0 { // Not a SYN packet
		return false
	}

	dataOffset := int(packet[ihl+12]>>4) * 4
	if dataOffset <= 20 || ihl+dataOffset > totalLen {
		return false // No options
	}

	optIdx := ihl + 20
	optEnd := ihl + dataOffset
	modified := false

	for optIdx < optEnd {
		kind := packet[optIdx]
		if kind == 0 { // End of Option List
			break
		}
		if kind == 1 { // NOP
			optIdx++
			continue
		}
		if optIdx+1 >= optEnd {
			break
		}
		length := int(packet[optIdx+1])
		if length < 2 || optIdx+length > optEnd {
			break
		}
		if kind == 2 && length == 4 { // MSS option
			curMSS := binary.BigEndian.Uint16(packet[optIdx+2 : optIdx+4])
			if curMSS > maxMSS {
				binary.BigEndian.PutUint16(packet[optIdx+2:optIdx+4], maxMSS)
				modified = true
			}
			break
		}
		optIdx += length
	}

	if !modified {
		return false
	}

	// Recalculate TCP Checksum over Pseudo-header and TCP segment
	tcpLen := totalLen - ihl
	packet[ihl+16] = 0
	packet[ihl+17] = 0

	var sum uint32
	// IPv4 Pseudo-header: SrcIP, DstIP, Zero, Protocol(6), TCPLength
	sum += uint32(binary.BigEndian.Uint16(packet[12:14]))
	sum += uint32(binary.BigEndian.Uint16(packet[14:16]))
	sum += uint32(binary.BigEndian.Uint16(packet[16:18]))
	sum += uint32(binary.BigEndian.Uint16(packet[18:20]))
	sum += uint32(6)
	sum += uint32(tcpLen)

	// TCP Segment
	tcpData := packet[ihl:totalLen]
	for i := 0; i < len(tcpData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[ihl+16:ihl+18], csum)

	return true
}
