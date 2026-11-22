// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package testbench

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/tunnel"
)

// VirtualNode represents one isolated actor in the test mesh.
type VirtualNode struct {
	ID               string
	Name             string
	VirtualIP        net.IP
	AdvertisedRoutes []string
	AllowExitNode    bool
	SelectedExitNode string
	Registry         *peer.Registry
	TransitForwarder *tunnel.TransitForwarder

	// Packet pipes simulating TUN / userspace I/O
	TunInboundChan   chan []byte // Packets arriving from TUN to be transmitted into mesh
	TunOutboundChan  chan []byte // Packets arriving from mesh to be written into TUN

	// Network transport pipes
	UDPRecvChan      chan []byte // Inbound UDP packets received from network
	TCPRecvChan      chan []byte // Inbound TCP fallback packets received from network

	// Send callback to the virtual switch
	SendPacketFunc   func(destVIP net.IP, payload []byte, transport string) error

	// Telemetry
	TxPackets        atomic.Uint64
	RxPackets        atomic.Uint64
	TxBytes          atomic.Uint64
	RxBytes          atomic.Uint64

	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.RWMutex
}

// VirtualMesh coordinates the virtual network topology.
type VirtualMesh struct {
	ClientNode       *VirtualNode
	ExitNode         *VirtualNode
	SubnetNode       *VirtualNode
	RelayNode        *VirtualNode

	nodes            map[string]*VirtualNode // Keyed by VIP string
	dropUDP          atomic.Bool             // Simulates DPI blocking UDP
	dropAll          atomic.Bool             // Simulates link disconnection
	packetLossRate   atomic.Uint64           // Scaled by 1000 (e.g. 50 = 5%)
	simulatedLatency time.Duration

	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.RWMutex
}

// NewVirtualMesh instantiates and bootstraps a 4-node virtual mesh topology.
func NewVirtualMesh(parentCtx context.Context) (*VirtualMesh, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	vm := &VirtualMesh{
		nodes:  make(map[string]*VirtualNode),
		ctx:    ctx,
		cancel: cancel,
	}

	// 1. Client Node (simulates Android phone or desktop client)
	clientVIP := net.ParseIP("10.11.12.101")
	clientNode := vm.createNode("client-node-01", "Android-Client", clientVIP, nil, false)

	// 2. Exit Node (simulates Windows PC or VPS acting as internet gateway)
	exitVIP := net.ParseIP("10.11.12.102")
	exitNode := vm.createNode("exit-node-01", "Windows-ExitNode", exitVIP, nil, true)

	// 3. Subnet Node (simulates Keenetic / Linux router advertising local LAN)
	subnetVIP := net.ParseIP("10.11.12.103")
	subnetRoutes := []string{"192.168.100.0/24"}
	subnetNode := vm.createNode("subnet-node-01", "Keenetic-Router", subnetVIP, subnetRoutes, false)

	// 4. Relay Node (simulates intermediate mesh peer)
	relayVIP := net.ParseIP("10.11.12.104")
	relayNode := vm.createNode("relay-node-01", "Mesh-RelayNode", relayVIP, nil, false)

	vm.ClientNode = clientNode
	vm.ExitNode = exitNode
	vm.SubnetNode = subnetNode
	vm.RelayNode = relayNode

	// Register all nodes in switch routing table
	vm.nodes[clientVIP.String()] = clientNode
	vm.nodes[exitVIP.String()] = exitNode
	vm.nodes[subnetVIP.String()] = subnetNode
	vm.nodes[relayVIP.String()] = relayNode

	// Cross-populate registries with initial discovery state
	allNodes := []*VirtualNode{clientNode, exitNode, subnetNode, relayNode}
	for _, n1 := range allNodes {
		for _, n2 := range allNodes {
			if n1.ID == n2.ID {
				continue
			}
			p := &peer.Peer{
				DeviceID:          n2.ID,
				DeviceName:        n2.Name,
				Nickname:          n2.Name,
				VirtualIP:         n2.VirtualIP.String(),
				ActiveEndpoint:    fmt.Sprintf("127.0.0.1:%d", int(n2.VirtualIP[3])+20000),
				Online:            true,
				DirectP2P:         true,
				Transport:         "udp_direct",
				LastSeen:          time.Now(),
				LastDirectSeen:    time.Now(),
				LastBilateralSeen: time.Now(),
				AdvertisedRoutes:  n2.AdvertisedRoutes,
				IsExitNode:        n2.AllowExitNode,
			}
			n1.Registry.Upsert(p)
		}
	}

	// Attach TransitForwarder on ExitNode
	exitNode.TransitForwarder = tunnel.NewTransitForwarder(
		exitVIP.String(),
		func(vipOrID string) *peer.Peer {
			if p, ok := exitNode.Registry.GetByIDOrVIP(vipOrID); ok {
				return p
			}
			return nil
		},
		func(destPeer *peer.Peer, packet []byte) error {
			if destPeer == nil {
				return fmt.Errorf("nil destination peer")
			}
			cleanVIP := strings.TrimSpace(strings.Split(destPeer.VirtualIP, "/")[0])
			destIP := net.ParseIP(cleanVIP)
			if destIP == nil {
				return fmt.Errorf("invalid dest VIP: %s", destPeer.VirtualIP)
			}
			return vm.routePacket(exitVIP, destIP, packet, "udp")
		},
	)

	// Start packet processing loops for each node
	for _, n := range allNodes {
		vm.startNodeLoops(n)
	}

	return vm, nil
}

func (vm *VirtualMesh) createNode(id, name string, vip net.IP, routes []string, allowExit bool) *VirtualNode {
	ctx, cancel := context.WithCancel(vm.ctx)
	reg := peer.NewRegistry()
	node := &VirtualNode{
		ID:               id,
		Name:             name,
		VirtualIP:        vip,
		AdvertisedRoutes: routes,
		AllowExitNode:    allowExit,
		Registry:         reg,
		TunInboundChan:   make(chan []byte, 4096),
		TunOutboundChan:  make(chan []byte, 4096),
		UDPRecvChan:      make(chan []byte, 4096),
		TCPRecvChan:      make(chan []byte, 4096),
		ctx:              ctx,
		cancel:           cancel,
	}

	node.SendPacketFunc = func(destVIP net.IP, payload []byte, transport string) error {
		return vm.routePacket(vip, destVIP, payload, transport)
	}

	return node
}

// routePacket is the Virtual Switch core router.
func (vm *VirtualMesh) routePacket(srcVIP, dstVIP net.IP, payload []byte, transport string) error {
	if vm.dropAll.Load() {
		return nil // Link down
	}

	if transport == "udp" && vm.dropUDP.Load() {
		return fmt.Errorf("UDP dropped by simulated firewall/DPI")
	}

	lossScaled := vm.packetLossRate.Load()
	if lossScaled > 0 {
		// Probabilistic drop
		if (uint64(len(payload)*137) % 1000) < lossScaled {
			return nil
		}
	}

	vm.mu.RLock()
	destNode, exists := vm.nodes[dstVIP.String()]
	vm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("destination node not found for VIP %s", dstVIP)
	}

	// Create decoupled copy of slice to prevent memory race
	pktCopy := make([]byte, len(payload))
	copy(pktCopy, payload)

	if transport == "tcp" {
		select {
		case destNode.TCPRecvChan <- pktCopy:
		default:
		}
	} else {
		select {
		case destNode.UDPRecvChan <- pktCopy:
		default:
		}
	}

	destNode.RxPackets.Add(1)
	destNode.RxBytes.Add(uint64(len(payload)))
	return nil
}

// startNodeLoops runs background goroutines simulating node packet pipeline.
func (vm *VirtualMesh) startNodeLoops(n *VirtualNode) {
	// 1. Process Outbound TUN packets (TUN -> Mesh)
	go func(node *VirtualNode) {
		for {
			select {
			case <-node.ctx.Done():
				return
			case pkt, ok := <-node.TunInboundChan:
				if !ok {
					return
				}
				node.TxPackets.Add(1)
				node.TxBytes.Add(uint64(len(pkt)))
				node.processOutboundPacket(pkt)
			}
		}
	}(n)

	// 2. Process Inbound Network packets (UDP/TCP -> Node / TUN / TransitForwarder)
	go func(node *VirtualNode) {
		for {
			select {
			case <-node.ctx.Done():
				return
			case pkt, ok := <-node.UDPRecvChan:
				if !ok {
					return
				}
				node.handleInboundPacket(pkt, "udp")
			case pkt, ok := <-node.TCPRecvChan:
				if !ok {
					return
				}
				node.handleInboundPacket(pkt, "tcp")
			}
		}
	}(n)
}

// processOutboundPacket implements LPM routing and Exit Node dispatch.
func (n *VirtualNode) processOutboundPacket(pkt []byte) {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return
	}

	destIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	_ = tunnel.ClampTCPMSS(pkt, constants.DefaultClampedMSS)

	// 1. Check direct mesh destination
	var targetPeer *peer.Peer
	if n.Registry != nil {
		if best, ok := n.Registry.GetByVirtualIP(destIP.String()); ok && best != nil {
			targetPeer = best
		} else {
			// 2. LPM Subnet Route Check
			for _, p := range n.Registry.List() {
				pVIP := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
				if pVIP == destIP.String() {
					targetPeer = p
					break
				}
				for _, route := range p.AdvertisedRoutes {
					r := strings.TrimSpace(route)
					if r == "0.0.0.0/0" || r == "::/0" {
						continue
					}
					if _, ipNet, err := net.ParseCIDR(r); err == nil && ipNet.Contains(destIP) {
						targetPeer = p
						break
					}
				}
				if targetPeer != nil {
					break
				}
			}
		}
	}

	// 3. Fallback to Exit Node if destination is external WAN
	if targetPeer == nil && n.SelectedExitNode != "" && n.Registry != nil {
		if ep, ok := n.Registry.GetByIDOrVIP(n.SelectedExitNode); ok && ep != nil {
			targetPeer = ep
		}
	}

	if targetPeer != nil {
		targetVIP := net.ParseIP(strings.TrimSpace(strings.Split(targetPeer.VirtualIP, "/")[0]))
		if targetVIP != nil && n.SendPacketFunc != nil {
			transport := "udp"
			if targetPeer.Transport == "tcp" || targetPeer.Transport == "shadowtls" {
				transport = "tcp"
			}
			_ = n.SendPacketFunc(targetVIP, pkt, transport)
		}
	}
}

// handleInboundPacket processes incoming packet on the node.
func (n *VirtualNode) handleInboundPacket(pkt []byte, transport string) {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return
	}

	destIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])

	// If this node is an Exit Node and packet is transit traffic destined for WAN
	if n.AllowExitNode && n.TransitForwarder != nil && n.TransitForwarder.HandleTransitPacket(pkt) {
		return
	}

	// If packet is destined for this node's VIP or advertised subnet, deliver to TUN
	if destIP.Equal(n.VirtualIP) {
		select {
		case n.TunOutboundChan <- pkt:
		default:
		}
		return
	}

	// Check if this node advertises the subnet for destIP (Subnet Gateway forwarding)
	for _, route := range n.AdvertisedRoutes {
		if _, ipNet, err := net.ParseCIDR(route); err == nil && ipNet.Contains(destIP) {
			select {
			case n.TunOutboundChan <- pkt:
			default:
			}
			return
		}
	}
}

// SetDropUDP sets or clears UDP blocking to test TCP fallback.
func (vm *VirtualMesh) SetDropUDP(drop bool) {
	vm.dropUDP.Store(drop)
}

// SetDropAll sets or clears all packet delivery (simulate complete link failure).
func (vm *VirtualMesh) SetDropAll(drop bool) {
	vm.dropAll.Store(drop)
}

// SetPacketLoss sets simulated loss percentage (0.0 to 1.0).
func (vm *VirtualMesh) SetPacketLoss(rate float64) {
	if rate < 0 {
		rate = 0
	}
	if rate > 1.0 {
		rate = 1.0
	}
	vm.packetLossRate.Store(uint64(rate * 1000))
}

// Close gracefully terminates all virtual nodes and forwarders.
func (vm *VirtualMesh) Close() {
	vm.cancel()
	if vm.ExitNode != nil && vm.ExitNode.TransitForwarder != nil {
		vm.ExitNode.TransitForwarder.Close()
	}
}
