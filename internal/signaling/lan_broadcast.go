// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/rs/zerolog/log"
)

const lanDiscoveryMagic = "NATBYPASS:LAN:BCST:V1"

// LANBroadcastChannel implements zero-config local network peer discovery via UDP broadcast.
// It allows nodes on the same LAN / Wi-Fi subnet to instantly discover each other in under 10ms
// without requiring any external internet access, STUN servers, or central MQTT brokers.
type LANBroadcastChannel struct {
	port       int
	myDevID    string
	networkKey string
	conn       *net.UDPConn
	outChans   []chan *Payload
	outMu      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	closeMu    sync.Mutex
}

var _ SignalingChannel = (*LANBroadcastChannel)(nil)

// NewLANBroadcastChannel creates a new LAN broadcast discovery channel.
func NewLANBroadcastChannel(myDevID, networkKey string, port int) *LANBroadcastChannel {
	if port <= 0 {
		port = constants.DefaultLANDiscoveryPort
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := &LANBroadcastChannel{
		port:       port,
		myDevID:    myDevID,
		networkKey: networkKey,
		ctx:        ctx,
		cancel:     cancel,
	}
	ch.startListener()
	return ch
}

func (c *LANBroadcastChannel) Name() string {
	return fmt.Sprintf("lan:broadcast:%d", c.port)
}

func (c *LANBroadcastChannel) SetNetworkKey(key string) {
	c.closeMu.Lock()
	c.networkKey = key
	c.closeMu.Unlock()
}

func (c *LANBroadcastChannel) startListener() {
	lAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: c.port,
	}
	conn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		log.Debug().Err(err).Int("port", c.port).Msg("LAN broadcast discovery listener could not bind port (might be in use by another instance)")
		return
	}
	c.conn = conn
	go c.listenLoop()
}

func (c *LANBroadcastChannel) listenLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		if c.conn == nil {
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, srcAddr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
				continue
			}
			c.closeMu.Lock()
			isClosed := c.closed
			c.closeMu.Unlock()
			if isClosed {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if n < len(lanDiscoveryMagic) || string(buf[:len(lanDiscoveryMagic)]) != lanDiscoveryMagic {
			continue
		}

		rawPayload := buf[len(lanDiscoveryMagic):n]
		var p Payload
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			continue
		}

		// Decrypt if networkKey is set
		c.closeMu.Lock()
		netKey := c.networkKey
		c.closeMu.Unlock()

		decrypted, err := DecryptPayloadWithKey(&p, netKey)
		if err != nil || decrypted == nil {
			continue
		}

		// Ignore own broadcasts
		if decrypted.DeviceID == c.myDevID {
			continue
		}

		// If LocalAddr is empty or remote, inject observed local LAN source address
		if srcAddr != nil && decrypted.LocalAddr == "" {
			decrypted.LocalAddr = srcAddr.IP.String()
		}

		c.outMu.RLock()
		for _, out := range c.outChans {
			select {
			case out <- decrypted:
			default:
			}
		}
		c.outMu.RUnlock()
	}
}

// Send broadcasts the payload to all local broadcast addresses and 255.255.255.255.
func (c *LANBroadcastChannel) Send(ctx context.Context, payload *Payload) error {
	if payload == nil {
		return nil
	}

	c.closeMu.Lock()
	netKey := c.networkKey
	c.closeMu.Unlock()

	encPayload, err := EncryptPayloadWithKey(payload, netKey)
	if err != nil {
		encPayload = payload
	}

	data, err := json.Marshal(encPayload)
	if err != nil {
		return err
	}

	frame := append([]byte(lanDiscoveryMagic), data...)

	// Target broadcast addresses: global 255.255.255.255 + all interface-specific broadcasts
	targets := []string{fmt.Sprintf("255.255.255.255:%d", c.port)}

	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						ip := ipNet.IP.To4()
						mask := ipNet.Mask
						bcast := net.IPv4(
							ip[0]|^mask[0],
							ip[1]|^mask[1],
							ip[2]|^mask[2],
							ip[3]|^mask[3],
						)
						targets = append(targets, fmt.Sprintf("%s:%d", bcast.String(), c.port))
					}
				}
			}
		}
	}

	// Dial ephemeral UDP sender socket with broadcast enabled
	sConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4bcast, Port: c.port})
	if err == nil {
		defer sConn.Close()
		for _, t := range targets {
			if rAddr, err := net.ResolveUDPAddr("udp4", t); err == nil {
				_, _ = sConn.WriteTo(frame, rAddr)
			}
		}
	}

	return nil
}

func (c *LANBroadcastChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	ch := make(chan *Payload, 32)
	c.outMu.Lock()
	c.outChans = append(c.outChans, ch)
	c.outMu.Unlock()
	return ch, nil
}

func (c *LANBroadcastChannel) IsAvailable(ctx context.Context) bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return !c.closed
}

func (c *LANBroadcastChannel) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	return nil
}
