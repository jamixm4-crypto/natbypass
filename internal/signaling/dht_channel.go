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
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/dht"
)

// DHTChannel implements decentralized serverless signaling over Kademlia DHT.
// It provides a fallback peer discovery channel when centralized MQTT brokers are unreachable or blocked.
type DHTChannel struct {
	node       *dht.Node
	myDevID    string
	networkKey string
	outChans   []chan *Payload
	outMu      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	closeMu    sync.Mutex
}

var _ SignalingChannel = (*DHTChannel)(nil)

// NewDHTChannel creates a new DHT-based signaling channel.
func NewDHTChannel(myDevID, networkKey, listenAddr string) *DHTChannel {
	ctx, cancel := context.WithCancel(context.Background())
	node := dht.NewNode(myDevID, listenAddr)
	ch := &DHTChannel{
		node:       node,
		myDevID:    myDevID,
		networkKey: networkKey,
		ctx:        ctx,
		cancel:     cancel,
	}
	node.SetOnPunchNow(func(senderID, senderSTUN string) {
		p := &Payload{
			DeviceID:  senderID,
			STUNAddr:  senderSTUN,
			Timestamp: time.Now(),
		}
		ch.outMu.RLock()
		for _, out := range ch.outChans {
			select {
			case out <- p:
			default:
			}
		}
		ch.outMu.RUnlock()
	})
	return ch
}

func (c *DHTChannel) Name() string {
	return "dht:kademlia"
}

func (c *DHTChannel) SetNetworkKey(key string) {
	c.closeMu.Lock()
	c.networkKey = key
	c.closeMu.Unlock()
}

func (c *DHTChannel) Send(ctx context.Context, payload *Payload) error {
	if payload == nil || payload.DeviceID == "" {
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
	return c.node.PublishEndpoint(payload.DeviceID, string(data))
}

func (c *DHTChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	ch := make(chan *Payload, 32)
	c.outMu.Lock()
	c.outChans = append(c.outChans, ch)
	c.outMu.Unlock()
	return ch, nil
}

func (c *DHTChannel) IsAvailable(ctx context.Context) bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return !c.closed
}

func (c *DHTChannel) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	if c.node != nil {
		c.node.Close()
	}
	return nil
}
