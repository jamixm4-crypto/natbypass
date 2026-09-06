package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/natbypass/natbypass/internal/signaling"
)

// PeerInfo — информация о найденном пире
type PeerInfo struct {
	NodeID     string
	Label      string
	Country    string
	PubKey     string
	STUNAddr   string
	NATType    string
	NATDelta   int
	VIP        string
	ListenPort int // UDP порт для probe-теста (отдельный от STUN)
	LastSeen   time.Time
}

// ProbeBeacon — структура beacon-сообщения для probe-теста
type ProbeBeacon struct {
	NodeID     string `json:"node_id"`
	Label      string `json:"label"`
	Country    string `json:"country"`
	PubKey     string `json:"pub_key"`
	STUNAddr   string `json:"stun_addr"`
	NATType    string `json:"nat_type"`
	NATDelta   int    `json:"nat_delta,omitempty"`
	VIP        string `json:"vip"`
	ProbeID    string `json:"probe_id"`
	ListenPort int    `json:"listen_port"` // UDP порт для приёма probe-пакетов
}

// Discovery управляет обнаружением пиров через MQTT
type Discovery struct {
	cfg      *ProbeConfig
	myNodeID string
	sigMgr   *signaling.FallbackManager
	mu       sync.RWMutex
	peers    map[string]*PeerInfo
	onPeer   func(*PeerInfo)
}

// NewDiscovery создаёт менеджер обнаружения
func NewDiscovery(cfg *ProbeConfig, myNodeID string, onPeer func(*PeerInfo)) (*Discovery, error) {
	clientID := fmt.Sprintf("probe-%s-%d", myNodeID, time.Now().UnixNano()%100000)
	mqttCh := signaling.NewMQTTChannel(cfg.MQTTBroker, cfg.MQTTTopic, clientID, "", "")
	sigMgr := signaling.NewFallbackManager([]signaling.SignalingChannel{mqttCh})
	return &Discovery{
		cfg:      cfg,
		myNodeID: myNodeID,
		sigMgr:   sigMgr,
		peers:    make(map[string]*PeerInfo),
		onPeer:   onPeer,
	}, nil
}

// PublishBeacon публикует beacon текущего узла.
// Beacon JSON сериализуется и кладётся в Payload.Nickname, а стандартные
// поля Payload заполняются для совместимости с другими клиентами.
func (d *Discovery) PublishBeacon(ctx context.Context, beacon *ProbeBeacon) error {
	data, err := json.Marshal(beacon)
	if err != nil {
		return err
	}
	payload := &signaling.Payload{
		DeviceID:   d.myNodeID,
		STUNAddr:   beacon.STUNAddr,
		NATType:    beacon.NATType,
		PublicKey:  beacon.PubKey,
		VirtualIP:  beacon.VIP,
		CountryFlag: beacon.Country,
		Nickname:   string(data), // embed full beacon JSON in Nickname field
	}
	return d.sigMgr.Send(ctx, payload)
}

// StartReceiving запускает goroutine для получения beacon'ов от других пиров
func (d *Discovery) StartReceiving(ctx context.Context) error {
	ch, err := d.sigMgr.Receive(ctx)
	if err != nil {
		return fmt.Errorf("signaling receive: %w", err)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case payload, ok := <-ch:
				if !ok {
					return
				}
				if payload.DeviceID == d.myNodeID {
					continue // skip own beacons
				}
				d.handlePayload(payload)
			}
		}
	}()
	return nil
}

func (d *Discovery) handlePayload(payload *signaling.Payload) {
	// Пробуем распарсить probe beacon из Nickname поля (содержит сериализованный ProbeBeacon)
	var beacon ProbeBeacon
	if payload.Nickname != "" {
		_ = json.Unmarshal([]byte(payload.Nickname), &beacon)
	}
	// Fallback на стандартные поля payload
	if beacon.NodeID == "" {
		beacon.NodeID = payload.DeviceID
	}
	if beacon.STUNAddr == "" {
		beacon.STUNAddr = payload.STUNAddr
	}
	if beacon.NATType == "" {
		beacon.NATType = payload.NATType
	}
	if beacon.PubKey == "" {
		beacon.PubKey = payload.PublicKey
	}
	if beacon.VIP == "" {
		beacon.VIP = payload.VirtualIP
	}
	if beacon.Country == "" {
		beacon.Country = payload.CountryFlag
	}
	if beacon.NodeID == "" || beacon.STUNAddr == "" {
		return // insufficient info
	}

	d.mu.Lock()
	_, found := d.peers[beacon.NodeID]
	peer := &PeerInfo{
		NodeID:     beacon.NodeID,
		Label:      beacon.Label,
		Country:    beacon.Country,
		PubKey:     beacon.PubKey,
		STUNAddr:   beacon.STUNAddr,
		NATType:    beacon.NATType,
		NATDelta:   beacon.NATDelta,
		VIP:        beacon.VIP,
		ListenPort: beacon.ListenPort,
		LastSeen:   time.Now(),
	}
	if peer.VIP == "" {
		peer.VIP = NodeVIP(peer.NodeID)
	}
	d.peers[beacon.NodeID] = peer
	d.mu.Unlock()

	if !found {
		logf("[PEER] Discovered %s (%s): stun=%s nat=%s", peer.NodeID, peer.Label, peer.STUNAddr, peer.NATType)
		if d.onPeer != nil {
			d.onPeer(peer)
		}
	}
}

// GetPeers возвращает список обнаруженных пиров
func (d *Discovery) GetPeers() []*PeerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var peers []*PeerInfo
	for _, p := range d.peers {
		peers = append(peers, p)
	}
	return peers
}

// StartBeaconLoop запускает периодическую публикацию beacon
func (d *Discovery) StartBeaconLoop(ctx context.Context, beacon *ProbeBeacon, intervalSec int) {
	go func() {
		ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer ticker.Stop()
		// Первая публикация сразу
		_ = d.PublishBeacon(ctx, beacon)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = d.PublishBeacon(ctx, beacon)
			}
		}
	}()
}
