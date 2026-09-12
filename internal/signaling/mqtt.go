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
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/rs/zerolog/log"
)

// PacketDedup implements a memory-efficient sliding-window hash deduplicator.
type PacketDedup struct {
	mu      sync.Mutex
	entries map[string]int64
	ring    [1024]string
	head    int
	size    int
}

func NewPacketDedup() *PacketDedup {
	return &PacketDedup{
		entries: make(map[string]int64, 1024),
	}
}

func (d *PacketDedup) IsDuplicate(hash string, maxAgeMs int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UnixMilli()
	if last, exists := d.entries[hash]; exists {
		if now-last < maxAgeMs {
			return true
		}
	}

	if d.size >= len(d.ring) {
		oldestHash := d.ring[d.head]
		delete(d.entries, oldestHash)
	} else {
		d.size++
	}

	d.ring[d.head] = hash
	d.entries[hash] = now
	d.head = (d.head + 1) % len(d.ring)
	return false
}

func (d *PacketDedup) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = make(map[string]int64, 1024)
	d.head = 0
	d.size = 0
}

type MQTTChannel struct {
	client        mqtt.Client
	topicMu       sync.RWMutex
	topic         string
	name          string
	brokerMu      sync.RWMutex
	brokerURL     string
	clientID      string
	username      string
	password      string
	myDevID       string
	outMu         sync.RWMutex
	outChans      []chan *Payload
	tunnelMu      sync.RWMutex
	tunnelTopic   string
	tunnelHandler func(pkt []byte)
	dedup         *PacketDedup
	keyMu         sync.RWMutex
	hasSignKey    bool
	signKey       [32]byte
}

// SetNetworkKey configures the HMAC-SHA256 signaling authentication key derived from the network key.
func (m *MQTTChannel) SetNetworkKey(networkKey string) {
	m.keyMu.Lock()
	defer m.keyMu.Unlock()
	if networkKey == "" {
		m.hasSignKey = false
		m.signKey = [32]byte{}
		return
	}
	m.signKey = crypto.DeriveSignKey(networkKey)
	m.hasSignKey = true
}

func NewMQTTChannel(brokerURL, topic, clientID, username, password string) *MQTTChannel {
	return NewMQTTChannelNamed("", brokerURL, topic, clientID, username, password)
}

func NewMQTTChannelNamed(name, brokerURL, topic, clientID, username, password string) *MQTTChannel {
	if brokerURL == "" {
		brokerURL = "ssl://broker.emqx.io:8883"
	}
	if name == "" {
		name = "mqtt:" + brokerURL
	}

	ch := &MQTTChannel{
		name:      name,
		brokerURL: brokerURL,
		clientID:  clientID,
		username:  username,
		password:  password,
		topic:     topic,
		dedup:     NewPacketDedup(),
	}

	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL)

	// Настройка TLS для безопасного шифрования MQTT
	if strings.HasPrefix(brokerURL, "ssl://") || strings.HasPrefix(brokerURL, "tls://") || strings.HasPrefix(brokerURL, "tcps://") || strings.HasPrefix(brokerURL, "wss://") {
		opts.SetTLSConfig(crypto.BuildTLSConfig(brokerURL))
	}

	opts.SetClientID(fmt.Sprintf("nb-%s-%d", clientID, time.Now().UnixNano()%1000000)).
		SetUsername(username).
		SetPassword(password).
		SetCleanSession(true).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(1 * time.Second).
		SetConnectTimeout(5 * time.Second).
		SetKeepAlive(20 * time.Second).
		SetPingTimeout(5 * time.Second).
		SetWriteTimeout(5 * time.Second).
		SetResumeSubs(true)

	opts.SetOnConnectHandler(func(c mqtt.Client) {
		currentTopic := ch.GetTopic()
		currentBroker := ch.BrokerURL()
		log.Info().Str("broker", currentBroker).Str("topic", currentTopic).Msg("MQTT подключен, подписка на топики...")
		if currentTopic != "" {
			c.Subscribe(currentTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				ch.handleIncoming(msg)
			})
		}
		ch.tunnelMu.RLock()
		tTopic := ch.tunnelTopic
		tHandler := ch.tunnelHandler
		ch.tunnelMu.RUnlock()
		if tTopic != "" && tHandler != nil {
			log.Info().Str("tunnel_topic", tTopic).Msg("MQTT подписка на туннельный поток...")
			c.Subscribe(tTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				ch.handleTunnelPayload(msg.Payload())
			})
		}
	}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			log.Warn().Err(err).Str("broker", ch.BrokerURL()).Msg("MQTT connection lost, reconnecting...")
		})

	client := mqtt.NewClient(opts)
	ch.client = client

	// Фоновое подключение
	go func() {
		token := client.Connect()
		_ = token.WaitTimeout(5 * time.Second)
	}()

	return ch
}

// BrokerURL возвращает текущий адрес брокера
func (m *MQTTChannel) BrokerURL() string {
	m.brokerMu.RLock()
	defer m.brokerMu.RUnlock()
	return m.brokerURL
}

// IsConnected возвращает true если соединение с брокером активно
func (m *MQTTChannel) IsConnected() bool {
	return m.client != nil && m.client.IsConnected()
}

// ReconnectWithBroker переключает MQTT канал на новый брокер «на лету»
func (m *MQTTChannel) ReconnectWithBroker(newBrokerURL string) error {
	if newBrokerURL == "" {
		return fmt.Errorf("empty broker URL")
	}
	m.brokerMu.Lock()
	if m.brokerURL == newBrokerURL && m.client != nil && m.client.IsConnected() {
		m.brokerMu.Unlock()
		return nil
	}
	oldURL := m.brokerURL
	m.brokerURL = newBrokerURL
	clientID := m.clientID
	username := m.username
	password := m.password
	m.name = "mqtt:" + newBrokerURL
	m.brokerMu.Unlock()

	log.Info().Str("old_broker", oldURL).Str("new_broker", newBrokerURL).Msg("🔄 Переподключение MQTT канала к новому брокеру...")

	if m.client != nil {
		m.client.Disconnect(250)
	}

	opts := mqtt.NewClientOptions().AddBroker(newBrokerURL)
	if strings.HasPrefix(newBrokerURL, "ssl://") || strings.HasPrefix(newBrokerURL, "tls://") || strings.HasPrefix(newBrokerURL, "tcps://") || strings.HasPrefix(newBrokerURL, "wss://") {
		opts.SetTLSConfig(crypto.BuildTLSConfig(newBrokerURL))
	}

	opts.SetClientID(fmt.Sprintf("nb-%s-%d", clientID, time.Now().UnixNano()%1000000)).
		SetUsername(username).
		SetPassword(password).
		SetCleanSession(true).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(1 * time.Second).
		SetConnectTimeout(5 * time.Second).
		SetKeepAlive(20 * time.Second).
		SetPingTimeout(5 * time.Second).
		SetWriteTimeout(5 * time.Second).
		SetResumeSubs(true)

	opts.SetOnConnectHandler(func(c mqtt.Client) {
		currentTopic := m.GetTopic()
		log.Info().Str("broker", newBrokerURL).Str("topic", currentTopic).Msg("MQTT подключен к новому брокеру, подписка на топики...")
		if currentTopic != "" {
			c.Subscribe(currentTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				m.handleIncoming(msg)
			})
		}
		m.tunnelMu.RLock()
		tTopic := m.tunnelTopic
		tHandler := m.tunnelHandler
		m.tunnelMu.RUnlock()
		if tTopic != "" && tHandler != nil {
			c.Subscribe(tTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				m.handleTunnelPayload(msg.Payload())
			})
		}
	}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			log.Warn().Err(err).Str("broker", newBrokerURL).Msg("MQTT connection lost, reconnecting...")
		})

	newClient := mqtt.NewClient(opts)
	m.client = newClient

	tok := newClient.Connect()
	if !tok.WaitTimeout(5 * time.Second) {
		return fmt.Errorf("MQTT connect timeout к %s", newBrokerURL)
	}
	return tok.Error()
}

func (m *MQTTChannel) GetTopic() string {
	m.topicMu.RLock()
	defer m.topicMu.RUnlock()
	return m.topic
}

func (m *MQTTChannel) handleIncoming(msg mqtt.Message) {
	data := msg.Payload()
	if len(data) == 0 {
		return
	}

	m.keyMu.RLock()
	hasKey := m.hasSignKey
	signKey := m.signKey
	m.keyMu.RUnlock()

	var payloadBytes []byte
	if hasKey {
		// Режим строгой безопасности: задан NetworkKey.
		// ВСЕ сигналы ОБЯЗАТЕЛЬНО должны быть подписаны HMAC-SHA256 фреймом.
		if len(data) < 40 {
			log.Warn().Int("len", len(data)).Msg("🛡️ MQTT signaling frame dropped: payload too short for signed frame")
			return
		}
		// Запрещаем сырой JSON в защищённом режиме
		if data[0] == '{' {
			log.Warn().Msg("🛡️ MQTT signaling frame dropped: plaintext JSON rejected when NetworkKey is active")
			return
		}

		inner, _, err := crypto.VerifyFrame(data, signKey, 300*time.Second)
		if err != nil {
			log.Warn().Err(err).Msg("🛡️ MQTT signaling frame dropped: invalid HMAC signature or replay detected")
			return
		}
		payloadBytes = inner
	} else {
		// Легаси режим: NetworkKey не задан. Разрешаем только сырой JSON.
		if len(data) > 0 && data[0] != '{' {
			log.Warn().Msg("🛡️ MQTT frame is HMAC-signed or binary, but channel has no NetworkKey configured — dropping")
			return
		}
		payloadBytes = data
	}

	var p Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil || p.DeviceID == "" {
		return
	}
	// Скоростная дедупликация: отсекаем повторные маяки за 1000 мс
	if m.dedup != nil && m.dedup.IsDuplicate(p.DeviceID, 1000) {
		return
	}

	p.Channel = "mqtt"
	m.outMu.RLock()
	defer m.outMu.RUnlock()
	for _, out := range m.outChans {
		cp := p
		select {
		case out <- &cp:
		default:
		}
	}
}

func (m *MQTTChannel) Name() string {
	if m.name != "" {
		return m.name
	}
	m.brokerMu.RLock()
	b := m.brokerURL
	m.brokerMu.RUnlock()
	if b != "" {
		return "mqtt:" + b
	}
	return "mqtt"
}

// UpdateTopic динамически меняет топик без разрыва соединения
func (m *MQTTChannel) UpdateTopic(newTopic string) {
	if newTopic == "" {
		return
	}
	m.topicMu.Lock()
	if newTopic == m.topic {
		m.topicMu.Unlock()
		return
	}
	oldTopic := m.topic
	m.topic = newTopic
	m.topicMu.Unlock()

	if m.dedup != nil {
		m.dedup.Clear()
	}

	if m.client != nil {
		if m.client.IsConnected() {
			if oldTopic != "" {
				m.client.Unsubscribe(oldTopic)
			}
			m.client.Subscribe(newTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				m.handleIncoming(msg)
			})
			log.Info().Str("old_topic", oldTopic).Str("new_topic", newTopic).Msg("MQTT топик динамически обновлен")
		} else {
			tok := m.client.Connect()
			if tok.WaitTimeout(3 * time.Second) && tok.Error() == nil {
				m.client.Subscribe(newTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
					m.handleIncoming(msg)
				})
				log.Info().Str("new_topic", newTopic).Msg("MQTT переподключен и подписан на новый топик")
			}
		}
	}

	m.tunnelMu.Lock()
	if m.tunnelHandler != nil && m.myDevID != "" {
		oldTunnelTopic := m.tunnelTopic
		newTunnelTopic := fmt.Sprintf("%s/tunnel/%s", newTopic, m.myDevID)
		m.tunnelTopic = newTunnelTopic
		if m.client != nil && m.client.IsConnected() {
			if oldTunnelTopic != "" && oldTunnelTopic != newTunnelTopic {
				m.client.Unsubscribe(oldTunnelTopic)
			}
			m.client.Subscribe(newTunnelTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				if len(msg.Payload()) >= 20 && m.tunnelHandler != nil {
					m.tunnelHandler(msg.Payload())
				}
			})
			log.Info().Str("old_tunnel", oldTunnelTopic).Str("new_tunnel", newTunnelTopic).Msg("MQTT туннельный топик динамически обновлен")
		}
	}
	m.tunnelMu.Unlock()
}

func (m *MQTTChannel) Send(ctx context.Context, payload *Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	m.keyMu.RLock()
	hasKey := m.hasSignKey
	signKey := m.signKey
	m.keyMu.RUnlock()

	dataToSend := data
	if hasKey {
		dataToSend = crypto.SignFrame(data, signKey)
	}

	if m.client == nil || !m.client.IsConnected() {
		if m.client == nil {
			return fmt.Errorf("MQTT client is nil (%s)", m.BrokerURL())
		}
		tok := m.client.Connect()
		if !tok.WaitTimeout(5 * time.Second) {
			return fmt.Errorf("MQTT reconnect timeout (%s)", m.BrokerURL())
		}
		if err := tok.Error(); err != nil {
			return fmt.Errorf("MQTT reconnect (%s): %w", m.BrokerURL(), err)
		}
	}

	targetTopic := m.GetTopic()
	token := m.client.Publish(targetTopic, 0, false, dataToSend)
	if !token.WaitTimeout(8 * time.Second) {
		return fmt.Errorf("MQTT publish timeout (%s)", m.BrokerURL())
	}
	return token.Error()
}

func (m *MQTTChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload, 128)

	m.outMu.Lock()
	m.outChans = append(m.outChans, out)
	m.outMu.Unlock()

	if m.client.IsConnected() {
		m.client.Subscribe(m.topic, 0, func(cl mqtt.Client, msg mqtt.Message) {
			m.handleIncoming(msg)
		})
	}

	go func() {
		<-ctx.Done()
		m.outMu.Lock()
		for i, c := range m.outChans {
			if c == out {
				m.outChans = append(m.outChans[:i], m.outChans[i+1:]...)
				break
			}
		}
		m.outMu.Unlock()
		close(out)
	}()

	return out, nil
}

func (m *MQTTChannel) IsAvailable(ctx context.Context) bool {
	return m.client != nil && m.client.IsConnected()
}

// PublishTunnelData отправляет сырой IP пакет туннеля целевому устройству через быстрый MQTT канал
func (m *MQTTChannel) PublishTunnelData(targetDevID string, pkt []byte) error {
	if !m.client.IsConnected() {
		return fmt.Errorf("MQTT client not connected")
	}

	m.keyMu.RLock()
	hasKey := m.hasSignKey
	signKey := m.signKey
	m.keyMu.RUnlock()

	dataToSend := pkt
	if hasKey {
		dataToSend = crypto.SignFrame(pkt, signKey)
	}

	topic := fmt.Sprintf("%s/tunnel/%s", m.GetTopic(), targetDevID)
	tok := m.client.Publish(topic, 0, false, dataToSend)
	return tok.Error()
}

// SubscribeTunnelData подписывается на входящие пакеты туннеля для текущего узла
func (m *MQTTChannel) SubscribeTunnelData(myDevID string, onPkt func(pkt []byte)) {
	topic := fmt.Sprintf("%s/tunnel/%s", m.GetTopic(), myDevID)
	m.tunnelMu.Lock()
	m.myDevID = myDevID
	m.tunnelTopic = topic
	m.tunnelHandler = onPkt
	m.tunnelMu.Unlock()

	if m.client != nil && m.client.IsConnected() {
		m.client.Subscribe(topic, 0, func(cl mqtt.Client, msg mqtt.Message) {
			m.handleTunnelPayload(msg.Payload())
		})
	}
}

// handleTunnelPayload верифицирует и передаёт входящий пакет туннеля обработчику.
func (m *MQTTChannel) handleTunnelPayload(raw []byte) {
	m.tunnelMu.RLock()
	handler := m.tunnelHandler
	m.tunnelMu.RUnlock()

	if handler == nil || len(raw) == 0 {
		return
	}

	m.keyMu.RLock()
	hasKey := m.hasSignKey
	signKey := m.signKey
	m.keyMu.RUnlock()

	if hasKey {
		if len(raw) < 40 {
			log.Warn().Int("len", len(raw)).Msg("🛡️ MQTT tunnel frame dropped: payload too short for HMAC verification")
			return
		}
		if raw[0] == '{' {
			log.Warn().Msg("🛡️ MQTT tunnel frame dropped: plaintext payload rejected when NetworkKey is active")
			return
		}
		inner, _, err := crypto.VerifyFrame(raw, signKey, 300*time.Second)
		if err != nil {
			log.Warn().Err(err).Msg("🛡️ MQTT tunnel frame dropped: invalid HMAC signature or replay detected")
			return
		}
		if len(inner) >= 20 {
			handler(inner)
		}
		return
	}

	// Legacy mode (без NetworkKey): разрешаем сырой IP-пакет (IPv4 заголовок >= 20 байт)
	if len(raw) >= 20 {
		handler(raw)
	}
}

func (m *MQTTChannel) Close() error {
	m.client.Disconnect(250)
	return nil
}
