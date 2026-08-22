package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/rs/zerolog/log"
)

type MQTTChannel struct {
	client   mqtt.Client
	topic    string
	outMu    sync.RWMutex
	outChans []chan *Payload
}

func NewMQTTChannel(brokerURL, topic, clientID, username, password string) *MQTTChannel {
	ch := &MQTTChannel{
		topic: topic,
	}

	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(fmt.Sprintf("nb-%s-%d", clientID, time.Now().UnixNano()%1000000)).
		SetUsername(username).
		SetPassword(password).
		SetCleanSession(true).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(2 * time.Second).
		SetKeepAlive(10 * time.Second).
		SetPingTimeout(3 * time.Second).
		SetResumeSubs(true).
		SetOnConnectHandler(func(c mqtt.Client) {
			log.Info().Str("broker", brokerURL).Str("topic", topic).Msg("MQTT подключен, подписка на топик...")
			c.Subscribe(topic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				var p Payload
				if err := json.Unmarshal(msg.Payload(), &p); err == nil && p.DeviceID != "" {
					ch.outMu.RLock()
					for _, out := range ch.outChans {
						select {
						case out <- &p:
						default:
						}
					}
					ch.outMu.RUnlock()
				}
			})
		}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			log.Warn().Err(err).Msg("MQTT connection lost")
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

func (m *MQTTChannel) Name() string {
	return "mqtt"
}

func (m *MQTTChannel) Send(ctx context.Context, payload *Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if !m.client.IsConnected() {
		tok := m.client.Connect()
		_ = tok.WaitTimeout(3 * time.Second)
	}

	token := m.client.Publish(m.topic, 0, false, data)
	if !token.WaitTimeout(5 * time.Second) {
		return fmt.Errorf("MQTT publish timeout")
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
			var p Payload
			if err := json.Unmarshal(msg.Payload(), &p); err == nil && p.DeviceID != "" {
				select {
				case out <- &p:
				default:
				}
			}
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
	return m.client.IsConnected()
}

// PublishTunnelData отправляет сырой IP пакет туннеля целевому устройству через быстрый MQTT канал
func (m *MQTTChannel) PublishTunnelData(targetDevID string, pkt []byte) error {
	if !m.client.IsConnected() {
		return fmt.Errorf("MQTT client not connected")
	}
	topic := fmt.Sprintf("%s/tunnel/%s", m.topic, targetDevID)
	tok := m.client.Publish(topic, 0, false, pkt)
	_ = tok.WaitTimeout(1 * time.Second)
	return tok.Error()
}

// SubscribeTunnelData подписывается на входящие пакеты туннеля для текущего узла
func (m *MQTTChannel) SubscribeTunnelData(myDevID string, onPkt func(pkt []byte)) {
	if m.client.IsConnected() {
		topic := fmt.Sprintf("%s/tunnel/%s", m.topic, myDevID)
		m.client.Subscribe(topic, 0, func(cl mqtt.Client, msg mqtt.Message) {
			if len(msg.Payload()) >= 20 && onPkt != nil {
				onPkt(msg.Payload())
			}
		})
	}
}

func (m *MQTTChannel) Close() error {
	m.client.Disconnect(250)
	return nil
}
