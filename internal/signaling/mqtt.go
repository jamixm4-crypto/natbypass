package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/rs/zerolog/log"
)

type MQTTChannel struct {
	client        mqtt.Client
	topic         string
	outMu         sync.RWMutex
	outChans      []chan *Payload
	tunnelMu      sync.RWMutex
	tunnelTopic   string
	tunnelHandler func(pkt []byte)
}

func NewMQTTChannel(brokerURL, topic, clientID, username, password string) *MQTTChannel {
	ch := &MQTTChannel{
		topic: topic,
	}

	if brokerURL == "" {
		brokerURL = "tcp://broker.emqx.io:1883"
	}

	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL)

	// Автоматический резервный брокер для максимальной надежности
	if strings.Contains(brokerURL, "broker.emqx.io") {
		opts.AddBroker("tcp://broker.hivemq.com:1883")
	} else if strings.Contains(brokerURL, "broker.hivemq.com") {
		opts.AddBroker("tcp://broker.emqx.io:1883")
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

	// LWT (Last Will and Testament): брокер моментально оповестит сеть если узел отключится
	lwtPayload, _ := json.Marshal(&Payload{
		DeviceID: clientID,
		Offline:  true,
		Leave:    true,
	})
	opts.SetWill(topic, string(lwtPayload), 0, false)

	opts.SetOnConnectHandler(func(c mqtt.Client) {
		log.Info().Str("broker", brokerURL).Str("topic", topic).Msg("MQTT подключен, подписка на топики...")
		c.Subscribe(topic, 0, func(cl mqtt.Client, msg mqtt.Message) {
			ch.handleIncoming(msg)
		})
		ch.tunnelMu.RLock()
		tTopic := ch.tunnelTopic
		tHandler := ch.tunnelHandler
		ch.tunnelMu.RUnlock()
		if tTopic != "" && tHandler != nil {
			log.Info().Str("tunnel_topic", tTopic).Msg("MQTT подписка на туннельный поток...")
			c.Subscribe(tTopic, 0, func(cl mqtt.Client, msg mqtt.Message) {
				if len(msg.Payload()) >= 20 {
					tHandler(msg.Payload())
				}
			})
		}
	}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			log.Warn().Err(err).Msg("MQTT connection lost, reconnecting...")
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

func (m *MQTTChannel) handleIncoming(msg mqtt.Message) {
	var p Payload
	if err := json.Unmarshal(msg.Payload(), &p); err == nil && p.DeviceID != "" {
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
		if tok.WaitTimeout(4 * time.Second) && tok.Error() != nil {
			return fmt.Errorf("MQTT reconnect: %w", tok.Error())
		}
	}

	token := m.client.Publish(m.topic, 0, false, data)
	if !token.WaitTimeout(4 * time.Second) {
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
	topic := fmt.Sprintf("%s/tunnel/%s", m.topic, myDevID)
	m.tunnelMu.Lock()
	m.tunnelTopic = topic
	m.tunnelHandler = onPkt
	m.tunnelMu.Unlock()

	if m.client != nil && m.client.IsConnected() {
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
