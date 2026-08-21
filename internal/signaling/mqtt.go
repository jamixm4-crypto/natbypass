package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/rs/zerolog/log"
)

type MQTTChannel struct {
	client mqtt.Client
	topic  string
}

func NewMQTTChannel(brokerURL, topic, clientID, username, password string) *MQTTChannel {
	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetUsername(username).
		SetPassword(password).
		SetCleanSession(false).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetOnConnectHandler(func(c mqtt.Client) {
			log.Info().Str("broker", brokerURL).Msg("MQTT connected")
		}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			log.Warn().Err(err).Msg("MQTT connection lost")
		})

	client := mqtt.NewClient(opts)
	
	go func() {
		token := client.Connect()
		if token.WaitTimeout(5*time.Second) && token.Error() != nil {
			log.Warn().Err(token.Error()).Msg("MQTT брокер пока недоступен (будет повтор в фоне)")
		}
	}()

	return &MQTTChannel{
		client: client,
		topic:  topic,
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

	token := m.client.Publish(m.topic, 1, false, data)
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("publish timeout")
	}
	return token.Error()
}

func (m *MQTTChannel) Receive(ctx context.Context) (<-chan *Payload, error) {
	out := make(chan *Payload)

	token := m.client.Subscribe(m.topic, 1, func(client mqtt.Client, msg mqtt.Message) {
		var p Payload
		if err := json.Unmarshal(msg.Payload(), &p); err == nil {
			out <- &p
		}
	})

	if token.WaitTimeout(3*time.Second) && token.Error() != nil {
		log.Warn().Err(token.Error()).Msg("MQTT подписка отложена (нет подключения)")
	}

	go func() {
		<-ctx.Done()
		m.client.Unsubscribe(m.topic)
	}()

	return out, nil
}

func (m *MQTTChannel) IsAvailable(ctx context.Context) bool {
	return m.client.IsConnected()
}

func (m *MQTTChannel) Close() error {
	m.client.Disconnect(250)
	return nil
}
