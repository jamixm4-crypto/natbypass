package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Profile — изолированный профиль mesh-сети с собственным топиком, ключами и настройками каналов
type Profile struct {
	ID          string    `json:"id" mapstructure:"id" yaml:"id"`
	Name        string    `json:"name" mapstructure:"name" yaml:"name"`
	NetworkKey  string    `json:"network_key,omitempty" mapstructure:"network_key" yaml:"network_key,omitempty"`
	VirtualIP   string    `json:"virtual_ip,omitempty" mapstructure:"virtual_ip" yaml:"virtual_ip,omitempty"`
	MQTTBroker  string    `json:"mqtt_broker" mapstructure:"mqtt_broker" yaml:"mqtt_broker"`
	MQTTTopic   string    `json:"mqtt_topic" mapstructure:"mqtt_topic" yaml:"mqtt_topic"`
	MQTTUser    string    `json:"mqtt_user,omitempty" mapstructure:"mqtt_user" yaml:"mqtt_user,omitempty"`
	MQTTPass    string    `json:"mqtt_pass,omitempty" mapstructure:"mqtt_pass" yaml:"mqtt_pass,omitempty"`
	TGToken     string    `json:"tg_token,omitempty" mapstructure:"tg_token" yaml:"tg_token,omitempty"`
	TGChatID    int64     `json:"tg_chat_id,omitempty" mapstructure:"tg_chat_id" yaml:"tg_chat_id,omitempty"`
	TGProxy     string    `json:"tg_proxy,omitempty" mapstructure:"tg_proxy" yaml:"tg_proxy,omitempty"`
	AWGPreset   string    `json:"awg_preset" mapstructure:"awg_preset" yaml:"awg_preset"`
	IsActive    bool      `json:"is_active" mapstructure:"is_active" yaml:"is_active"`
	CreatedAt   time.Time `json:"created_at" mapstructure:"created_at" yaml:"created_at"`
}

// GenerateRandomHex возвращает криптостойкую случайную hex-строку
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateDefaultProfile создает новый профиль с уникальным случайным топиком и сетевым ключом
func GenerateDefaultProfile(name string) Profile {
	if name == "" {
		name = "Основная сеть"
	}
	topicID := GenerateRandomHex(8)
	return Profile{
		ID:         "p-" + GenerateRandomHex(4),
		Name:       name,
		NetworkKey: GenerateRandomHex(16),
		MQTTBroker: "tcp://broker.emqx.io:1883",
		MQTTTopic:  "natbypass/mesh/" + topicID,
		AWGPreset:  "dpi",
		IsActive:   true,
		CreatedAt:  time.Now(),
	}
}

// EnsureActiveProfile гарантирует наличие хотя бы одного профиля и синхронизирует каналы
func (c *Config) EnsureActiveProfile() *Profile {
	if len(c.Profiles) == 0 {
		defaultProf := GenerateDefaultProfile("Основная сеть")
		for _, ch := range c.Signaling.Channels {
			if ch.Type == "mqtt" {
				if b, ok := ch.Params["broker"]; ok && b != "" {
					defaultProf.MQTTBroker = b
				} else if b, ok := ch.Params["broker_url"]; ok && b != "" {
					defaultProf.MQTTBroker = b
				}
				if t, ok := ch.Params["topic"]; ok && t != "" {
					defaultProf.MQTTTopic = t
				}
				if k, ok := ch.Params["network_key"]; ok && k != "" {
					defaultProf.NetworkKey = k
				}
			} else if ch.Type == "telegram" {
				if tok, ok := ch.Params["token"]; ok && tok != "" {
					defaultProf.TGToken = tok
				} else if tok, ok := ch.Params["bot_token"]; ok && tok != "" {
					defaultProf.TGToken = tok
				}
				if cidStr, ok := ch.Params["chat_id"]; ok && cidStr != "" {
					if cid, err := strconv.ParseInt(cidStr, 10, 64); err == nil {
						defaultProf.TGChatID = cid
					}
				}
			}
		}
		c.Profiles = append(c.Profiles, defaultProf)
		c.ActiveProfileID = defaultProf.ID
	}

	var active *Profile
	for i := range c.Profiles {
		if c.Profiles[i].ID == c.ActiveProfileID {
			c.Profiles[i].IsActive = true
			active = &c.Profiles[i]
		} else {
			c.Profiles[i].IsActive = false
		}
	}

	if active == nil && len(c.Profiles) > 0 {
		c.Profiles[0].IsActive = true
		c.ActiveProfileID = c.Profiles[0].ID
		active = &c.Profiles[0]
	}

	// Синхронизируем каналы связи в SignalingConfig под активный профиль
	if active != nil {
		c.SyncSignalingWithProfile(active)
	}

	return active
}

// GetActiveProfile возвращает текущий активный профиль
func (c *Config) GetActiveProfile() *Profile {
	return c.EnsureActiveProfile()
}

// SyncSignalingWithProfile применяет настройки профиля в общую конфигурацию каналов
func (c *Config) SyncSignalingWithProfile(p *Profile) {
	if p == nil {
		return
	}

	var newChannels []ChannelConfig

	// 1. MQTT Канал
	mqttBroker := p.MQTTBroker
	if mqttBroker == "" {
		mqttBroker = "tcp://broker.emqx.io:1883"
	}
	mqttTopic := p.MQTTTopic
	if mqttTopic == "" {
		mqttTopic = "natbypass/mesh/" + GenerateRandomHex(8)
		p.MQTTTopic = mqttTopic
	}

	mqttParams := map[string]string{
		"broker":     mqttBroker,
		"broker_url": mqttBroker,
		"topic":      mqttTopic,
	}
	if p.MQTTUser != "" {
		mqttParams["username"] = p.MQTTUser
	}
	if p.MQTTPass != "" {
		mqttParams["password"] = p.MQTTPass
	}
	if p.NetworkKey != "" {
		mqttParams["network_key"] = p.NetworkKey
	}

	newChannels = append(newChannels, ChannelConfig{
		Type:     "mqtt",
		Priority: 1,
		Enabled:  true,
		Params:   mqttParams,
	})

	// 2. Telegram Канал (если настроен)
	if p.TGToken != "" && p.TGChatID != 0 {
		tgParams := map[string]string{
			"bot_token": p.TGToken,
			"chat_id":   fmt.Sprintf("%d", p.TGChatID),
		}
		if p.TGProxy != "" {
			tgParams["proxy"] = p.TGProxy
		}
		newChannels = append(newChannels, ChannelConfig{
			Type:     "telegram",
			Priority: 2,
			Enabled:  true,
			Params:   tgParams,
		})
	}

	c.Signaling.Channels = newChannels
}

// SwitchProfile переключает активный профиль по ID
func (c *Config) SwitchProfile(profileID string) (*Profile, error) {
	var target *Profile
	for i := range c.Profiles {
		if c.Profiles[i].ID == profileID {
			c.Profiles[i].IsActive = true
			c.ActiveProfileID = profileID
			target = &c.Profiles[i]
		} else {
			c.Profiles[i].IsActive = false
		}
	}
	if target == nil {
		return nil, fmt.Errorf("profile with ID %s not found", profileID)
	}

	c.SyncSignalingWithProfile(target)
	return target, nil
}

// AddOrUpdateProfile добавляет или обновляет профиль
func (c *Config) AddOrUpdateProfile(p Profile) *Profile {
	if p.ID == "" {
		p.ID = "p-" + GenerateRandomHex(4)
	}
	if p.MQTTTopic == "" {
		p.MQTTTopic = "natbypass/mesh/" + GenerateRandomHex(8)
	}
	if p.MQTTBroker == "" {
		p.MQTTBroker = "tcp://broker.emqx.io:1883"
	}
	if p.AWGPreset == "" {
		p.AWGPreset = "dpi"
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}

	found := false
	for i := range c.Profiles {
		// Обновляем существующий профиль ТОЛЬКО при точном совпадении ID
		if c.Profiles[i].ID == p.ID {
			c.Profiles[i] = p
			if p.IsActive {
				c.ActiveProfileID = p.ID
			}
			found = true
			break
		}
	}
	if !found {
		c.Profiles = append(c.Profiles, p)
		if p.IsActive || len(c.Profiles) == 1 {
			c.ActiveProfileID = p.ID
		}
	}

	return c.EnsureActiveProfile()
}

// DeleteProfile удаляет профиль
func (c *Config) DeleteProfile(profileID string) error {
	if len(c.Profiles) <= 1 {
		return fmt.Errorf("cannot delete the only profile")
	}

	var newProfiles []Profile
	for _, p := range c.Profiles {
		if p.ID != profileID {
			newProfiles = append(newProfiles, p)
		}
	}

	if len(newProfiles) == len(c.Profiles) {
		return fmt.Errorf("profile %s not found", profileID)
	}

	c.Profiles = newProfiles
	if c.ActiveProfileID == profileID {
		c.ActiveProfileID = c.Profiles[0].ID
	}

	c.EnsureActiveProfile()
	return nil
}

// ExportProfileURI формирует URL и QR payload для быстрого импорта профиля
func ExportProfileURI(p Profile) string {
	q := url.Values{}
	q.Set("id", p.ID)
	q.Set("name", p.Name)
	q.Set("broker", p.MQTTBroker)
	q.Set("topic", p.MQTTTopic)
	if p.NetworkKey != "" {
		q.Set("key", p.NetworkKey)
	}
	if p.MQTTUser != "" {
		q.Set("user", p.MQTTUser)
	}
	if p.MQTTPass != "" {
		q.Set("pass", p.MQTTPass)
	}
	if p.TGToken != "" {
		q.Set("tg_token", p.TGToken)
	}
	if p.TGChatID != 0 {
		q.Set("tg_chat", fmt.Sprintf("%d", p.TGChatID))
	}
	if p.TGProxy != "" {
		q.Set("tg_proxy", p.TGProxy)
	}
	if p.AWGPreset != "" {
		q.Set("awg", p.AWGPreset)
	}

	return "natbypass://profile?" + q.Encode()
}

// ImportProfileURI парсит строку импорта (natbypass://profile?... или base64/JSON)
func ImportProfileURI(raw string) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty profile payload")
	}

	// 1. Попытка распарсить как natbypass://profile?...
	if strings.HasPrefix(raw, "natbypass://profile?") || strings.HasPrefix(raw, "natbypass://profile") {
		u, err := url.Parse(raw)
		if err == nil {
			q := u.Query()
			name := q.Get("name")
			if name == "" {
				name = "Импортированная сеть"
			}
			topic := q.Get("topic")
			if topic == "" {
				topic = "natbypass/mesh/" + GenerateRandomHex(8)
			}
			broker := q.Get("broker")
			if broker == "" {
				broker = "tcp://broker.emqx.io:1883"
			}
			var tgChat int64
			if chatStr := q.Get("tg_chat"); chatStr != "" {
				tgChat, _ = strconv.ParseInt(chatStr, 10, 64)
			}

			id := q.Get("id")
			if id == "" {
				id = "p-" + GenerateRandomHex(4)
			}
			p := &Profile{
				ID:         id,
				Name:       name,
				NetworkKey: q.Get("key"),
				MQTTBroker: broker,
				MQTTTopic:  topic,
				MQTTUser:   q.Get("user"),
				MQTTPass:   q.Get("pass"),
				TGToken:    q.Get("tg_token"),
				TGChatID:   tgChat,
				TGProxy:    q.Get("tg_proxy"),
				AWGPreset:  q.Get("awg"),
				IsActive:   true,
				CreatedAt:  time.Now(),
			}
			if p.AWGPreset == "" {
				p.AWGPreset = "dpi"
			}
			return p, nil
		}
	}

	// 2. Попытка распарсить как Base64 JSON
	if data, err := base64.StdEncoding.DecodeString(raw); err == nil {
		var p Profile
		if err := json.Unmarshal(data, &p); err == nil && p.MQTTTopic != "" {
			if p.ID == "" {
				p.ID = "p-" + GenerateRandomHex(4)
			}
			p.IsActive = true
			p.CreatedAt = time.Now()
			return &p, nil
		}
	}

	// 3. Попытка распарсить как прямой JSON
	var p Profile
	if err := json.Unmarshal([]byte(raw), &p); err == nil && p.MQTTTopic != "" {
		if p.ID == "" {
			p.ID = "p-" + GenerateRandomHex(4)
		}
		p.IsActive = true
		p.CreatedAt = time.Now()
		return &p, nil
	}

	return nil, fmt.Errorf("unsupported profile format")
}


// GetNetworkKeyBytes возвращает 32-байтный ключ шифрования для сети
func (p *Profile) GetNetworkKeyBytes() [32]byte {
	seed := p.NetworkKey
	if seed == "" {
		seed = p.MQTTTopic + ":" + p.ID
	}
	h := sha256.Sum256([]byte(seed))
	return h
}

// GetDeterministicVIP возвращает постоянный фиксированный IP-адрес узла в данной сети
func (p *Profile) GetDeterministicVIP(deviceID string) string {
	if p.VirtualIP != "" && strings.HasPrefix(p.VirtualIP, "100.64.200.") {
		return p.VirtualIP
	}
	h := sha256.Sum256([]byte(deviceID + ":" + p.ID + ":" + p.MQTTTopic))
	octet := int(h[0])%240 + 10 // Диапазон 100.64.200.10 - 100.64.200.249
	vip := fmt.Sprintf("100.64.200.%d", octet)
	p.VirtualIP = vip
	return vip
}
