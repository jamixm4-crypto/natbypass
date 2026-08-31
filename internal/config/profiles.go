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
	ID                  string    `json:"id" mapstructure:"id" yaml:"id"`
	Name                string    `json:"name" mapstructure:"name" yaml:"name"`
	NetworkKey          string    `json:"network_key,omitempty" mapstructure:"network_key" yaml:"network_key,omitempty"`
	VirtualIP           string    `json:"virtual_ip,omitempty" mapstructure:"virtual_ip" yaml:"virtual_ip,omitempty"`
	Subnet              string    `json:"subnet,omitempty" mapstructure:"subnet" yaml:"subnet,omitempty"`
	MQTTBroker          string    `json:"mqtt_broker" mapstructure:"mqtt_broker" yaml:"mqtt_broker"`
	MQTTTopic           string    `json:"mqtt_topic" mapstructure:"mqtt_topic" yaml:"mqtt_topic"`
	MQTTUser            string    `json:"mqtt_user,omitempty" mapstructure:"mqtt_user" yaml:"mqtt_user,omitempty"`
	MQTTPass            string    `json:"mqtt_pass,omitempty" mapstructure:"mqtt_pass" yaml:"mqtt_pass,omitempty"`
	TGToken             string    `json:"tg_token,omitempty" mapstructure:"tg_token" yaml:"tg_token,omitempty"`
	TGChatID            int64     `json:"tg_chat_id,omitempty" mapstructure:"tg_chat_id" yaml:"tg_chat_id,omitempty"`
	TGProxy             string    `json:"tg_proxy,omitempty" mapstructure:"tg_proxy" yaml:"tg_proxy,omitempty"`
	AWGPreset           string    `json:"awg_preset" mapstructure:"awg_preset" yaml:"awg_preset"`
	Jc                  int       `json:"jc,omitempty" mapstructure:"jc" yaml:"jc,omitempty"`
	Jmin                int       `json:"jmin,omitempty" mapstructure:"jmin" yaml:"jmin,omitempty"`
	Jmax                int       `json:"jmax,omitempty" mapstructure:"jmax" yaml:"jmax,omitempty"`
	S1                  int       `json:"s1,omitempty" mapstructure:"s1" yaml:"s1,omitempty"`
	S2                  int       `json:"s2,omitempty" mapstructure:"s2" yaml:"s2,omitempty"`
	H1                  uint32    `json:"h1,omitempty" mapstructure:"h1" yaml:"h1,omitempty"`
	H2                  uint32    `json:"h2,omitempty" mapstructure:"h2" yaml:"h2,omitempty"`
	H3                  uint32    `json:"h3,omitempty" mapstructure:"h3" yaml:"h3,omitempty"`
	H4                  uint32    `json:"h4,omitempty" mapstructure:"h4" yaml:"h4,omitempty"`
	HeaderProtectionKey string    `json:"header_protection_key,omitempty" mapstructure:"header_protection_key" yaml:"header_protection_key,omitempty"`
	RandomTrailers      bool      `json:"random_trailers,omitempty" mapstructure:"random_trailers" yaml:"random_trailers,omitempty"`
	DisableCookies      bool      `json:"disable_cookies,omitempty" mapstructure:"disable_cookies" yaml:"disable_cookies,omitempty"`
	IsActive            bool      `json:"is_active" mapstructure:"is_active" yaml:"is_active"`
	CreatedAt           time.Time `json:"created_at" mapstructure:"created_at" yaml:"created_at"`
}

// GenerateRandomHex возвращает криптостойкую случайную hex-строку
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateDefaultProfile создает новый профиль с уникальным случайным топиком и сетевым ключом

// GenerateRandomAWGProfileParams генерирует полностью уникальный набор параметров AWG 3.1 для новой сети
func GenerateRandomAWGProfileParams() (jc, jmin, jmax, s1, s2 int, h1, h2, h3, h4 uint32, hpKey string) {
	var b [16]byte
	_, _ = rand.Read(b[:])
	h1 = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	h2 = uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	h3 = uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11])
	h4 = uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	if h1 < 1000000 { h1 += 1000000 }
	if h2 < 1000000 { h2 += 1000000 }
	if h3 < 1000000 { h3 += 1000000 }
	if h4 < 1000000 { h4 += 1000000 }

	var r [4]byte
	_, _ = rand.Read(r[:])
	jc = 3 + int(r[0]%4)
	jmin = 25 + int(r[1]%25)
	jmax = jmin + 30 + int(r[2]%35)
	s1 = 20 + int(r[3]%45)
	s2 = 20 + int(r[0]%45)
	hpKey = GenerateRandomHex(32)
	return
}

func GenerateDefaultProfile(name string) Profile {
	if name == "" {
		name = "Основная сеть"
	}
	topicID := GenerateRandomHex(8)
	jc, jmin, jmax, s1, s2, h1, h2, h3, h4, hpKey := GenerateRandomAWGProfileParams()
	return Profile{
		ID:                  "p-" + GenerateRandomHex(4),
		Name:                name,
		NetworkKey:          GenerateRandomHex(16),
		MQTTBroker:          "tcp://broker.emqx.io:1883",
		MQTTTopic:           "natbypass/mesh/" + topicID,
		AWGPreset:           "custom",
		Jc:                  jc,
		Jmin:                jmin,
		Jmax:                jmax,
		S1:                  s1,
		S2:                  s2,
		H1:                  h1,
		H2:                  h2,
		H3:                  h3,
		H4:                  h4,
		HeaderProtectionKey: hpKey,
		RandomTrailers:      true,
		DisableCookies:      true,
		IsActive:            true,
		CreatedAt:           time.Now(),
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
		if defaultProf.MQTTTopic == "" && c.Signaling.MQTTTopic != "" {
			defaultProf.MQTTTopic = c.Signaling.MQTTTopic
		}
		if defaultProf.MQTTBroker == "" && c.Signaling.MQTTBroker != "" {
			defaultProf.MQTTBroker = c.Signaling.MQTTBroker
		}
		c.Profiles = append(c.Profiles, defaultProf)
		c.ActiveProfileID = defaultProf.ID
	}


	for i := range c.Profiles {
		if c.Profiles[i].H1 == 0 {
			jc, jmin, jmax, s1, s2, h1, h2, h3, h4, hpKey := GenerateRandomAWGProfileParams()
			c.Profiles[i].Jc = jc
			c.Profiles[i].Jmin = jmin
			c.Profiles[i].Jmax = jmax
			c.Profiles[i].S1 = s1
			c.Profiles[i].S2 = s2
			c.Profiles[i].H1 = h1
			c.Profiles[i].H2 = h2
			c.Profiles[i].H3 = h3
			c.Profiles[i].H4 = h4
			c.Profiles[i].HeaderProtectionKey = hpKey
			c.Profiles[i].RandomTrailers = true
			c.Profiles[i].DisableCookies = true
		}
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
		if c.Signaling.MQTTBroker != "" {
			mqttBroker = c.Signaling.MQTTBroker
			p.MQTTBroker = mqttBroker
		} else {
			mqttBroker = "tcp://broker.emqx.io:1883"
		}
	}
	mqttTopic := p.MQTTTopic
	if mqttTopic == "" {
		if c.Signaling.MQTTTopic != "" {
			mqttTopic = c.Signaling.MQTTTopic
			p.MQTTTopic = mqttTopic
		} else {
			mqttTopic = "natbypass/mesh/" + GenerateRandomHex(8)
			p.MQTTTopic = mqttTopic
		}
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

	if p.VirtualIP != "" {
		c.Network.Address = p.VirtualIP
	}
	if p.AWGPreset != "" {
		c.WireGuard.AWGPreset = p.AWGPreset
		c.WireGuard.AWG.Preset = p.AWGPreset
	}
	if p.H1 != 0 && p.H2 != 0 {
		c.WireGuard.AWG.H1 = p.H1
		c.WireGuard.AWG.H2 = p.H2
		c.WireGuard.AWG.H3 = p.H3
		c.WireGuard.AWG.H4 = p.H4
		c.WireGuard.AWG.S1 = p.S1
		c.WireGuard.AWG.S2 = p.S2
		c.WireGuard.AWG.Jc = p.Jc
		c.WireGuard.AWG.Jmin = p.Jmin
		c.WireGuard.AWG.Jmax = p.Jmax
		c.WireGuard.AWG.HeaderProtectionKey = p.HeaderProtectionKey
		c.WireGuard.AWG.RandomTrailers = p.RandomTrailers
		c.WireGuard.AWG.DisableCookies = p.DisableCookies
		c.WireGuard.AWG.Enabled = true
		c.WireGuard.AWG.Version = "3.1"
	}
	c.Signaling.Channels = newChannels
}

// SyncAWGWithProfile синхронизирует параметры AWG 3.1 активного профиля с конфигурацией WireGuard
func (c *Config) SyncAWGWithProfile(p *Profile) {
	if p == nil {
		return
	}
	if p.AWGPreset != "" {
		c.WireGuard.AWGPreset = p.AWGPreset
		c.WireGuard.AWG.Preset = p.AWGPreset
	}
	if p.H1 != 0 && p.H2 != 0 {
		c.WireGuard.AWG.H1 = p.H1
		c.WireGuard.AWG.H2 = p.H2
		c.WireGuard.AWG.H3 = p.H3
		c.WireGuard.AWG.H4 = p.H4
		c.WireGuard.AWG.S1 = p.S1
		c.WireGuard.AWG.S2 = p.S2
		c.WireGuard.AWG.Jc = p.Jc
		c.WireGuard.AWG.Jmin = p.Jmin
		c.WireGuard.AWG.Jmax = p.Jmax
		c.WireGuard.AWG.HeaderProtectionKey = p.HeaderProtectionKey
		c.WireGuard.AWG.RandomTrailers = p.RandomTrailers
		c.WireGuard.AWG.DisableCookies = p.DisableCookies
		c.WireGuard.AWG.Enabled = true
		c.WireGuard.AWG.Version = "3.1"
	}
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
	if p.VirtualIP != "" {
		q.Set("subnet", ExtractSubnetPrefix(p.VirtualIP)+".0/24")
	} else if p.Subnet != "" {
		q.Set("subnet", ExtractSubnetPrefix(p.Subnet)+".0/24")
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
	// Гарантируем экспорт полных параметров AWG 3.1, чтобы все узлы в сети имели 100% идентичные ключи обфускации
	h1, h2, h3, h4 := p.H1, p.H2, p.H3, p.H4
	s1, s2, jc, jmin, jmax := p.S1, p.S2, p.Jc, p.Jmin, p.Jmax
	hpk := p.HeaderProtectionKey
	rt := p.RandomTrailers
	dc := p.DisableCookies

	if h1 == 0 || h2 == 0 || h3 == 0 || h4 == 0 {
		genJc, genJmin, genJmax, genS1, genS2, genH1, genH2, genH3, genH4, genHPK := GenerateRandomAWGProfileParams()
		jc, jmin, jmax, s1, s2 = genJc, genJmin, genJmax, genS1, genS2
		h1, h2, h3, h4 = genH1, genH2, genH3, genH4
		hpk = genHPK
		rt = true
		dc = true
	}

	q.Set("h1", fmt.Sprintf("%d", h1))
	q.Set("h2", fmt.Sprintf("%d", h2))
	q.Set("h3", fmt.Sprintf("%d", h3))
	q.Set("h4", fmt.Sprintf("%d", h4))
	q.Set("s1", fmt.Sprintf("%d", s1))
	q.Set("s2", fmt.Sprintf("%d", s2))
	q.Set("jc", fmt.Sprintf("%d", jc))
	q.Set("jmin", fmt.Sprintf("%d", jmin))
	q.Set("jmax", fmt.Sprintf("%d", jmax))
	if hpk != "" {
		q.Set("hpk", hpk)
	}
	q.Set("rt", fmt.Sprintf("%t", rt))
	q.Set("dc", fmt.Sprintf("%t", dc))

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
				Subnet:     q.Get("subnet"),
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
			if h1Str := q.Get("h1"); h1Str != "" {
				if v, err := strconv.ParseUint(h1Str, 10, 32); err == nil { p.H1 = uint32(v) }
				if v, err := strconv.ParseUint(q.Get("h2"), 10, 32); err == nil { p.H2 = uint32(v) }
				if v, err := strconv.ParseUint(q.Get("h3"), 10, 32); err == nil { p.H3 = uint32(v) }
				if v, err := strconv.ParseUint(q.Get("h4"), 10, 32); err == nil { p.H4 = uint32(v) }
				if v, err := strconv.Atoi(q.Get("s1")); err == nil { p.S1 = v }
				if v, err := strconv.Atoi(q.Get("s2")); err == nil { p.S2 = v }
				if v, err := strconv.Atoi(q.Get("jc")); err == nil { p.Jc = v }
				if v, err := strconv.Atoi(q.Get("jmin")); err == nil { p.Jmin = v }
				if v, err := strconv.Atoi(q.Get("jmax")); err == nil { p.Jmax = v }
				p.HeaderProtectionKey = q.Get("hpk")
				p.RandomTrailers = q.Get("rt") == "true"
				p.DisableCookies = q.Get("dc") == "true"
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
	if p.VirtualIP != "" {
		clean := strings.TrimSpace(strings.Split(p.VirtualIP, "/")[0])
		if !strings.HasSuffix(clean, ".0") && clean != "" {
			return clean
		}
	}
	prefix := "100.64.200"
	if p.Subnet != "" {
		prefix = ExtractSubnetPrefix(p.Subnet)
	} else if p.VirtualIP != "" {
		prefix = ExtractSubnetPrefix(p.VirtualIP)
	}
	return GenerateSubnetIP(prefix, deviceID)
}

// ExtractSubnetPrefix извлекает подсеть вида "10.123.111" из "10.123.111.1/24", "10.123.111.0" или "10.123.111.1"
func ExtractSubnetPrefix(vipOrSubnet string) string {
	raw := strings.TrimSpace(vipOrSubnet)
	if raw == "" {
		return "100.64.200"
	}
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	parts := strings.Split(raw, ".")
	if len(parts) >= 3 {
		return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	}
	return "100.64.200"
}

// GenerateSubnetIP генерирует детерминированный уникальный IP-адрес в подсети для указанного deviceID
func GenerateSubnetIP(prefix string, deviceID string) string {
	if prefix == "" {
		prefix = "100.64.200"
	}
	h := sha256.Sum256([]byte(deviceID))
	// Диапазон октетов 2..254 (избегая 1 как дефолтный шлюз/создатель и 0/255)
	octet := int(h[0]%250) + 2
	if octet == 1 {
		octet = 2
	}
	return fmt.Sprintf("%s.%d", prefix, octet)
}

// ResolveVirtualIP возвращает актуальный уникальный Virtual IP узла в подсети активного профиля
func ResolveVirtualIP(cfg *Config, deviceID string) string {
	if cfg == nil {
		return GenerateSubnetIP("100.64.200", deviceID)
	}
	// 1. Приоритет прямому Network.Address в конфигурации
	if cfg.Network.Address != "" {
		clean := strings.TrimSpace(strings.Split(cfg.Network.Address, "/")[0])
		if !strings.HasSuffix(clean, ".0") && clean != "" {
			return clean
		}
	}
	// 2. Активный профиль
	activeProf := cfg.EnsureActiveProfile()
	if activeProf != nil {
		if activeProf.VirtualIP != "" {
			clean := strings.TrimSpace(strings.Split(activeProf.VirtualIP, "/")[0])
			if !strings.HasSuffix(clean, ".0") && clean != "" {
				return clean
			}
			prefix := ExtractSubnetPrefix(activeProf.VirtualIP)
			return GenerateSubnetIP(prefix, deviceID)
		}
		if activeProf.Subnet != "" {
			prefix := ExtractSubnetPrefix(activeProf.Subnet)
			return GenerateSubnetIP(prefix, deviceID)
		}
	}
	// 3. Network.Address как подсеть (если оканчивается на .0)
	if cfg.Network.Address != "" {
		prefix := ExtractSubnetPrefix(cfg.Network.Address)
		return GenerateSubnetIP(prefix, deviceID)
	}
	// 4. Дефолтный fallback (только если нигде ничего не задано)
	return GenerateSubnetIP("100.64.200", deviceID)
}
