package signaling

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

type AWGParams struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
}

func (a *AWGParams) UnmarshalJSON(data []byte) error {
	type Alias AWGParams
	aux := &struct {
		UpperJc    *int            `json:"Jc"`
		UpperJmin  *int            `json:"Jmin"`
		UpperJmax  *int            `json:"Jmax"`
		CamelJmin  *int            `json:"jMin"`
		CamelJmax  *int            `json:"jMax"`
		UpperS1    *int            `json:"S1"`
		UpperS2    *int            `json:"S2"`
		RawH1      json.RawMessage `json:"h1"`
		RawH2      json.RawMessage `json:"h2"`
		RawH3      json.RawMessage `json:"h3"`
		RawH4      json.RawMessage `json:"h4"`
		UpperRawH1 json.RawMessage `json:"H1"`
		UpperRawH2 json.RawMessage `json:"H2"`
		UpperRawH3 json.RawMessage `json:"H3"`
		UpperRawH4 json.RawMessage `json:"H4"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.UpperJc != nil {
		a.Jc = *aux.UpperJc
	}
	if aux.UpperJmin != nil {
		a.Jmin = *aux.UpperJmin
	} else if aux.CamelJmin != nil {
		a.Jmin = *aux.CamelJmin
	}
	if aux.UpperJmax != nil {
		a.Jmax = *aux.UpperJmax
	} else if aux.CamelJmax != nil {
		a.Jmax = *aux.CamelJmax
	}
	if aux.UpperS1 != nil {
		a.S1 = *aux.UpperS1
	}
	if aux.UpperS2 != nil {
		a.S2 = *aux.UpperS2
	}

	parseH := func(raw, upperRaw json.RawMessage) string {
		r := raw
		if len(r) == 0 {
			r = upperRaw
		}
		if len(r) == 0 || string(r) == "null" {
			return ""
		}
		var str string
		if err := json.Unmarshal(r, &str); err == nil {
			return str
		}
		return strings.Trim(string(r), "\"")
	}

	if h1 := parseH(aux.RawH1, aux.UpperRawH1); h1 != "" {
		a.H1 = h1
	}
	if h2 := parseH(aux.RawH2, aux.UpperRawH2); h2 != "" {
		a.H2 = h2
	}
	if h3 := parseH(aux.RawH3, aux.UpperRawH3); h3 != "" {
		a.H3 = h3
	}
	if h4 := parseH(aux.RawH4, aux.UpperRawH4); h4 != "" {
		a.H4 = h4
	}

	return nil
}

type Payload struct {
	DeviceID         string     `json:"device_id"`
	Nickname         string     `json:"nickname,omitempty"`
	DeviceName       string     `json:"device_name,omitempty"`
	VirtualIP        string     `json:"virtual_ip"`
	PublicKey        string     `json:"public_key"`
	PublicIP         string     `json:"public_ip"`
	LocalAddr        string     `json:"local_addr"`
	STUNAddr         string     `json:"stun_addr"`
	WGPubKey         string     `json:"wg_pub_key"`
	WGPort           int        `json:"wg_port"`
	Timestamp        time.Time  `json:"timestamp"`
	Encrypted        []byte     `json:"encrypted,omitempty"`
	IsExitNode       bool       `json:"is_exit_node,omitempty"`
	AdvertisedRoutes []string   `json:"advertised_routes,omitempty"`
	ExitRevoked      bool       `json:"exit_revoked,omitempty"`
	Offline          bool       `json:"offline,omitempty"`
	Leave            bool       `json:"leave,omitempty"`
	AWG              *AWGParams `json:"awg,omitempty"`
}

func (p *Payload) UnmarshalJSON(data []byte) error {
	type Alias Payload
	aux := &struct {
		UpperDeviceID         string     `json:"DeviceID"`
		UpperNickname         string     `json:"Nickname"`
		UpperDeviceName       string     `json:"DeviceName"`
		UpperVirtualIP        string     `json:"VirtualIP"`
		UpperPublicIP         string     `json:"PublicIP"`
		UpperLocalAddr        string     `json:"LocalAddr"`
		UpperSTUNAddr         string     `json:"STUNAddr"`
		UpperWGPubKey         string     `json:"WGPubKey"`
		UpperWGPort           int        `json:"WGPort"`
		UpperIsExitNode       bool       `json:"IsExitNode"`
		UpperAdvertisedRoutes []string   `json:"AdvertisedRoutes"`
		UpperExitRevoked      bool       `json:"ExitRevoked"`
		UpperOffline          bool       `json:"Offline"`
		UpperLeave            bool       `json:"Leave"`
		UpperAWG              *AWGParams `json:"AWG"`
		CamelAWG              *AWGParams `json:"awg"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if p.DeviceID == "" && aux.UpperDeviceID != "" {
		p.DeviceID = aux.UpperDeviceID
	}
	if p.Nickname == "" && aux.UpperNickname != "" {
		p.Nickname = aux.UpperNickname
	}
	if p.DeviceName == "" && aux.UpperDeviceName != "" {
		p.DeviceName = aux.UpperDeviceName
	}
	if p.Nickname == "" && p.DeviceName != "" {
		p.Nickname = p.DeviceName
	} else if p.DeviceName == "" && p.Nickname != "" {
		p.DeviceName = p.Nickname
	}
	if p.VirtualIP == "" && aux.UpperVirtualIP != "" {
		p.VirtualIP = aux.UpperVirtualIP
	}
	if p.PublicIP == "" && aux.UpperPublicIP != "" {
		p.PublicIP = aux.UpperPublicIP
	}
	if p.LocalAddr == "" && aux.UpperLocalAddr != "" {
		p.LocalAddr = aux.UpperLocalAddr
	}
	if p.STUNAddr == "" && aux.UpperSTUNAddr != "" {
		p.STUNAddr = aux.UpperSTUNAddr
	}
	if p.WGPubKey == "" && aux.UpperWGPubKey != "" {
		p.WGPubKey = aux.UpperWGPubKey
	}
	if p.WGPort == 0 && aux.UpperWGPort != 0 {
		p.WGPort = aux.UpperWGPort
	}
	if !p.IsExitNode && aux.UpperIsExitNode {
		p.IsExitNode = aux.UpperIsExitNode
	}
	if len(p.AdvertisedRoutes) == 0 && len(aux.UpperAdvertisedRoutes) > 0 {
		p.AdvertisedRoutes = aux.UpperAdvertisedRoutes
	}
	if !p.ExitRevoked && aux.UpperExitRevoked {
		p.ExitRevoked = aux.UpperExitRevoked
	}
	if !p.Offline && aux.UpperOffline {
		p.Offline = aux.UpperOffline
	}
	if !p.Leave && aux.UpperLeave {
		p.Leave = aux.UpperLeave
	}
	if p.AWG == nil {
		if aux.UpperAWG != nil {
			p.AWG = aux.UpperAWG
		} else if aux.CamelAWG != nil {
			p.AWG = aux.CamelAWG
		}
	}
	return nil
}

type SignalingChannel interface {
	Name() string
	Send(ctx context.Context, payload *Payload) error
	Receive(ctx context.Context) (<-chan *Payload, error)
	IsAvailable(ctx context.Context) bool
	Close() error
}

func EncryptPayload(p *Payload, pubKey, privKey [32]byte) (*Payload, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	
	enc, err := crypto.Encrypt(data, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	// Копируем все поля и прикрепляем зашифрованный блоб
	res := *p
	res.Encrypted = enc
	return &res, nil
}

func DecryptPayload(p *Payload, senderPub, recipientPriv [32]byte) (*Payload, error) {
	if len(p.Encrypted) == 0 {
		return p, nil
	}

	data, err := crypto.Decrypt(p.Encrypted, senderPub, recipientPriv)
	if err != nil {
		return nil, err
	}

	var res Payload
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	return &res, nil
}
