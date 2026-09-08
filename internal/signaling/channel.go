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
	"strings"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

type AWGParams struct {
	Jc                      int    `json:"jc"`
	Jmin                    int    `json:"jmin"`
	Jmax                    int    `json:"jmax"`
	S1                      int    `json:"s1"`
	S2                      int    `json:"s2"`
	S3                      int    `json:"s3,omitempty"`
	S4                      int    `json:"s4,omitempty"`
	H1                      string `json:"h1"`
	H2                      string `json:"h2"`
	H3                      string `json:"h3"`
	H4                      string `json:"h4"`
	Pmin                    int    `json:"pmin,omitempty"` // Amnezia 3.x Min Random Data Packet Padding
	Pmax                    int    `json:"pmax,omitempty"` // Amnezia 3.x Max Random Data Packet Padding
	Version                 string `json:"version,omitempty"`
	Preset                  string `json:"preset,omitempty"`
	HeaderProtectionEnabled bool   `json:"header_protection_enabled,omitempty"`
	RandomTrailers          bool   `json:"random_trailers,omitempty"`
	DisableCookies          bool   `json:"disable_cookies,omitempty"`
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

// SymPunchSignal is broadcast via the mesh signaling channel to trigger coordinated
// simultaneous hole-punching between two nodes where one or both are behind Symmetric NAT.
// When a node starts a SymmetricNATSession it broadcasts this to the target peer;
// the target peer immediately starts probing the sender's current STUN address without
// calling HopPort() (so its own NAT mapping stays stable for the sender's sweep).
type SymPunchSignal struct {
	// MySTUNAddr is the sender's current external address:port (from STUN discovery).
	MySTUNAddr string `json:"my_stun_addr"`
	// TargetDeviceID restricts which peer should respond (empty = broadcast to all peers).
	TargetDeviceID string `json:"target_device_id,omitempty"`
	// HopHint: if non-zero, recipient should probe the sender at MySTUNAddr IP
	// at ports [HopHint-256 .. HopHint+256] in addition to MySTUNAddr port.
	HopHint int `json:"hop_hint,omitempty"`
}

// RemoteDiagSignal is used for remote cluster diagnostics collection and update orchestration in beta builds.
// RendezvousSignal coordinates on-demand synchronized bilateral hole-punching between peers.
type RendezvousSignal struct {
	Phase            string   `json:"phase"`                       // "init" | "ack"
	SessionID        string   `json:"session_id"`                  // unique session identifier
	TargetDeviceID   string   `json:"target_device_id"`            // recipient DeviceID
	SenderDeviceID   string   `json:"sender_device_id"`            // initiator / responder DeviceID
	SenderSTUN       string   `json:"sender_stun"`                 // sender's fresh external STUN address (IP:Port)
	SenderCandidates []string `json:"sender_candidates,omitempty"` // sender's current socket candidates
	Timestamp        int64    `json:"timestamp"`
}

type RemoteDiagSignal struct {
	Action      string `json:"action"`                // "request_diag", "response_diag", "request_update", "response_update"
	TargetID    string `json:"target_id,omitempty"`   // empty = all beta nodes in topic, or specific DeviceID
	SenderID    string `json:"sender_id,omitempty"`   // DeviceID of the diagnostic controller
	SessionID   string `json:"session_id,omitempty"`  // unique request session ID
	ChunkIndex  int    `json:"chunk_index,omitempty"` // for chunked report responses
	TotalChunks int    `json:"total_chunks,omitempty"`
	Payload     string `json:"payload,omitempty"`     // diagnostic text output or status details
	Status      string `json:"status,omitempty"`      // "ok", "error", "updating", "success"
	OS          string `json:"os,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Arch        string `json:"arch,omitempty"`
	Version     string `json:"version,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
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
	TCPAddr          string     `json:"tcp_addr,omitempty"`
	IPv6Addr         string     `json:"ipv6_addr,omitempty"`
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
	OS               string     `json:"os,omitempty"`
	Platform         string     `json:"platform,omitempty"`
	Arch             string     `json:"arch,omitempty"`
	Version          string     `json:"version,omitempty"`
	IsKeenetic       bool       `json:"is_keenetic,omitempty"`
	CountryFlag      string     `json:"country_flag,omitempty"`
	Channel          string     `json:"channel,omitempty"`
	NetworkKey       string     `json:"network_key,omitempty"`
	NetworkID        string     `json:"network_id,omitempty"`
	Topic            string     `json:"topic,omitempty"`
	DirectP2P        bool       `json:"direct_p2p,omitempty"`
	ActiveEndpoint   string     `json:"active_endpoint,omitempty"`
	PingMs           int64      `json:"ping_ms,omitempty"`
	NATType          string     `json:"nat_type,omitempty"` // "full_cone", "restricted", "symmetric", "unknown"
	NATDelta         int        `json:"nat_delta,omitempty"`
	Candidates       []string   `json:"candidates,omitempty"`

	// MDAR (Mesh Dynamic Adaptive Reconfiguration)
	MTU             int    `json:"mtu,omitempty"`
	PreferredPort   int    `json:"preferred_port,omitempty"`
	DPIPreset       string `json:"dpi_preset,omitempty"`
	AdaptationEpoch uint64 `json:"adaptation_epoch,omitempty"`
	HealthScore     int    `json:"health_score,omitempty"`

	// SymPunch: coordinated simultaneous Symmetric NAT hole-punch request.
	// Non-nil when this payload is a punch coordination signal, not a regular beacon.
	SymPunch *SymPunchSignal `json:"sym_punch,omitempty"`

	// RemoteDiag: beta-only remote cluster diagnostics collection and update coordination
	RemoteDiag *RemoteDiagSignal `json:"remote_diag,omitempty"`

	// Rendezvous: on-demand synchronized bilateral hole-punch coordination
	Rendezvous *RendezvousSignal `json:"rendezvous,omitempty"`
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
		UpperIPv6Addr         string     `json:"IPv6Addr"`
		UpperWGPubKey         string     `json:"WGPubKey"`
		UpperWGPort           int        `json:"WGPort"`
		UpperIsExitNode       bool       `json:"IsExitNode"`
		UpperAdvertisedRoutes []string   `json:"AdvertisedRoutes"`
		UpperExitRevoked      bool       `json:"ExitRevoked"`
		UpperOffline          bool       `json:"Offline"`
		UpperLeave            bool       `json:"Leave"`
		UpperAWG              *AWGParams `json:"AWG"`
		CamelAWG              *AWGParams `json:"awg"`
		UpperOS               string     `json:"OS"`
		UpperPlatform         string     `json:"Platform"`
		UpperArch             string     `json:"Arch"`
		UpperVersion          string     `json:"Version"`
		UpperIsKeenetic       bool       `json:"IsKeenetic"`
		UpperCountryFlag      string     `json:"CountryFlag"`
		UpperNetworkKey       string     `json:"NetworkKey"`
		UpperNetworkID        string     `json:"NetworkID"`
		UpperTopic            string     `json:"Topic"`
		UpperDirectP2P        bool       `json:"DirectP2P"`
		UpperActiveEndpoint   string     `json:"ActiveEndpoint"`
		UpperPingMs           int64      `json:"PingMs"`
		UpperNATType          string            `json:"NATType"`
		UpperNATDelta         *int              `json:"NATDelta"`
		CamelNATDelta         *int              `json:"natDelta"`
		UpperRemoteDiag       *RemoteDiagSignal `json:"RemoteDiag"`
		CamelRemoteDiag       *RemoteDiagSignal `json:"remoteDiag"`
		UpperRendezvous       *RendezvousSignal `json:"Rendezvous"`
		CamelRendezvous       *RendezvousSignal `json:"rendezvous"`
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
	if p.Rendezvous == nil {
		if aux.UpperRendezvous != nil {
			p.Rendezvous = aux.UpperRendezvous
		} else if aux.CamelRendezvous != nil {
			p.Rendezvous = aux.CamelRendezvous
		}
	}
	// DirectP2P, ActiveEndpoint, and PingMs are local network observations of THIS node.
	// They must NEVER be adopted from a remote peer's signaling beacon.
	p.DirectP2P = false
	p.ActiveEndpoint = ""
	p.PingMs = 0
	if p.IPv6Addr == "" && aux.UpperIPv6Addr != "" {
		p.IPv6Addr = aux.UpperIPv6Addr
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
	if p.NetworkKey == "" && aux.UpperNetworkKey != "" {
		p.NetworkKey = aux.UpperNetworkKey
	}
	if p.NetworkID == "" && aux.UpperNetworkID != "" {
		p.NetworkID = aux.UpperNetworkID
	}
	if p.Topic == "" && aux.UpperTopic != "" {
		p.Topic = aux.UpperTopic
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
	if p.OS == "" && aux.UpperOS != "" {
		p.OS = aux.UpperOS
	}
	if p.Platform == "" && aux.UpperPlatform != "" {
		p.Platform = aux.UpperPlatform
	}
	if p.Arch == "" && aux.UpperArch != "" {
		p.Arch = aux.UpperArch
	}
	if p.Version == "" && aux.UpperVersion != "" {
		p.Version = aux.UpperVersion
	}
	if !p.IsKeenetic && aux.UpperIsKeenetic {
		p.IsKeenetic = aux.UpperIsKeenetic
	}
	if p.CountryFlag == "" && aux.UpperCountryFlag != "" {
		p.CountryFlag = aux.UpperCountryFlag
	}
	if p.NATType == "" && aux.UpperNATType != "" {
		p.NATType = aux.UpperNATType
	}
	if p.NATDelta == 0 {
		if aux.UpperNATDelta != nil {
			p.NATDelta = *aux.UpperNATDelta
		} else if aux.CamelNATDelta != nil {
			p.NATDelta = *aux.CamelNATDelta
		}
	}
	if p.RemoteDiag == nil {
		if aux.UpperRemoteDiag != nil {
			p.RemoteDiag = aux.UpperRemoteDiag
		} else if aux.CamelRemoteDiag != nil {
			p.RemoteDiag = aux.CamelRemoteDiag
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

	// Скрываем конфиденциальные данные в открытом заголовке
	res := &Payload{
		DeviceID:  p.DeviceID,
		Timestamp: p.Timestamp,
		Encrypted: enc,
	}
	return res, nil
}

// EncryptPayloadWithKey шифрует маяк симметричным ключом комнаты (NetworkKey) и полностью скрывает чувствительные данные из открытого JSON.
func EncryptPayloadWithKey(p *Payload, keyStr string) (*Payload, error) {
	if keyStr == "" {
		return p, nil
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveKey(keyStr)
	enc, err := crypto.EncryptSelf(data, key)
	if err != nil {
		return nil, err
	}
	// В открытом виде оставляем ТОЛЬКО идентификатор и зашифрованный блоб
	res := &Payload{
		DeviceID:  p.DeviceID,
		Timestamp: p.Timestamp,
		Encrypted: enc,
	}
	return res, nil
}

// DecryptPayloadWithKey расшифровывает маяк симметричным ключом комнаты.
func DecryptPayloadWithKey(p *Payload, keyStr string) (*Payload, error) {
	if len(p.Encrypted) == 0 {
		return p, nil
	}
	if keyStr == "" {
		return p, nil
	}
	key := crypto.DeriveKey(keyStr)
	data, err := crypto.DecryptSelf(p.Encrypted, key)
	if err != nil {
		return nil, err
	}

	var res Payload
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

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
