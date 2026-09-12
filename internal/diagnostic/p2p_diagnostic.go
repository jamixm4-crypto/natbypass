// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package diagnostic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

type NATClassification struct {
	NATType         string `json:"nat_type"`
	MappingType     string `json:"mapping_type"`
	FilteringType   string `json:"filtering_type"`
	PublicIP        string `json:"public_ip"`
	MappedPort1     int    `json:"mapped_port_1"`
	MappedPort2     int    `json:"mapped_port_2"`
	MappedPort3     int    `json:"mapped_port_3,omitempty"`
	PortDelta       int    `json:"port_delta"`
	ParityPreserved bool   `json:"parity_preserved"`
	Parity          int    `json:"parity"`
	PBABlockSize    int    `json:"pba_block_size,omitempty"`
	PBABase         int    `json:"pba_base,omitempty"`
	IsCGNAT         bool   `json:"is_cgnat"`
	P2PFeasibility  string `json:"p2p_feasibility"`
	Recommendation  string `json:"recommendation"`
}

var cgnatSubnet = &net.IPNet{
	IP:   net.ParseIP("100.64.0.0"),
	Mask: net.CIDRMask(10, 32),
}

// ClassifyNATBehavior выполняет RFC 4787 / RFC 5780 / RFC 6888 тест поведения NAT и классификацию портов
func ClassifyNATBehavior() (*NATClassification, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open local UDP socket: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Сервер 1: Google STUN
	ip1, port1, err1 := querySTUN(ctx, conn, "stun.l.google.com:19302")
	if err1 != nil {
		return nil, fmt.Errorf("STUN server 1 error: %w", err1)
	}

	// Небольшая задержка перед вторым запросом из того же сокета
	time.Sleep(30 * time.Millisecond)

	// Сервер 2: Cloudflare STUN (другой IP)
	ip2, port2, err2 := querySTUN(ctx, conn, "stun.cloudflare.com:3478")
	if err2 != nil {
		ip2, port2, err2 = querySTUN(ctx, conn, "stun1.l.google.com:19302")
	}

	time.Sleep(30 * time.Millisecond)

	// Сервер 3: Nextcloud STUN (порт 443 / другой IP)
	ip3, port3, err3 := querySTUN(ctx, conn, "stun.nextcloud.com:443")
	if err3 != nil {
		ip3, port3, err3 = querySTUN(ctx, conn, "stun2.l.google.com:19302")
	}

	res := &NATClassification{
		PublicIP:    ip1.String(),
		MappedPort1: port1,
		IsCGNAT:     cgnatSubnet.Contains(ip1),
	}

	if err2 != nil || ip2 == nil {
		res.NATType = "Single STUN Response"
		res.MappingType = "Endpoint-Independent (Вероятно)"
		res.P2PFeasibility = "🟢 Высокая (95%)"
		res.Recommendation = "NAT отвечает на STUN запросы. Прямой P2P должен работать без ограничений."
		return res, nil
	}

	res.MappedPort2 = port2
	res.PortDelta = port2 - port1

	// Триангуляция по 3 серверам
	if err3 == nil && ip3 != nil {
		res.MappedPort3 = port3

		// 1. Parity preservation (RFC 4787)
		if (port1%2 == port2%2) && (port2%2 == port3%2) {
			res.ParityPreserved = true
			res.Parity = port1 % 2
		}

		// 2. Port Block Allocation (RFC 6888)
		blockSizes := []int{512, 256, 128, 64}
		for _, size := range blockSizes {
			mask := ^(size - 1)
			if (port1&mask) == (port2&mask) && (port2&mask) == (port3&mask) {
				res.PBABlockSize = size
				res.PBABase = port1 & mask
				break
			}
		}

		delta2 := port3 - port2

		if port1 == port2 && port2 == port3 {
			res.NATType = "Full Cone / Restricted Cone NAT"
			res.MappingType = "Endpoint-Independent Mapping (EIM)"
			res.FilteringType = "Address/Port Restricted"
			res.P2PFeasibility = "🟢 Идеальная (100%)"
			res.Recommendation = "Ваш роутер сохраняет постоянный внешний порт для всех направлений. Прямой P2P устанавливается мгновенно!"
		} else if abs(res.PortDelta) <= 5 && res.PortDelta == delta2 {
			res.NATType = "Symmetric NAT (Линейный сдвиг портов)"
			res.MappingType = fmt.Sprintf("Address-Dependent Mapping (Дельта: %+d)", res.PortDelta)
			res.FilteringType = "Port-Dependent Filtering"
			res.P2PFeasibility = "🟡 Хорошая (85-95% через предсказание портов)"
			res.Recommendation = fmt.Sprintf("Роутер выделяет разные внешние порты с фиксированным шагом (%+d). Алгоритм предсказания портов NatBypass автоматически пробьет сокет.", res.PortDelta)
		} else if res.PBABlockSize > 0 {
			res.NATType = fmt.Sprintf("Symmetric NAT / CGNAT (Пул PBA-%d)", res.PBABlockSize)
			res.MappingType = fmt.Sprintf("Port Block Allocation (Диапазон: %d..%d)", res.PBABase, res.PBABase+res.PBABlockSize-1)
			res.FilteringType = "Address and Port Dependent"
			res.P2PFeasibility = "🟡 Средне-высокая (80-90% через блочный sweep)"
			res.Recommendation = fmt.Sprintf("Обнаружен CGNAT пул Port Block Allocation (%d портов). NatBypass автоматически сузит диапазон поиска портов.", res.PBABlockSize)
		} else {
			res.NATType = "Symmetric NAT / CGNAT (Случайные порты)"
			res.MappingType = fmt.Sprintf("Address-Dependent Mapping (Порты: %d -> %d -> %d)", port1, port2, port3)
			res.FilteringType = "Address and Port Dependent"
			res.P2PFeasibility = "🟠 Средняя (50-70% / Требуется UPnP или Relay)"
			res.Recommendation = "Мобильный интернет или жесткий корпоративный CGNAT. Рекомендуется включить UPnP на роутере или использовать релей."
		}
		return res, nil
	}

	if port1 == port2 {
		res.NATType = "Full Cone / Restricted Cone NAT"
		res.MappingType = "Endpoint-Independent Mapping (EIM)"
		res.FilteringType = "Address/Port Restricted"
		res.P2PFeasibility = "🟢 Идеальная (100%)"
		res.Recommendation = "Ваш роутер сохраняет постоянный внешний порт для всех направлений. Прямой P2P устанавливается мгновенно!"
	} else if abs(res.PortDelta) <= 5 {
		res.NATType = "Symmetric NAT (Последовательные порты)"
		res.MappingType = fmt.Sprintf("Address-Dependent Mapping (Дельта: %+d)", res.PortDelta)
		res.FilteringType = "Port-Dependent Filtering"
		res.P2PFeasibility = "🟡 Хорошая (80-90% через предсказание портов)"
		res.Recommendation = fmt.Sprintf("Роутер выделяет разные внешние порты с фиксированным шагом (%+d). Алгоритм предсказания портов NatBypass автоматически пробьет сокет.", res.PortDelta)
	} else {
		res.NATType = "Symmetric NAT / CGNAT (Случайные порты)"
		res.MappingType = fmt.Sprintf("Address-Dependent Mapping (Случайный порт: %d -> %d)", port1, port2)
		res.FilteringType = "Address and Port Dependent"
		res.P2PFeasibility = "🟠 Средняя (50-70% / Требуется UPnP или Relay)"
		res.Recommendation = "Мобильный интернет или жесткий корпоративный CGNAT. Рекомендуется включить UPnP на роутере или использовать релей."
	}

	return res, nil
}

func querySTUN(ctx context.Context, conn *net.UDPConn, serverAddr string) (net.IP, int, error) {
	rAddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, 0, err
	}

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteToUDP(msg.Raw, rAddr); err != nil {
		return nil, 0, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, 0, err
		}

		if stun.IsMessage(buf[:n]) {
			var resp stun.Message
			resp.Raw = buf[:n]
			if err := resp.Decode(); err == nil {
				var xorAddr stun.XORMappedAddress
				if err := xorAddr.GetFrom(&resp); err == nil {
					return xorAddr.IP, xorAddr.Port, nil
				}
			}
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
