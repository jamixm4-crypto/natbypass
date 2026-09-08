// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package peer

import (
	"testing"
	"time"
)

// FuzzIsValidEndpointForPeer tests endpoint validation against arbitrary input strings and IP spoofing.
func FuzzIsValidEndpointForPeer(f *testing.F) {
	f.Add("1.2.3.4:51820", "1.2.3.4", "5.6.7.8:51820", "10.0.0.1:51820")
	f.Add("[::1]:51820", "127.0.0.1", "", "")
	f.Add("invalid-endpoint", "", "", "")

	f.Fuzz(func(t *testing.T, endpoint, myPubIP, stunAddr, localAddr string) {
		p := &Peer{
			DeviceID:  "peer-fuzz",
			STUNAddr:  stunAddr,
			LocalAddr: localAddr,
		}
		// Must not panic on any malformed host/port, IPv4/IPv6, or empty string
		_ = IsValidEndpointForPeer(endpoint, p, myPubIP)
	})
}

// FuzzRegistryUpsert tests thread safety and boundary correctness of peer Upsert and GetByVirtualIP.
func FuzzRegistryUpsert(f *testing.F) {
	f.Add("dev1", "10.1.1.5", "1.2.3.4:51820", true)
	f.Add("dev2", "10.1.1.6/24", "", false)
	f.Add("", "", "", false)

	reg := NewRegistry()

	f.Fuzz(func(t *testing.T, devID, vip, endpoint string, direct bool) {
		p := &Peer{
			DeviceID:       devID,
			VirtualIP:      vip,
			ActiveEndpoint: endpoint,
			DirectP2P:      direct,
			LastSeen:       time.Now(),
			Online:         true,
		}
		reg.Upsert(p)
		if devID != "" {
			_, _ = reg.Get(devID)
		}
		if vip != "" {
			_, _ = reg.GetByVirtualIP(vip)
		}
	})
}
