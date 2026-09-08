// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package shadowtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateMeshTLSCertificate creates an in-memory self-signed ECDSA certificate
// for native TLS 1.3 mode. The certificate contains the DeviceID in CommonName,
// DNS:<deviceID>.mesh in SANs, and IP SAN matching the virtual IP.
func GenerateMeshTLSCertificate(deviceID, vip string, networkKey [32]byte) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Compute mesh signature tag embedded in Organization
	h := hmac.New(sha256.New, networkKey[:])
	h.Write([]byte(deviceID))
	meshTag := fmt.Sprintf("NatBypass-Mesh-%x", h.Sum(nil)[:8])

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{meshTag},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year (safer rotation window against compromise)
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{deviceID + ".mesh", "localhost"},
	}

	if vip != "" {
		cleanVIP := vip
		if host, _, err := net.SplitHostPort(vip); err == nil {
			cleanVIP = host
		}
		if ip := net.ParseIP(cleanVIP); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create x509 certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return cert, nil
}

// NewMeshClientTLSConfig creates a client tls.Config for native TLS 1.3 mutual authentication.
func NewMeshClientTLSConfig(cert tls.Certificate, networkKey [32]byte, sni string) *tls.Config {
	if sni == "" {
		sni = DefaultSNI
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ServerName:         sni,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We verify via custom VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate presented")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %w", err)
			}
			// Verify mesh organization HMAC tag
			h := hmac.New(sha256.New, networkKey[:])
			h.Write([]byte(peerCert.Subject.CommonName))
			expectedTag := fmt.Sprintf("NatBypass-Mesh-%x", h.Sum(nil)[:8])
			for _, org := range peerCert.Subject.Organization {
				if org == expectedTag {
					return nil
				}
			}
			return fmt.Errorf("peer certificate mesh auth tag mismatch")
		},
	}
}

// NewMeshServerTLSConfig creates a server tls.Config for native TLS 1.3 mutual authentication.
func NewMeshServerTLSConfig(cert tls.Certificate, networkKey [32]byte) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate presented")
			}
			clientCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse client certificate: %w", err)
			}
			h := hmac.New(sha256.New, networkKey[:])
			h.Write([]byte(clientCert.Subject.CommonName))
			expectedTag := fmt.Sprintf("NatBypass-Mesh-%x", h.Sum(nil)[:8])
			for _, org := range clientCert.Subject.Organization {
				if org == expectedTag {
					return nil
				}
			}
			return fmt.Errorf("client certificate mesh auth tag mismatch")
		},
	}
}
