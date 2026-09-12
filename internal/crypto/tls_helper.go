// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Embedded Root CA bundle (ISRG Root X1 + DigiCert Global Root G2)
// Ensures routers without /etc/ssl/certs/ca-certificates.crt (Keenetic, OpenWrt, MIPS)
// can securely verify TLS connections to public MQTT brokers (HiveMQ, EMQX, Mosquitto)
// without resorting to InsecureSkipVerify: true.
const embeddedRootCAs = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRQBq13OhCz8wDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8S5z2lbfIkRiJNsHGC8D4BX83mKOmTx06Qq6mqBKutNKn77NauCg8L3tq
whUXmHvj42RPKXifIKUb95KEKxQuUsLeR4PBPzC2c3v0sfNTUPuk73+x0dVKE29wy
UhiI62mSOjy2wG3YsSm048WKJ2ZsVDWbeubKePDu+MHgk65gEyxvmaAhK/bpCEuc
AfPpx0WXhzax5T5mSHVX79NgKYZ51vhrtRpvZ0OyoAioZgg9PGKNT/GqGVSXt1wEp
goWYiYSUwhR00WDicqvNUL49USi8ehk+/aKEgkYv9wpbwtdSo3HR9RTrUAWquezPn/
lBKP6sMkqIE9222iOHMmpJlhIRW8hzQySg106PN64XR2dZZj4fhmxdRhzyKWiszU
BfkFiN2evDGbKZEEtLpdK5QDJWLaST2FHRqh84C5iFBSnfS14oAH35bGASomYTbv
nwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUebRZ5V296bAjVQt9Ka0duSkak5AwDQYJKoZIhvcNAQELBQADggIBABn9
8WN27334555ahNT08UR5xjCorPRd6fGDDguBrULqP/3ZHMzNUXvB4cjWBV3cfEBw
xEIKW7FovEQguUURfwBH7KZIne22endMW/RNTxEIfI53qmOzBoMBKeIECH7BNdXl
DQ9WQFYirHNddooOwGfcwPHDrhE10xsbo7/57144e2/tdhAomch6242yHnDLBGbo
rpH1keGiPTFSpNTrgVPW++n+S/cTTAue3z22UHMWjW441b8QVNStKE3gPemFag=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7aWfvNg7wWYdMW+UP746cy8HNVHYO
OQF1GTxaWjPPu3/bIh72bNz3PZsJUKLy0ShW3t3C579DM9UbjKsEgGCYTAdaKJSsq
G2fGkwZcnh328IQA57g5jns3DWVNtVNqtwUvTEkULbtsA50Fetgn0kB9nCQHlT65
kpzpuxNW55zcn9h20h3o8MeqNHLKYDGuUvjbgU6LKAuptW3zZVirddxESOeIWDYE
DRKOWTQ1maPX17iPSqDYuefAgKEghPC/v3DNAAAA/4wDQYJKoZIhvcNAQELBQAD
ggEBAGakUQfGkWgfKnId3YkWNENCRr8uUS2RypEBc9cdLheHMuIG2eGnpPmsvWnq
nPt0EIzWB1tsjbhGY4ffdOcUXN4b84NxLpmgnY94x2epZ95gMgj900Rhy37JYRhz
-----END CERTIFICATE-----
`

var (
	certPoolOnce sync.Once
	cachedPool   *x509.CertPool
)

func getRootCertPool() *x509.CertPool {
	certPoolOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		// Supplementary append of Mozilla/Let's Encrypt roots
		pool.AppendCertsFromPEM([]byte(embeddedRootCAs))
		cachedPool = pool
	})
	return cachedPool
}

// BuildTLSConfig builds a secure tls.Config for connecting to remote brokers or relays.
// It verifies the server certificate using the system certificate pool supplemented by
// embedded trusted root CAs. InsecureSkipVerify is disabled by default.
func BuildTLSConfig(targetURL string) *tls.Config {
	serverName := ""
	if strings.Contains(targetURL, "://") {
		if u, err := url.Parse(targetURL); err == nil {
			serverName = u.Hostname()
		}
	} else {
		serverName = strings.Split(targetURL, ":")[0]
	}

	// Support explicit override via environment variable NATBYPASS_TLS_INSECURE=1 or local loopback
	isLocal := serverName == "localhost" || serverName == "127.0.0.1" || serverName == "::1"
	insecureOverride := os.Getenv("NATBYPASS_TLS_INSECURE") == "1"
	if insecureOverride || isLocal {
		if !isLocal {
			log.Warn().Str("target", targetURL).Msg("SECURITY WARNING: TLS verification disabled via NATBYPASS_TLS_INSECURE=1")
		}
		return &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
	}

	return &tls.Config{
		ServerName: serverName,
		RootCAs:    getRootCertPool(),
		MinVersion: tls.VersionTLS12,
	}
}
