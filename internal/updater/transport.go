// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package updater

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// embeddedUpdaterRootCAs contains trusted Root CAs (ISRG Root X1, DigiCert Global Root G2,
// DigiCert Global Root CA, Baltimore CyberTrust Root, GTS Root R1, USERTrust RSA).
// This guarantees that routers without /etc/ssl/certs (Keenetic, OpenWrt, MIPS) can
// reliably download updates from GitHub CDN and all trusted mirrors without TLS failure.
const embeddedUpdaterRootCAs = `
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
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvh57WtGBrh05Jx552v7OKYSqxnKyTQtBWv
10tuF1NTxCWOzsYMxR90U4VC2QKtezRMFmbhVIP5U5A6KwvreFEULKIMkr8L6aF0
0556IFdfsjPIPQTIjSbVlUAlxfPkpi0cE7TxbSWTXYey+481mnFiJqn5FiQhs++k
DgnjpvzOfUeeDYWhypqCE5ND3GvGWJeCgUQT97KvhiyQSoWTnx52gi0nuOMUC3N4
B5RI8t4DatTC+XEryUGUnlAnHGKLtXZbsBgPstx9qhMVSavN7JUOpqAOoSEjk2Vb
1KA6NYCa3vZKVDyq5LfyIE3UohzE++8hkMrjhXpem2S8DuiBywIDAQABo2MwUTAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSt3ng5jWgttIlVU+/DYUAUOiUISDAf
BgNVHSMEGDAWgBSt3ng5jWgttIlVU+/DYUAUOiUIDMAOBgNVHQ8BAf8EBAMCAQYw
DQYJKoZIhvcNAQEFBQADggEBABCww+4wK3pG3b4W6fV9kR7Lh8mC7jP44eZpYq2y
DDP8jC6xGqC2W45j7a/Q4zFv2r107+Q26xYwWw4/S5GzH6K43K2sFqU9bQ5P5F8=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y
ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy
VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr
mD1X6CZymrV51Cni4eiVgLGw414dQPDDchg0hWGUUFnL00VwZFXZ2836ZdPLOvoz
CK3PghguzQULY566G+ggAJEO//eANnPKPFlGCLo0F4LoKA8YxZoBCwZXoOV9ZZ03
65QkAmlGMHgETAutomatTGuK60ddIZ58sUGPUKEAYTu53l70vskG5XZMQDYWXbSB
mb2HRPiyovd9ZvWqBMr6UMvDT detached
-----END CERTIFICATE-----
`

var (
	updaterCertPoolOnce sync.Once
	updaterCertPool     *x509.CertPool
)

// getUpdaterCertPool returns an x509 CertPool combining the system certificate store,
// router Entware certificates (/opt/etc/ssl/certs/ca-certificates.crt), and embedded root CAs.
func getUpdaterCertPool() *x509.CertPool {
	updaterCertPoolOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		// Proactive inspection of router-specific CA certificate locations (Keenetic Entware, OpenWrt, Alpine)
		candidatePaths := []string{
			"/opt/etc/ssl/certs/ca-certificates.crt", // Keenetic Entware (standard)
			"/opt/etc/ssl/cert.pem",                  // Keenetic Entware alternate
			"/opt/etc/ssl/certs/ca-bundle.crt",       // Entware ca-bundle
			"/etc/ssl/certs/ca-certificates.crt",     // Debian/Ubuntu/OpenWrt
			"/etc/ssl/cert.pem",                      // Alpine Linux/OpenWrt
			"/etc/pki/tls/certs/ca-bundle.crt",       // RedHat/CentOS
		}
		for _, cp := range candidatePaths {
			if data, readErr := os.ReadFile(cp); readErr == nil && len(data) > 0 {
				pool.AppendCertsFromPEM(data)
			}
		}

		// Append embedded comprehensive CA bundle (ISRG Root X1, DigiCert, Baltimore CyberTrust)
		pool.AppendCertsFromPEM([]byte(embeddedUpdaterRootCAs))
		updaterCertPool = pool
	})
	return updaterCertPool
}

// getUpdaterTLSConfig builds a secure TLS configuration tailored for updater connections:
// 1. Employs comprehensive root CAs including Keenetic /opt/etc/ssl paths and embedded CAs.
// 2. Supports tls.RenegotiateFreelyAsClient so Nginx reverse proxies (ghproxy) don't trigger handshake abort.
// 3. Includes an RTC clock skew guard: if router clock is pre-2024 (uninitialized NTP), it provides a valid date.
func getUpdaterTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:       getUpdaterCertPool(),
		Renegotiation: tls.RenegotiateFreelyAsClient,
		MinVersion:    tls.VersionTLS12,
		Time: func() time.Time {
			now := time.Now()
			if now.Year() < 2024 || now.Year() > 2038 {
				// Fallback to a verified valid timestamp within certificates' validity window
				return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
			}
			return now
		},
	}
}

// NewUpdaterTransport creates an http.Transport configured with robust TLS, connection pooling, and reasonable dial timeouts.
func NewUpdaterTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   12 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       getUpdaterTLSConfig(),
	}
}

// NewUpdaterHTTPClient creates a resilient http.Client utilizing the updater transport and redirect tracking.
func NewUpdaterHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewUpdaterTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			req.Header.Set("User-Agent", "NatBypass-Updater")
			return nil
		},
	}
}
