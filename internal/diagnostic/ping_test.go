package diagnostic

import (
	"context"
	"testing"
	"time"
)

func TestParsePingOutput(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		wantRTT time.Duration
		wantErr bool
	}{
		{
			name:    "Windows Russian normal",
			output:  "Ответ от 100.64.200.2: число байт=32 время=16мс TTL=128",
			wantRTT: 16 * time.Millisecond,
			wantErr: false,
		},
		{
			name:    "Windows Russian <1ms",
			output:  "Ответ от 100.64.200.2: число байт=32 время<1мс TTL=128",
			wantRTT: 1 * time.Millisecond,
			wantErr: false,
		},
		{
			name:    "Windows English normal",
			output:  "Reply from 100.64.200.2: bytes=32 time=23ms TTL=128",
			wantRTT: 23 * time.Millisecond,
			wantErr: false,
		},
		{
			name:    "Windows English <1ms",
			output:  "Reply from 100.64.200.2: bytes=32 time<1ms TTL=128",
			wantRTT: 1 * time.Millisecond,
			wantErr: false,
		},
		{
			name:    "Linux iputils format",
			output:  "64 bytes from 100.64.200.2: icmp_seq=1 ttl=64 time=18.4 ms",
			wantRTT: time.Duration(18.4 * float64(time.Millisecond)),
			wantErr: false,
		},
		{
			name:    "BusyBox / Keenetic format",
			output:  "64 bytes from 100.64.200.2: seq=0 ttl=64 time=12.345 ms",
			wantRTT: time.Duration(12.345 * float64(time.Millisecond)),
			wantErr: false,
		},
		{
			name:    "Linux summary avg",
			output:  "--- 100.64.200.2 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss\nrtt min/avg/max/mdev = 12.345/14.567/18.910/1.234 ms",
			wantRTT: time.Duration(14.567 * float64(time.Millisecond)),
			wantErr: false,
		},
		{
			name:    "Windows timeout",
			output:  "Превышен интервал ожидания для запроса.",
			wantErr: true,
		},
		{
			name:    "Linux 100% packet loss",
			output:  "--- 100.64.200.2 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss",
			wantErr: true,
		},
		{
			name:    "Destination unreachable",
			output:  "From 100.64.200.1 icmp_seq=1 Destination Host Unreachable",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePingOutput(tc.output)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got RTT: %v", got)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantRTT {
					t.Fatalf("expected RTT %v, got %v", tc.wantRTT, got)
				}
			}
		})
	}
}

func TestPingVirtualIP_Loopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rtt, err := PingVirtualIP(ctx, "127.0.0.1", 2*time.Second)
	if err != nil {
		t.Logf("loopback ping skipped or failed: %v", err)
		return
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT for 127.0.0.1, got %v", rtt)
	}
	t.Logf("✓ Real OS loopback ping measured: %v", rtt)
}
