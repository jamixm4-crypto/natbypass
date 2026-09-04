package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PingVirtualIP pings a target Virtual IP address using the operating system's
// native ping command through the TUN interface / network stack, measuring the
// true end-to-end device-level latency.
func PingVirtualIP(ctx context.Context, targetVIP string, timeout time.Duration) (time.Duration, error) {
	cleanIP := strings.TrimSpace(strings.Split(targetVIP, "/")[0])
	if cleanIP == "" {
		return 0, errors.New("empty target IP")
	}
	if parsed := net.ParseIP(cleanIP); parsed == nil {
		return 0, fmt.Errorf("invalid target IP address: %s", cleanIP)
	}

	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		ms := int(timeout.Milliseconds())
		if ms < 200 {
			ms = 200
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(ms), cleanIP)
		setSysProcAttr(cmd)
	case "darwin":
		sec := int(timeout.Seconds())
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-t", strconv.Itoa(sec), cleanIP)
	default: // linux, android, keenetic, openwrt
		sec := int(timeout.Seconds())
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(sec), cleanIP)
	}

	outBytes, err := cmd.CombinedOutput()
	outStr := string(outBytes)

	// If command failed and output is empty, return immediate error
	if err != nil && len(strings.TrimSpace(outStr)) == 0 {
		return 0, fmt.Errorf("ping command failed: %w", err)
	}

	rtt, parseErr := ParsePingOutput(outStr)
	if parseErr != nil {
		if err != nil {
			return 0, fmt.Errorf("ping %s unreachable: %w (%s)", cleanIP, err, strings.TrimSpace(outStr))
		}
		return 0, fmt.Errorf("ping %s failed: %w", cleanIP, parseErr)
	}

	return rtt, nil
}

// ParsePingOutput parses standard OS ping utility output (Windows, Linux, macOS, BusyBox)
// and extracts the round-trip latency in milliseconds.
func ParsePingOutput(out string) (time.Duration, error) {
	lower := strings.ToLower(out)

	// Check for failure indicators
	if strings.Contains(lower, "100% packet loss") ||
		strings.Contains(lower, "100% loss") ||
		strings.Contains(lower, "100% потерь") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "превышен интервал") ||
		strings.Contains(lower, "unreachable") ||
		strings.Contains(lower, "недоступен") ||
		strings.Contains(lower, "unknown host") {
		return 0, errors.New("packet lost or host unreachable")
	}

	// 1. Check for "<1ms" or "<1мс"
	if strings.Contains(lower, "<1ms") || strings.Contains(lower, "<1мс") || strings.Contains(lower, "<1 ms") {
		return 1 * time.Millisecond, nil
	}

	// 2. Standard time matching: "time=XX.X ms" or "время=XXмс" or "time=XXms"
	// Works for Linux ("time=14.2 ms"), Windows English ("time=15ms"), Windows Russian ("время=15мс")
	reTime := regexp.MustCompile(`(?i)(?:time|время)\s*=\s*([0-9.]+)\s*(?:ms|мс)?`)
	if m := reTime.FindStringSubmatch(out); len(m) >= 2 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil && val >= 0 {
			if val < 1.0 && val > 0 {
				return time.Duration(val * float64(time.Millisecond)), nil
			}
			return time.Duration(val * float64(time.Millisecond)), nil
		}
	}

	// 3. Fallback: match any number right before TTL: e.g. "=15мс TTL=" or "=15 TTL=" or "<1 TTL="
	reTTL := regexp.MustCompile(`(?i)[<=]\s*([0-9.]+)\s*[^\s=]*\s+ttl=`)
	if m := reTTL.FindStringSubmatch(out); len(m) >= 2 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil && val >= 0 {
			return time.Duration(val * float64(time.Millisecond)), nil
		}
	}

	// 4. Linux summary line: "rtt min/avg/max/mdev = 12.345/14.567/..." or "round-trip min/avg/max = ..."
	reAvg := regexp.MustCompile(`(?i)(?:min/avg/max|round-trip)[^=]*=\s*[0-9.]+/([0-9.]+)/`)
	if m := reAvg.FindStringSubmatch(out); len(m) >= 2 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil && val >= 0 {
			return time.Duration(val * float64(time.Millisecond)), nil
		}
	}

	// 5. Windows summary line: "Average = 14ms" or "Среднее = 14мсек" or "Среднее = 14 мсек"
	reWinAvg := regexp.MustCompile(`(?i)(?:average|среднее)\s*=\s*([0-9.]+)\s*(?:ms|мс|мсек)?`)
	if m := reWinAvg.FindStringSubmatch(out); len(m) >= 2 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil && val >= 0 {
			return time.Duration(val * float64(time.Millisecond)), nil
		}
	}

	return 0, errors.New("could not parse ping latency from output")
}
