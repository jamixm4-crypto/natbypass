# NatBypass Architecture Decisions & Stability Log (v1.9.20)

## 1. Crash Prevention & Panic Recovery
- **Decision:** Wrap `main()` in a top-level `defer recover()` block that logs the full stack trace to both `dist/crash.log` and the active log file, explicitly invokes `cleanupTrayIcon()`, and exits with code 2.
- **Rationale:** Ensures no dangling tray icons or zombie handles remain in the Windows Shell if an unhandled panic occurs.

## 2. Windows Shell Tray Icon Handling
- **Decision:** Deterministic `uID = 1001` and explicit `Shell_NotifyIconW(NIM_DELETE, ...)` on normal shutdown, signal termination (`SIGINT`/`SIGTERM`), and panic recovery.
- **Rationale:** Eliminates phantom/ghost tray icons upon rapid process restarts.

## 3. Per-Configuration Single Instance Mutex
- **Decision:** Key the Windows Named Mutex using SHA-256 hash of the normalized configuration file path: `Local\NatBypass_Instance_<hash>`.
- **Rationale:** Allows multiple instances to run side-by-side on the same machine for testing or multi-network mesh routing, while strictly preventing duplicate processes from running the same configuration file.

## 4. Always-Up Wintun TUN Interface & Self-Ping
- **Decision:** Create Wintun TUN interface (`NatBypass` or `NatBypass-<deviceID>`) unconditionally on engine start when running with administrative privileges, assign the Virtual IP (VIP) and `/24` subnet mask, set lower metric (`100`), and automatically verify interface readiness via self-ping probe.
- **Rationale:** Decouples L3 routing and local virtual interface setup from peer availability or WireGuard configuration.

## 5. L3 Data-Plane Routing (Direct UDP + MQTT Fallback)
- **Decision:** Read raw IPv4 packets from Wintun, inspect destination IP from header bytes 16..20, lookup peer by VIP in `peer.Registry`, and transmit directly over UDP punch socket (`NATBYPASS:TUN:` protocol header) if `direct_p2p == true`, or fallback to MQTT tunnel topic `natbypass/mesh/<topic>/tunnel/<targetDevID>`.
- **Rationale:** Enables true transparent mesh IP packet exchange (ICMP ping, TCP, UDP) across Symmetric NATs, CGNATs, and direct LAN/WAN connections.