package webui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/peer"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/wireguard"
	"golang.org/x/net/proxy"
)

//go:embed static/index.html
var staticFS embed.FS

// Response — стандартный JSON-ответ API
type Response struct {
	Ok    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

// AppState — состояние приложения для статус-эндпоинта
type AppState struct {
	DeviceID       string    `json:"device_id"`
	PublicIP       string    `json:"public_ip"`
	STUNAddr       string    `json:"stun_addr"`
	Uptime         string    `json:"uptime"`
	CurrentChannel string    `json:"current_channel"`
	StartedAt      time.Time `json:"started_at"`
}

// Server — встроенный Web UI HTTP-сервер
type Server struct {
	port       int
	user       string
	password   string
	configPath string
	registry   *peer.Registry
	sigMgr     *signaling.FallbackManager
	state      *AppState
	srv        *http.Server
}

// NewServer создаёт новый экземпляр Web UI сервера
func NewServer(port int, user, password string, registry *peer.Registry, sigMgr *signaling.FallbackManager) *Server {
	return &Server{
		port:       port,
		user:       user,
		password:   password,
		configPath: "config.yaml",
		registry:   registry,
		sigMgr:     sigMgr,
		state: &AppState{
			StartedAt: time.Now(),
		},
	}
}

// SetConfigPath задает путь к файлу конфигурации
func (s *Server) SetConfigPath(path string) {
	if path != "" {
		s.configPath = path
	}
}

// SetAppState обновляет состояние приложения (вызывается из main)
func (s *Server) SetAppState(deviceID, publicIP, stunAddr string) {
	if s.state != nil {
		s.state.DeviceID = deviceID
		s.state.PublicIP = publicIP
		s.state.STUNAddr = stunAddr
	}
}

// GetPort возвращает актуальный порт, на котором работает сервер
func (s *Server) GetPort() int {
	return s.port
}

// Start запускает HTTP-сервер и ждёт отмены контекста (с авто-перебором порта при занятости)
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/refresh-ip", s.handleRefreshIP)
	mux.HandleFunc("/api/channel/switch", s.handleChannelSwitch)
	mux.HandleFunc("/api/channel/status", s.handleChannelStatus)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/test/telegram", s.handleTestTelegram)
	mux.HandleFunc("/api/test/mqtt", s.handleTestMQTT)
	mux.HandleFunc("/api/wg/config", s.handleWgConfig)
	mux.HandleFunc("/api/restart", s.handleRestart)

	handler := s.corsMiddleware(s.authMiddleware(mux))

	// Ищем свободный порт, начиная с s.port (до +20 портов)
	var listener net.Listener
	var err error
	initialPort := s.port
	if initialPort <= 0 {
		initialPort = 8080
	}

	for p := initialPort; p < initialPort+20; p++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err == nil {
			s.port = p
			break
		}
	}

	if listener == nil {
		listener, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("не удалось найти свободный порт для Web UI: %w", err)
		}
		s.port = listener.Addr().(*net.TCPAddr).Port
	}

	s.srv = &http.Server{
		Addr:         listener.Addr().String(),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Ошибка остановки Web UI сервера", "err", err)
		}
	}()

	slog.Info("Web UI запущен", "url", fmt.Sprintf("http://localhost:%d", s.port))
	if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("ошибка Web UI сервера: %w", err)
	}
	return nil
}

// authMiddleware — HTTP Basic Auth защита (активна только если задан пароль)
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.password == "" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.user))
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.password))
		if !ok || userMatch != 1 || passMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="NatBypass"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorized\n"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware — CORS заголовки
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// jsonResponse отправляет стандартный JSON-ответ
func (s *Server) jsonResponse(w http.ResponseWriter, status int, data interface{}, errStr string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	resp := Response{
		Ok:    status >= 200 && status < 300,
		Data:  data,
		Error: errStr,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("Ошибка сериализации JSON", "err", err)
	}
}

// handleIndex — главная страница
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	content, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

// handlePeers — GET /api/peers — список устройств
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	peers := s.registry.List()
	s.jsonResponse(w, http.StatusOK, peers, "")
}

// handleStatus — GET /api/status — статус приложения
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}

	uptime := time.Since(s.state.StartedAt).Round(time.Second).String()
	currentChannel := ""
	if s.sigMgr != nil {
		currentChannel = s.sigMgr.CurrentChannel()
	}

	status := map[string]interface{}{
		"device_id":       s.state.DeviceID,
		"public_ip":       s.state.PublicIP,
		"stun_addr":       s.state.STUNAddr,
		"uptime":          uptime,
		"started_at":      s.state.StartedAt,
		"current_channel": currentChannel,
		"peers_count":     len(s.registry.List()),
	}
	s.jsonResponse(w, http.StatusOK, status, "")
}

// handleRefreshIP — POST /api/refresh-ip — принудительное обновление IP
func (s *Server) handleRefreshIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	slog.Info("Запрос на обновление IP через Web UI")
	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Обновление IP запущено"}, "")
}

// handleChannelSwitch — POST /api/channel/switch — смена канала
func (s *Server) handleChannelSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, nil, "некорректный JSON")
		return
	}
	if req.Name == "" {
		s.jsonResponse(w, http.StatusBadRequest, nil, "имя канала не задано")
		return
	}
	if s.sigMgr != nil {
		if err := s.sigMgr.SwitchTo(req.Name); err != nil {
			s.jsonResponse(w, http.StatusBadRequest, nil, err.Error())
			return
		}
	}
	slog.Info("Переключён сигнальный канал", "channel", req.Name)
	s.jsonResponse(w, http.StatusOK, map[string]string{"channel": req.Name}, "")
}

// handleChannelStatus — GET /api/channel/status — статус каналов
func (s *Server) handleChannelStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	var statuses []signaling.ChannelStatus
	if s.sigMgr != nil {
		statuses = s.sigMgr.Status()
	}
	s.jsonResponse(w, http.StatusOK, statuses, "")
}

// handleConfig — GET & POST /api/config — чтение и сохранение настроек
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := config.Load(s.configPath)
		if err != nil {
			// Возвращаем дефолтный если файла нет
			cfg = &config.Config{}
			cfg.WebUI.Port = s.port
			cfg.WebUI.Enabled = true
		}
		s.jsonResponse(w, http.StatusOK, cfg, "")

	case http.MethodPost:
		var req config.Config
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonResponse(w, http.StatusBadRequest, nil, "ошибка разбора JSON: "+err.Error())
			return
		}

		// Сохраняем в YAML
		yamlData := fmt.Sprintf(`# ============================================================
# NatBypass — Конфигурационный файл (Сохранено через Web UI)
# ============================================================

app:
  name: "%s"
  version: "1.0.0"
  log_level: "%s"
  publish_interval: %d

web_ui:
  enabled: %t
  port: %d
  username: "%s"
  password: "%s"

network:
  upnp_enabled: %t
  stun_servers:
`, req.App.Name, req.App.LogLevel, req.App.PublishInterval, req.WebUI.Enabled, req.WebUI.Port, req.WebUI.Username, req.WebUI.Password, req.Network.UpnpEnabled)

		for _, st := range req.Network.StunServers {
			yamlData += fmt.Sprintf("    - \"%s\"\n", st)
		}
		yamlData += "  ip_apis:\n"
		for _, ipa := range req.Network.IPApis {
			yamlData += fmt.Sprintf("    - \"%s\"\n", ipa)
		}

		yamlData += "signaling:\n  channels:\n"
		for _, ch := range req.Signaling.Channels {
			yamlData += fmt.Sprintf("    - type: \"%s\"\n      priority: %d\n      enabled: %t\n      params:\n", ch.Type, ch.Priority, ch.Enabled)
			for k, v := range ch.Params {
				yamlData += fmt.Sprintf("        %s: \"%s\"\n", k, v)
			}
		}

		yamlData += fmt.Sprintf(`wireguard:
  enabled: %t
  interface: "%s"
  listen_port: %d
  mtu: %d
`, req.WireGuard.Enabled, req.WireGuard.Interface, req.WireGuard.ListenPort, req.WireGuard.MTU)

		targetPath := s.configPath
		if targetPath == "" {
			targetPath = "config.yaml"
		}
		_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
		if err := os.WriteFile(targetPath, []byte(yamlData), 0644); err != nil {
			s.jsonResponse(w, http.StatusInternalServerError, nil, "ошибка записи файла: "+err.Error())
			return
		}

		slog.Info("Настройки сохранены через Web UI", "file", targetPath)
		s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Конфигурация успешно сохранена!"}, "")

	default:
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
	}
}

// handleTestTelegram — POST /api/test/telegram — проверка Telegram токена и чата
func (s *Server) handleTestTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}

	var req struct {
		Token  string `json:"token"`
		ChatID string `json:"chat_id"`
		Proxy  string `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, nil, "некорректный JSON")
		return
	}
	if req.Token == "" {
		s.jsonResponse(w, http.StatusBadRequest, nil, "укажите токен бота")
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if req.Proxy != "" {
		if u, err := url.Parse(req.Proxy); err == nil && u.Scheme == "socks5" {
			if dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct); err == nil {
				client.Transport = &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					},
				}
			}
		}
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", req.Token)
	resp, err := client.Get(apiURL)
	if err != nil {
		s.jsonResponse(w, http.StatusBadRequest, nil, "ошибка подключения к Telegram API: "+err.Error())
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var tgResp struct {
		Ok          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
		} `json:"result"`
	}
	_ = json.Unmarshal(bodyBytes, &tgResp)

	if !tgResp.Ok {
		s.jsonResponse(w, http.StatusBadRequest, nil, "Telegram API ошибка: "+tgResp.Description)
		return
	}

	res := map[string]interface{}{
		"bot_username": "@" + tgResp.Result.Username,
		"bot_name":     tgResp.Result.FirstName,
		"status":       "Подключение успешно!",
	}
	s.jsonResponse(w, http.StatusOK, res, "")
}

// handleTestMQTT — POST /api/test/mqtt — проверка доступности брокера
func (s *Server) handleTestMQTT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	var req struct {
		BrokerURL string `json:"broker_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.BrokerURL == "" {
		req.BrokerURL = "tcp://mqtt.eclipseprojects.io:1883"
	}

	u, err := url.Parse(req.BrokerURL)
	host := req.BrokerURL
	if err == nil && u.Host != "" {
		host = u.Host
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		s.jsonResponse(w, http.StatusBadRequest, nil, "не удалось подключиться к MQTT брокеру: "+err.Error())
		return
	}
	conn.Close()

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "MQTT брокер доступен!"}, "")
}

// handleWgConfig — GET /api/wg/config — генерация WireGuard конфига
func (s *Server) handleWgConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}

	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, nil, "ошибка генерации ключей WireGuard")
		return
	}

	var wgPeers []wireguard.WGPeer
	for i, p := range s.registry.List() {
		if p.WGPubKey != "" {
			wgPeers = append(wgPeers, wireguard.WGPeer{
				PublicKey:  p.WGPubKey,
				Endpoint:   fmt.Sprintf("%s:%d", p.PublicIP, p.WGPort),
				AllowedIPs: []string{fmt.Sprintf("10.200.0.%d/32", i+2)},
			})
		}
	}

	cfg := &wireguard.WGConfig{
		InterfaceName: "wg0",
		PrivateKey:    kp.PrivateKey,
		Address:       "10.200.0.1/24",
		ListenPort:    51820,
		MTU:           1420,
		Peers:         wgPeers,
	}

	content, err := wireguard.GenerateWGConfig(cfg)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, nil, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="wg-mesh.conf"`)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

// handleRestart — POST /api/restart — перезапуск сервиса
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, nil, "метод не поддерживается")
		return
	}
	slog.Warn("Получен сигнал перезапуска через Web UI")
	s.jsonResponse(w, http.StatusOK, map[string]string{"message": "Сигнал перезапуска отправлен"}, "")

	go func() {
		time.Sleep(100 * time.Millisecond)
		if proc, err := os.FindProcess(os.Getpid()); err == nil {
			proc.Signal(syscall.SIGTERM)
		}
	}()
}