Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }
$DistDir = Join-Path $ProjectRoot "dist"
$ExePath = Join-Path $DistDir "natbypass-windows-amd64.exe"
if (-not (Test-Path $ExePath)) { $ExePath = Join-Path $ProjectRoot "natbypass-windows-amd64.exe" }
$ConfigPath = Join-Path $DistDir "config.yaml"
if (-not (Test-Path $ConfigPath)) { $ConfigPath = Join-Path $ProjectRoot "config.yaml" }
$LogPath = Join-Path $DistDir "natbypass.log"
if (-not (Test-Path $LogPath)) { $LogPath = Join-Path $ProjectRoot "natbypass.log" }

# Проверяем / запускаем фоновый процесс natbypass если еще не запущен
$backendProc = $null

function Ensure-BackendRunning {
    $existing = Get-Process -Name "*natbypass*" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*natbypass*" }
    if (-not $existing) {
        if (Test-Path $ExePath) {
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = $ExePath
            $pinfo.Arguments = "start --tray=false"
            $pinfo.UseShellExecute = $false
            $pinfo.CreateNoWindow = $true
            $pinfo.WorkingDirectory = Split-Path $ExePath
            $global:backendProc = [System.Diagnostics.Process]::Start($pinfo)
        }
    }
}

Ensure-BackendRunning

# ── Создаем главное окно ─────────────────────────────────────────
$form = New-Object System.Windows.Forms.Form
$form.Text = "NatBypass — Панель управления P2P сетью"
$form.Size = New-Object System.Drawing.Size(960, 760)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$form.ForeColor = [System.Drawing.Color]::FromArgb(225, 230, 235)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

# Tray Icon для формы
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "NatBypass P2P Network"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Shield
$trayIcon.Visible = $true

$trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
$trayMenu.BackColor = [System.Drawing.Color]::FromArgb(25, 30, 40)
$trayMenu.ForeColor = [System.Drawing.Color]::White

$miOpen = $trayMenu.Items.Add("🖥 Открыть главное окно")
$miWebUI = $trayMenu.Items.Add("🌐 Открыть Web UI в браузере")
$miRefresh = $trayMenu.Items.Add("🔄 Обновить внешний IP")
$trayMenu.Items.Add("-") | Out-Null
$miStatus = $trayMenu.Items.Add("💡 Статус: Онлайн")
$miStatus.Enabled = $false
$trayMenu.Items.Add("-") | Out-Null
$miExit = $trayMenu.Items.Add("❌ Завершить работу")

$trayIcon.ContextMenuStrip = $trayMenu

$miOpen.Add_Click({
    $form.Show()
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $form.BringToFront()
})

$trayIcon.Add_DoubleClick({
    $form.Show()
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $form.BringToFront()
})

$miWebUI.Add_Click({
    [System.Diagnostics.Process]::Start("http://localhost:8080")
})

$miRefresh.Add_Click({
    try {
        Invoke-RestMethod -Uri "http://localhost:8080/api/refresh-ip" -Method Post -ErrorAction SilentlyContinue | Out-Null
        $trayIcon.ShowBalloonTip(2000, "NatBypass", "Запрос на обновление внешнего IP отправлен.", [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {}
})

$miExit.Add_Click({
    $trayIcon.Visible = $false
    if ($global:backendProc -and -not $global:backendProc.HasExited) {
        $global:backendProc.Kill()
    }
    $form.Close()
    [System.Windows.Forms.Application]::Exit()
})

# Сворачивание в трей при закрытии или минимизации
$form.Add_FormClosing({
    param($sender, $e)
    if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
        $e.Cancel = $true
        $form.Hide()
        $trayIcon.ShowBalloonTip(2500, "NatBypass", "Приложение свернуто в трей и продолжает работать в фоне.", [System.Windows.Forms.ToolTipIcon]::Info)
    }
})

# ── Заголовок формы ──────────────────────────────────────────────
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = "Top"
$headerPanel.Height = 75
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(25, 30, 42)
$form.Controls.Add($headerPanel)

$lblAppTitle = New-Object System.Windows.Forms.Label
$lblAppTitle.Text = "🚀 NatBypass P2P Network"
$lblAppTitle.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$lblAppTitle.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$lblAppTitle.Location = New-Object System.Drawing.Point(20, 12)
$lblAppTitle.Size = New-Object System.Drawing.Size(300, 25)
$headerPanel.Controls.Add($lblAppTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "Прямой P2P доступ через NAT / CGNAT с мультиканальной сигнализацией"
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(140, 155, 170)
$lblSub.Location = New-Object System.Drawing.Point(20, 40)
$lblSub.Size = New-Object System.Drawing.Size(480, 20)
$headerPanel.Controls.Add($lblSub)

# Статус бейджи в шапке
$lblBadgeStatus = New-Object System.Windows.Forms.Label
$lblBadgeStatus.Text = "🟢 ОНЛАЙН"
$lblBadgeStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$lblBadgeStatus.ForeColor = [System.Drawing.Color]::FromArgb(63, 185, 80)
$lblBadgeStatus.BackColor = [System.Drawing.Color]::FromArgb(20, 50, 30)
$lblBadgeStatus.TextAlign = "MiddleCenter"
$lblBadgeStatus.Location = New-Object System.Drawing.Point(520, 15)
$lblBadgeStatus.Size = New-Object System.Drawing.Size(100, 30)
$headerPanel.Controls.Add($lblBadgeStatus)

$lblHeaderIP = New-Object System.Windows.Forms.Label
$lblHeaderIP.Text = "IP: Определяется..."
$lblHeaderIP.ForeColor = [System.Drawing.Color]::FromArgb(210, 220, 230)
$lblHeaderIP.Location = New-Object System.Drawing.Point(630, 12)
$lblHeaderIP.Size = New-Object System.Drawing.Size(300, 20)
$headerPanel.Controls.Add($lblHeaderIP)

$lblHeaderChannel = New-Object System.Windows.Forms.Label
$lblHeaderChannel.Text = "Канал: telegram"
$lblHeaderChannel.ForeColor = [System.Drawing.Color]::FromArgb(160, 175, 190)
$lblHeaderChannel.Location = New-Object System.Drawing.Point(630, 35)
$lblHeaderChannel.Size = New-Object System.Drawing.Size(300, 20)
$headerPanel.Controls.Add($lblHeaderChannel)

# ── Табы (Вкладки) ───────────────────────────────────────────────
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$form.Controls.Add($tabControl)

# Вкладка 1: Устройства в сети
$tabPeers = New-Object System.Windows.Forms.TabPage
$tabPeers.Text = " 👥 Устройства в сети "
$tabPeers.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabPeers)

$gridPeers = New-Object System.Windows.Forms.DataGridView
$gridPeers.Dock = "Fill"
$gridPeers.BackgroundColor = [System.Drawing.Color]::FromArgb(15, 18, 25)
$gridPeers.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$gridPeers.GridColor = [System.Drawing.Color]::FromArgb(40, 45, 60)
$gridPeers.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(20, 25, 35)
$gridPeers.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$gridPeers.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(35, 75, 130)
$gridPeers.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(30, 36, 50)
$gridPeers.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$gridPeers.EnableHeadersVisualStyles = $false
$gridPeers.ReadOnly = $true
$gridPeers.AllowUserToAddRows = $false
$gridPeers.RowHeadersVisible = $false
$gridPeers.SelectionMode = "FullRowSelect"
$gridPeers.AutoSizeColumnsMode = "Fill"

$gridPeers.Columns.Add("DeviceID", "Устройство") | Out-Null
$gridPeers.Columns.Add("PublicIP", "Публичный IP") | Out-Null
$gridPeers.Columns.Add("STUNAddr", "STUN Endpoint") | Out-Null
$gridPeers.Columns.Add("WGPubKey", "WireGuard Key") | Out-Null
$gridPeers.Columns.Add("Online", "Статус") | Out-Null
$gridPeers.Columns.Add("LastSeen", "Последний раз виден") | Out-Null

$tabPeers.Controls.Add($gridPeers)

$panelPeersBottom = New-Object System.Windows.Forms.Panel
$panelPeersBottom.Dock = "Bottom"
$panelPeersBottom.Height = 45
$panelPeersBottom.BackColor = [System.Drawing.Color]::FromArgb(22, 27, 38)
$tabPeers.Controls.Add($panelPeersBottom)

$btnRefreshPeers = New-Object System.Windows.Forms.Button
$btnRefreshPeers.Text = "🔄 Обновить устройства"
$btnRefreshPeers.Location = New-Object System.Drawing.Point(10, 8)
$btnRefreshPeers.Size = New-Object System.Drawing.Size(180, 28)
$btnRefreshPeers.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnRefreshPeers.ForeColor = [System.Drawing.Color]::White
$btnRefreshPeers.FlatStyle = "Flat"
$panelPeersBottom.Controls.Add($btnRefreshPeers)

$btnTriggerIP = New-Object System.Windows.Forms.Button
$btnTriggerIP.Text = "⚡ Запросить новый IP"
$btnTriggerIP.Location = New-Object System.Drawing.Point(200, 8)
$btnTriggerIP.Size = New-Object System.Drawing.Size(180, 28)
$btnTriggerIP.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnTriggerIP.ForeColor = [System.Drawing.Color]::White
$btnTriggerIP.FlatStyle = "Flat"
$panelPeersBottom.Controls.Add($btnTriggerIP)

$btnOpenWebUIPeers = New-Object System.Windows.Forms.Button
$btnOpenWebUIPeers.Text = "🌐 Открыть Web UI"
$btnOpenWebUIPeers.Location = New-Object System.Drawing.Point(390, 8)
$btnOpenWebUIPeers.Size = New-Object System.Drawing.Size(160, 28)
$btnOpenWebUIPeers.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnOpenWebUIPeers.ForeColor = [System.Drawing.Color]::White
$btnOpenWebUIPeers.FlatStyle = "Flat"
$panelPeersBottom.Controls.Add($btnOpenWebUIPeers)

# Вкладка 2: Настройки Telegram и Сети
$tabSettings = New-Object System.Windows.Forms.TabPage
$tabSettings.Text = " ⚙ Настройки Telegram & Сети "
$tabSettings.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabSettings)

$panelSet = New-Object System.Windows.Forms.Panel
$panelSet.Dock = "Fill"
$panelSet.AutoScroll = $true
$panelSet.Padding = New-Object System.Windows.Forms.Padding(15)
$tabSettings.Controls.Add($panelSet)

# GroupBox: Telegram
$grpTg = New-Object System.Windows.Forms.GroupBox
$grpTg.Text = " 💬 Настройки Telegram Bot API "
$grpTg.Location = New-Object System.Drawing.Point(15, 10)
$grpTg.Size = New-Object System.Drawing.Size(890, 165)
$grpTg.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$panelSet.Controls.Add($grpTg)

$lblTgTok = New-Object System.Windows.Forms.Label
$lblTgTok.Text = "Bot Token:"
$lblTgTok.Location = New-Object System.Drawing.Point(20, 30)
$lblTgTok.Size = New-Object System.Drawing.Size(100, 20)
$lblTgTok.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($lblTgTok)

$txtTgToken = New-Object System.Windows.Forms.TextBox
$txtTgToken.Location = New-Object System.Drawing.Point(125, 27)
$txtTgToken.Size = New-Object System.Drawing.Size(460, 24)
$txtTgToken.BackColor = [System.Drawing.Color]::FromArgb(30, 35, 48)
$txtTgToken.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($txtTgToken)

$btnTestTg = New-Object System.Windows.Forms.Button
$btnTestTg.Text = "🧪 Проверить Telegram"
$btnTestTg.Location = New-Object System.Drawing.Point(600, 25)
$btnTestTg.Size = New-Object System.Drawing.Size(260, 28)
$btnTestTg.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnTestTg.ForeColor = [System.Drawing.Color]::White
$btnTestTg.FlatStyle = "Flat"
$grpTg.Controls.Add($btnTestTg)

$lblTgChat = New-Object System.Windows.Forms.Label
$lblTgChat.Text = "Chat/Channel ID:"
$lblTgChat.Location = New-Object System.Drawing.Point(20, 70)
$lblTgChat.Size = New-Object System.Drawing.Size(100, 20)
$lblTgChat.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($lblTgChat)

$txtTgChatID = New-Object System.Windows.Forms.TextBox
$txtTgChatID.Location = New-Object System.Drawing.Point(125, 67)
$txtTgChatID.Size = New-Object System.Drawing.Size(300, 24)
$txtTgChatID.BackColor = [System.Drawing.Color]::FromArgb(30, 35, 48)
$txtTgChatID.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($txtTgChatID)

$lblTgProxy = New-Object System.Windows.Forms.Label
$lblTgProxy.Text = "SOCKS5 Прокси:"
$lblTgProxy.Location = New-Object System.Drawing.Point(440, 70)
$lblTgProxy.Size = New-Object System.Drawing.Size(110, 20)
$lblTgProxy.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($lblTgProxy)

$txtTgProxy = New-Object System.Windows.Forms.TextBox
$txtTgProxy.Location = New-Object System.Drawing.Point(560, 67)
$txtTgProxy.Size = New-Object System.Drawing.Size(300, 24)
$txtTgProxy.BackColor = [System.Drawing.Color]::FromArgb(30, 35, 48)
$txtTgProxy.ForeColor = [System.Drawing.Color]::White
$grpTg.Controls.Add($txtTgProxy)

$lblTgHint = New-Object System.Windows.Forms.Label
$lblTgHint.Text = "💡 Подсказка: Бот создается в @BotFather, а Chat ID приватного канала начинается с -100..."
$lblTgHint.Location = New-Object System.Drawing.Point(20, 115)
$lblTgHint.Size = New-Object System.Drawing.Size(840, 35)
$lblTgHint.ForeColor = [System.Drawing.Color]::FromArgb(140, 155, 170)
$grpTg.Controls.Add($lblTgHint)

# GroupBox: MQTT
$grpMqtt = New-Object System.Windows.Forms.GroupBox
$grpMqtt.Text = " ⚡ Настройки MQTT Брокера "
$grpMqtt.Location = New-Object System.Drawing.Point(15, 190)
$grpMqtt.Size = New-Object System.Drawing.Size(890, 115)
$grpMqtt.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$panelSet.Controls.Add($grpMqtt)

$lblMqttB = New-Object System.Windows.Forms.Label
$lblMqttB.Text = "Broker URL:"
$lblMqttB.Location = New-Object System.Drawing.Point(20, 30)
$lblMqttB.Size = New-Object System.Drawing.Size(100, 20)
$lblMqttB.ForeColor = [System.Drawing.Color]::White
$grpMqtt.Controls.Add($lblMqttB)

$txtMqttBroker = New-Object System.Windows.Forms.TextBox
$txtMqttBroker.Location = New-Object System.Drawing.Point(125, 27)
$txtMqttBroker.Size = New-Object System.Drawing.Size(460, 24)
$txtMqttBroker.BackColor = [System.Drawing.Color]::FromArgb(30, 35, 48)
$txtMqttBroker.ForeColor = [System.Drawing.Color]::White
$grpMqtt.Controls.Add($txtMqttBroker)

$btnTestMqtt = New-Object System.Windows.Forms.Button
$btnTestMqtt.Text = "🧪 Проверить MQTT"
$btnTestMqtt.Location = New-Object System.Drawing.Point(600, 25)
$btnTestMqtt.Size = New-Object System.Drawing.Size(260, 28)
$btnTestMqtt.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnTestMqtt.ForeColor = [System.Drawing.Color]::White
$btnTestMqtt.FlatStyle = "Flat"
$grpMqtt.Controls.Add($btnTestMqtt)

$lblMqttT = New-Object System.Windows.Forms.Label
$lblMqttT.Text = "Topic:"
$lblMqttT.Location = New-Object System.Drawing.Point(20, 70)
$lblMqttT.Size = New-Object System.Drawing.Size(100, 20)
$lblMqttT.ForeColor = [System.Drawing.Color]::White
$grpMqtt.Controls.Add($lblMqttT)

$txtMqttTopic = New-Object System.Windows.Forms.TextBox
$txtMqttTopic.Location = New-Object System.Drawing.Point(125, 67)
$txtMqttTopic.Size = New-Object System.Drawing.Size(460, 24)
$txtMqttTopic.BackColor = [System.Drawing.Color]::FromArgb(30, 35, 48)
$txtMqttTopic.ForeColor = [System.Drawing.Color]::White
$grpMqtt.Controls.Add($txtMqttTopic)

# GroupBox: Windows Service & Сохранение
$grpSave = New-Object System.Windows.Forms.GroupBox
$grpSave.Text = " 💾 Сохранение и Служба Windows "
$grpSave.Location = New-Object System.Drawing.Point(15, 320)
$grpSave.Size = New-Object System.Drawing.Size(890, 180)
$grpSave.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$panelSet.Controls.Add($grpSave)

$btnSaveAll = New-Object System.Windows.Forms.Button
$btnSaveAll.Text = "💾 Сохранить и применить настройки"
$btnSaveAll.Location = New-Object System.Drawing.Point(20, 30)
$btnSaveAll.Size = New-Object System.Drawing.Size(340, 38)
$btnSaveAll.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnSaveAll.ForeColor = [System.Drawing.Color]::White
$btnSaveAll.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnSaveAll.FlatStyle = "Flat"
$grpSave.Controls.Add($btnSaveAll)

$lblSvcStatus = New-Object System.Windows.Forms.Label
$lblSvcStatus.Text = "Статус службы: Проверяется..."
$lblSvcStatus.Location = New-Object System.Drawing.Point(20, 85)
$lblSvcStatus.Size = New-Object System.Drawing.Size(840, 20)
$lblSvcStatus.ForeColor = [System.Drawing.Color]::White
$grpSave.Controls.Add($lblSvcStatus)

$btnSvcInstall = New-Object System.Windows.Forms.Button
$btnSvcInstall.Text = "➕ Установить службу"
$btnSvcInstall.Location = New-Object System.Drawing.Point(20, 115)
$btnSvcInstall.Size = New-Object System.Drawing.Size(180, 32)
$btnSvcInstall.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnSvcInstall.ForeColor = [System.Drawing.Color]::White
$btnSvcInstall.FlatStyle = "Flat"
$grpSave.Controls.Add($btnSvcInstall)

$btnSvcStart = New-Object System.Windows.Forms.Button
$btnSvcStart.Text = "▶ Запустить"
$btnSvcStart.Location = New-Object System.Drawing.Point(210, 115)
$btnSvcStart.Size = New-Object System.Drawing.Size(130, 32)
$btnSvcStart.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnSvcStart.ForeColor = [System.Drawing.Color]::White
$btnSvcStart.FlatStyle = "Flat"
$grpSave.Controls.Add($btnSvcStart)

$btnSvcStop = New-Object System.Windows.Forms.Button
$btnSvcStop.Text = "⏹ Остановить"
$btnSvcStop.Location = New-Object System.Drawing.Point(350, 115)
$btnSvcStop.Size = New-Object System.Drawing.Size(130, 32)
$btnSvcStop.BackColor = [System.Drawing.Color]::FromArgb(218, 54, 51)
$btnSvcStop.ForeColor = [System.Drawing.Color]::White
$btnSvcStop.FlatStyle = "Flat"
$grpSave.Controls.Add($btnSvcStop)

$btnSvcUninstall = New-Object System.Windows.Forms.Button
$btnSvcUninstall.Text = "➖ Удалить службу"
$btnSvcUninstall.Location = New-Object System.Drawing.Point(490, 115)
$btnSvcUninstall.Size = New-Object System.Drawing.Size(160, 32)
$btnSvcUninstall.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnSvcUninstall.ForeColor = [System.Drawing.Color]::White
$btnSvcUninstall.FlatStyle = "Flat"
$grpSave.Controls.Add($btnSvcUninstall)

# Вкладка 3: WireGuard Mesh
$tabWG = New-Object System.Windows.Forms.TabPage
$tabWG.Text = " 🔒 WireGuard Mesh "
$tabWG.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabWG)

$panelWG = New-Object System.Windows.Forms.Panel
$panelWG.Dock = "Fill"
$panelWG.Padding = New-Object System.Windows.Forms.Padding(20)
$tabWG.Controls.Add($panelWG)

$lblWGTitle = New-Object System.Windows.Forms.Label
$lblWGTitle.Text = "Автоматическая конфигурация P2P Mesh туннеля WireGuard:"
$lblWGTitle.ForeColor = [System.Drawing.Color]::FromArgb(180, 190, 200)
$lblWGTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblWGTitle.Size = New-Object System.Drawing.Size(600, 20)
$panelWG.Controls.Add($lblWGTitle)

$txtWGConfig = New-Object System.Windows.Forms.RichTextBox
$txtWGConfig.Location = New-Object System.Drawing.Point(20, 45)
$txtWGConfig.Size = New-Object System.Drawing.Size(890, 380)
$txtWGConfig.BackColor = [System.Drawing.Color]::FromArgb(15, 18, 25)
$txtWGConfig.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$txtWGConfig.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtWGConfig.ReadOnly = $true
$panelWG.Controls.Add($txtWGConfig)

$btnFetchWG = New-Object System.Windows.Forms.Button
$btnFetchWG.Text = "📥 Сгенерировать актуальный wg-mesh.conf"
$btnFetchWG.Location = New-Object System.Drawing.Point(20, 440)
$btnFetchWG.Size = New-Object System.Drawing.Size(300, 34)
$btnFetchWG.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnFetchWG.ForeColor = [System.Drawing.Color]::White
$btnFetchWG.FlatStyle = "Flat"
$panelWG.Controls.Add($btnFetchWG)

$btnCopyWG = New-Object System.Windows.Forms.Button
$btnCopyWG.Text = "📋 Скопировать в буфер"
$btnCopyWG.Location = New-Object System.Drawing.Point(330, 440)
$btnCopyWG.Size = New-Object System.Drawing.Size(200, 34)
$btnCopyWG.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnCopyWG.ForeColor = [System.Drawing.Color]::White
$btnCopyWG.FlatStyle = "Flat"
$panelWG.Controls.Add($btnCopyWG)

# Вкладка 4: Логи
$tabLogs = New-Object System.Windows.Forms.TabPage
$tabLogs.Text = " 📜 Журнал событий (Логи) "
$tabLogs.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabLogs)

$txtLogs = New-Object System.Windows.Forms.RichTextBox
$txtLogs.Dock = "Fill"
$txtLogs.BackColor = [System.Drawing.Color]::FromArgb(12, 15, 22)
$txtLogs.ForeColor = [System.Drawing.Color]::FromArgb(210, 220, 230)
$txtLogs.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$txtLogs.ReadOnly = $true
$tabLogs.Controls.Add($txtLogs)

$panelLogsBottom = New-Object System.Windows.Forms.Panel
$panelLogsBottom.Dock = "Bottom"
$panelLogsBottom.Height = 40
$panelLogsBottom.BackColor = [System.Drawing.Color]::FromArgb(22, 27, 38)
$tabLogs.Controls.Add($panelLogsBottom)

$btnClearLogs = New-Object System.Windows.Forms.Button
$btnClearLogs.Text = "Очистить"
$btnClearLogs.Location = New-Object System.Drawing.Point(10, 6)
$btnClearLogs.Size = New-Object System.Drawing.Size(100, 26)
$btnClearLogs.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnClearLogs.ForeColor = [System.Drawing.Color]::White
$btnClearLogs.FlatStyle = "Flat"
$panelLogsBottom.Controls.Add($btnClearLogs)

# ── Логика работы ────────────────────────────────────────────────

function Refresh-Dashboard {
    try {
        $st = Invoke-RestMethod -Uri "http://localhost:8080/api/status" -ErrorAction Stop
        if ($st.ok) {
            $d = $st.data
            $lblHeaderIP.Text = "IP: $($d.public_ip) (STUN: $($d.stun_addr))"
            $lblHeaderChannel.Text = "Канал: $($d.current_channel) | Устройств: $($d.peers_count)"
            $miStatus.Text = "💡 Статус: Онлайн ($($d.current_channel))"
        }
    } catch {}

    try {
        $peersRes = Invoke-RestMethod -Uri "http://localhost:8080/api/peers" -ErrorAction Stop
        $gridPeers.Rows.Clear()
        if ($peersRes.ok -and $peersRes.data) {
            foreach ($p in $peersRes.data) {
                $onl = if ($p.online) { "🟢 Онлайн" } else { "🔴 Офлайн" }
                $seen = if ($p.last_seen) { ([DateTime]$p.last_seen).ToLocalTime().ToString("HH:mm:ss") } else { "-" }
                $gridPeers.Rows.Add($p.device_id, $p.public_ip, $p.stun_addr, $p.wg_pub_key, $onl, $seen) | Out-Null
            }
        }
    } catch {}
}

function Load-ConfigForm {
    try {
        $cfgRes = Invoke-RestMethod -Uri "http://localhost:8080/api/config" -ErrorAction Stop
        if ($cfgRes.ok -and $cfgRes.data) {
            $c = $cfgRes.data
            if ($c.signaling -and $c.signaling.channels) {
                foreach ($ch in $c.signaling.channels) {
                    if ($ch.type -eq "telegram" -and $ch.params) {
                        $txtTgToken.Text = $ch.params.token
                        $txtTgChatID.Text = $ch.params.chat_id
                        $txtTgProxy.Text = $ch.params.proxy
                    }
                    if ($ch.type -eq "mqtt" -and $ch.params) {
                        $txtMqttBroker.Text = $ch.params.broker_url
                        $txtMqttTopic.Text = $ch.params.topic
                    }
                }
            }
        }
    } catch {}
}

function Refresh-ServiceStatus {
    try {
        $out = & $ExePath service status 2>&1
        $lblSvcStatus.Text = "Статус службы: $out"
    } catch {
        $lblSvcStatus.Text = "Статус службы: Не установлена"
    }
}

# ── Обработчики кнопок ───────────────────────────────────────────

$btnRefreshPeers.Add_Click({ Refresh-Dashboard })
$btnTriggerIP.Add_Click({
    try {
        Invoke-RestMethod -Uri "http://localhost:8080/api/refresh-ip" -Method Post -ErrorAction SilentlyContinue | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Запрос на обновление внешнего IP отправлен.", "NatBypass", "OK", "Information")
        Refresh-Dashboard
    } catch {}
})
$btnOpenWebUIPeers.Add_Click({ [System.Diagnostics.Process]::Start("http://localhost:8080") })

$btnTestTg.Add_Click({
    $tok = $txtTgToken.Text.Trim()
    $chat = $txtTgChatID.Text.Trim()
    $proxy = $txtTgProxy.Text.Trim()
    if (-not $tok) {
        [System.Windows.Forms.MessageBox]::Show("Укажите Bot Token для проверки", "Внимание", "OK", "Warning")
        return
    }
    try {
        $body = @{ token = $tok; chat_id = $chat; proxy = $proxy } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "http://localhost:8080/api/test/telegram" -Method Post -Body $body -ContentType "application/json"
        if ($res.ok) {
            [System.Windows.Forms.MessageBox]::Show("✓ Подключение к Telegram успешно!`nБот: $($res.data.bot_username) ($($res.data.bot_name))", "Telegram Тест", "OK", "Information")
        } else {
            [System.Windows.Forms.MessageBox]::Show("❌ Ошибка Telegram: $($res.error)", "Ошибка", "OK", "Error")
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Ошибка запроса к API: $_", "Ошибка", "OK", "Error")
    }
})

$btnTestMqtt.Add_Click({
    $b = $txtMqttBroker.Text.Trim()
    try {
        $body = @{ broker_url = $b } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "http://localhost:8080/api/test/mqtt" -Method Post -Body $body -ContentType "application/json"
        if ($res.ok) {
            [System.Windows.Forms.MessageBox]::Show("✓ $($res.data.status)", "MQTT Тест", "OK", "Information")
        } else {
            [System.Windows.Forms.MessageBox]::Show("❌ $($res.error)", "Ошибка", "OK", "Error")
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Ошибка проверки MQTT: $_", "Ошибка", "OK", "Error")
    }
})

$btnSaveAll.Add_Click({
    $channels = @()
    if ($txtTgToken.Text.Trim() -and $txtTgChatID.Text.Trim()) {
        $channels += @{
            type = "telegram"
            priority = 1
            enabled = $true
            params = @{
                token = $txtTgToken.Text.Trim()
                chat_id = $txtTgChatID.Text.Trim()
                proxy = $txtTgProxy.Text.Trim()
            }
        }
    }
    if ($txtMqttBroker.Text.Trim() -and $txtMqttTopic.Text.Trim()) {
        $channels += @{
            type = "mqtt"
            priority = 2
            enabled = $true
            params = @{
                broker_url = $txtMqttBroker.Text.Trim()
                topic = $txtMqttTopic.Text.Trim()
            }
        }
    }

    $payload = @{
        app = @{ name = "NatBypass"; log_level = "info"; publish_interval = 60 }
        web_ui = @{ enabled = $true; port = 8080; username = "admin"; password = "" }
        network = @{
            upnp_enabled = $true
            stun_servers = @("stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.cloudflare.com:3478")
            ip_apis = @("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")
        }
        signaling = @{ channels = $channels }
        wireguard = @{ enabled = $true; interface = "wg0"; listen_port = 51820; mtu = 1420 }
    } | ConvertTo-Json -Depth 6

    try {
        $res = Invoke-RestMethod -Uri "http://localhost:8080/api/config" -Method Post -Body $payload -ContentType "application/json"
        if ($res.ok) {
            [System.Windows.Forms.MessageBox]::Show("✓ Настройки Telegram и сети успешно сохранены в config.yaml и применены!", "Успех", "OK", "Information")
            Refresh-Dashboard
        } else {
            [System.Windows.Forms.MessageBox]::Show("Ошибка: $($res.error)", "Ошибка", "OK", "Error")
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Ошибка сохранения: $_", "Ошибка", "OK", "Error")
    }
})

$btnFetchWG.Add_Click({
    try {
        $conf = (Invoke-WebRequest -Uri "http://localhost:8080/api/wg/config" -UseBasicParsing).Content
        $txtWGConfig.Text = $conf
    } catch {
        $txtWGConfig.Text = "# Ошибка получения WireGuard конфигурации"
    }
})

$btnCopyWG.Add_Click({
    if ($txtWGConfig.Text) {
        [System.Windows.Forms.Clipboard]::SetText($txtWGConfig.Text)
        [System.Windows.Forms.MessageBox]::Show("WireGuard конфигурация скопирована в буфер обмена!", "NatBypass", "OK", "Information")
    }
})

$btnSvcInstall.Add_Click({
    $res = Start-Process -FilePath $ExePath -ArgumentList "service install --config `"$ConfigPath`"" -Verb RunAs -PassThru -Wait
    Refresh-ServiceStatus
})

$btnSvcStart.Add_Click({
    $res = Start-Process -FilePath $ExePath -ArgumentList "service start" -Verb RunAs -PassThru -Wait
    Refresh-ServiceStatus
})

$btnSvcStop.Add_Click({
    $res = Start-Process -FilePath $ExePath -ArgumentList "service stop" -Verb RunAs -PassThru -Wait
    Refresh-ServiceStatus
})

$btnSvcUninstall.Add_Click({
    $res = Start-Process -FilePath $ExePath -ArgumentList "service uninstall" -Verb RunAs -PassThru -Wait
    Refresh-ServiceStatus
})

$btnClearLogs.Add_Click({ $txtLogs.Clear() })

# Таймер автообновления
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Refresh-Dashboard })
$timer.Start()

Refresh-Dashboard
Load-ConfigForm
Refresh-ServiceStatus
$btnFetchWG.PerformClick()

[void]$form.ShowDialog()