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
            $pinfo.Arguments = "--tray=false"
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
$form.Size = New-Object System.Drawing.Size(920, 720)
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
$lblHeaderIP.Size = New-Object System.Drawing.Size(260, 20)
$headerPanel.Controls.Add($lblHeaderIP)

$lblHeaderChannel = New-Object System.Windows.Forms.Label
$lblHeaderChannel.Text = "Канал: telegram"
$lblHeaderChannel.ForeColor = [System.Drawing.Color]::FromArgb(160, 175, 190)
$lblHeaderChannel.Location = New-Object System.Drawing.Point(630, 35)
$lblHeaderChannel.Size = New-Object System.Drawing.Size(260, 20)
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

# Вкладка 2: Сигнальные каналы
$tabChannels = New-Object System.Windows.Forms.TabPage
$tabChannels.Text = " 📡 Сигнальные каналы "
$tabChannels.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabChannels)

$panelCh = New-Object System.Windows.Forms.Panel
$panelCh.Dock = "Fill"
$panelCh.Padding = New-Object System.Windows.Forms.Padding(20)
$tabChannels.Controls.Add($panelCh)

$lblChDesc = New-Object System.Windows.Forms.Label
$lblChDesc.Text = "Состояние мультиканальной сети сигнализации (Fallback Manager):"
$lblChDesc.ForeColor = [System.Drawing.Color]::FromArgb(180, 190, 200)
$lblChDesc.Location = New-Object System.Drawing.Point(20, 15)
$lblChDesc.Size = New-Object System.Drawing.Size(700, 20)
$panelCh.Controls.Add($lblChDesc)

$listChannels = New-Object System.Windows.Forms.ListView
$listChannels.Location = New-Object System.Drawing.Point(20, 45)
$listChannels.Size = New-Object System.Drawing.Size(860, 220)
$listChannels.View = "Details"
$listChannels.FullRowSelect = $true
$listChannels.GridLines = $true
$listChannels.BackColor = [System.Drawing.Color]::FromArgb(15, 18, 25)
$listChannels.ForeColor = [System.Drawing.Color]::White
$listChannels.Columns.Add("Канал", 150) | Out-Null
$listChannels.Columns.Add("Статус", 150) | Out-Null
$listChannels.Columns.Add("Приоритет", 100) | Out-Null
$listChannels.Columns.Add("Последняя ошибка", 440) | Out-Null
$panelCh.Controls.Add($listChannels)

$lblSwitch = New-Object System.Windows.Forms.Label
$lblSwitch.Text = "Принудительно переключить активный сигнальный канал:"
$lblSwitch.Location = New-Object System.Drawing.Point(20, 285)
$lblSwitch.Size = New-Object System.Drawing.Size(400, 20)
$panelCh.Controls.Add($lblSwitch)

$cmbSwitchCh = New-Object System.Windows.Forms.ComboBox
$cmbSwitchCh.Items.AddRange(@("telegram", "mqtt", "webhook", "dns"))
$cmbSwitchCh.SelectedIndex = 0
$cmbSwitchCh.DropDownStyle = "DropDownList"
$cmbSwitchCh.Location = New-Object System.Drawing.Point(20, 310)
$cmbSwitchCh.Size = New-Object System.Drawing.Size(180, 26)
$cmbSwitchCh.BackColor = [System.Drawing.Color]::FromArgb(35, 40, 50)
$cmbSwitchCh.ForeColor = [System.Drawing.Color]::White
$panelCh.Controls.Add($cmbSwitchCh)

$btnSwitchCh = New-Object System.Windows.Forms.Button
$btnSwitchCh.Text = "🔀 Переключить"
$btnSwitchCh.Location = New-Object System.Drawing.Point(210, 309)
$btnSwitchCh.Size = New-Object System.Drawing.Size(140, 28)
$btnSwitchCh.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnSwitchCh.ForeColor = [System.Drawing.Color]::White
$btnSwitchCh.FlatStyle = "Flat"
$panelCh.Controls.Add($btnSwitchCh)

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
$txtWGConfig.Size = New-Object System.Drawing.Size(860, 360)
$txtWGConfig.BackColor = [System.Drawing.Color]::FromArgb(15, 18, 25)
$txtWGConfig.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$txtWGConfig.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtWGConfig.ReadOnly = $true
$panelWG.Controls.Add($txtWGConfig)

$btnFetchWG = New-Object System.Windows.Forms.Button
$btnFetchWG.Text = "📥 Сгенерировать актуальный wg-mesh.conf"
$btnFetchWG.Location = New-Object System.Drawing.Point(20, 420)
$btnFetchWG.Size = New-Object System.Drawing.Size(300, 32)
$btnFetchWG.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnFetchWG.ForeColor = [System.Drawing.Color]::White
$btnFetchWG.FlatStyle = "Flat"
$panelWG.Controls.Add($btnFetchWG)

$btnCopyWG = New-Object System.Windows.Forms.Button
$btnCopyWG.Text = "📋 Скопировать в буфер"
$btnCopyWG.Location = New-Object System.Drawing.Point(330, 420)
$btnCopyWG.Size = New-Object System.Drawing.Size(200, 32)
$btnCopyWG.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnCopyWG.ForeColor = [System.Drawing.Color]::White
$btnCopyWG.FlatStyle = "Flat"
$panelWG.Controls.Add($btnCopyWG)

# Вкладка 4: Управление и Служба Windows
$tabService = New-Object System.Windows.Forms.TabPage
$tabService.Text = " ⚙ Управление и Служба Windows "
$tabService.BackColor = [System.Drawing.Color]::FromArgb(18, 22, 30)
$tabControl.TabPages.Add($tabService)

$panelSvc = New-Object System.Windows.Forms.Panel
$panelSvc.Dock = "Fill"
$panelSvc.Padding = New-Object System.Windows.Forms.Padding(20)
$tabService.Controls.Add($panelSvc)

$grpWinSvc = New-Object System.Windows.Forms.GroupBox
$grpWinSvc.Text = " 🪟 Системная служба Windows (Service) "
$grpWinSvc.Location = New-Object System.Drawing.Point(20, 20)
$grpWinSvc.Size = New-Object System.Drawing.Size(860, 140)
$grpWinSvc.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$panelSvc.Controls.Add($grpWinSvc)

$lblSvcStatus = New-Object System.Windows.Forms.Label
$lblSvcStatus.Text = "Статус службы: Проверяется..."
$lblSvcStatus.Location = New-Object System.Drawing.Point(20, 30)
$lblSvcStatus.Size = New-Object System.Drawing.Size(400, 20)
$lblSvcStatus.ForeColor = [System.Drawing.Color]::White
$grpWinSvc.Controls.Add($lblSvcStatus)

$btnSvcInstall = New-Object System.Windows.Forms.Button
$btnSvcInstall.Text = "➕ Установить службу"
$btnSvcInstall.Location = New-Object System.Drawing.Point(20, 65)
$btnSvcInstall.Size = New-Object System.Drawing.Size(180, 32)
$btnSvcInstall.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnSvcInstall.ForeColor = [System.Drawing.Color]::White
$btnSvcInstall.FlatStyle = "Flat"
$grpWinSvc.Controls.Add($btnSvcInstall)

$btnSvcStart = New-Object System.Windows.Forms.Button
$btnSvcStart.Text = "▶ Запустить"
$btnSvcStart.Location = New-Object System.Drawing.Point(210, 65)
$btnSvcStart.Size = New-Object System.Drawing.Size(130, 32)
$btnSvcStart.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnSvcStart.ForeColor = [System.Drawing.Color]::White
$btnSvcStart.FlatStyle = "Flat"
$grpWinSvc.Controls.Add($btnSvcStart)

$btnSvcStop = New-Object System.Windows.Forms.Button
$btnSvcStop.Text = "⏹ Остановить"
$btnSvcStop.Location = New-Object System.Drawing.Point(350, 65)
$btnSvcStop.Size = New-Object System.Drawing.Size(130, 32)
$btnSvcStop.BackColor = [System.Drawing.Color]::FromArgb(218, 54, 51)
$btnSvcStop.ForeColor = [System.Drawing.Color]::White
$btnSvcStop.FlatStyle = "Flat"
$grpWinSvc.Controls.Add($btnSvcStop)

$btnSvcUninstall = New-Object System.Windows.Forms.Button
$btnSvcUninstall.Text = "➖ Удалить службу"
$btnSvcUninstall.Location = New-Object System.Drawing.Point(490, 65)
$btnSvcUninstall.Size = New-Object System.Drawing.Size(160, 32)
$btnSvcUninstall.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnSvcUninstall.ForeColor = [System.Drawing.Color]::White
$btnSvcUninstall.FlatStyle = "Flat"
$grpWinSvc.Controls.Add($btnSvcUninstall)

$grpActions = New-Object System.Windows.Forms.GroupBox
$grpActions.Text = " 📁 Файлы и Редактирование "
$grpActions.Location = New-Object System.Drawing.Point(20, 180)
$grpActions.Size = New-Object System.Drawing.Size(860, 120)
$grpActions.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$panelSvc.Controls.Add($grpActions)

$btnOpenConfig = New-Object System.Windows.Forms.Button
$btnOpenConfig.Text = "📝 Редактировать config.yaml"
$btnOpenConfig.Location = New-Object System.Drawing.Point(20, 40)
$btnOpenConfig.Size = New-Object System.Drawing.Size(240, 34)
$btnOpenConfig.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnOpenConfig.ForeColor = [System.Drawing.Color]::White
$btnOpenConfig.FlatStyle = "Flat"
$grpActions.Controls.Add($btnOpenConfig)

$btnOpenDir = New-Object System.Windows.Forms.Button
$btnOpenDir.Text = "📂 Открыть папку программы"
$btnOpenDir.Location = New-Object System.Drawing.Point(270, 40)
$btnOpenDir.Size = New-Object System.Drawing.Size(240, 34)
$btnOpenDir.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 65)
$btnOpenDir.ForeColor = [System.Drawing.Color]::White
$btnOpenDir.FlatStyle = "Flat"
$grpActions.Controls.Add($btnOpenDir)

# Вкладка 5: Логи
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

# ── Логика обновления данных ─────────────────────────────────────

function Append-LogLine {
    param([string]$text)
    if (-not $text) { return }
    $col = [System.Drawing.Color]::FromArgb(200, 210, 220)
    if ($text -match "ERR|error|ошибка") { $col = [System.Drawing.Color]::FromArgb(248, 81, 73) }
    elseif ($text -match "WRN|warn|предупреждение") { $col = [System.Drawing.Color]::FromArgb(210, 153, 34) }
    elseif ($text -match "INF|info|OK|запущен") { $col = [System.Drawing.Color]::FromArgb(63, 185, 80) }

    $txtLogs.SelectionStart = $txtLogs.TextLength
    $txtLogs.SelectionLength = 0
    $txtLogs.SelectionColor = $col
    $txtLogs.AppendText("$text`r`n")
    $txtLogs.ScrollToCaret()
}

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

    # Загрузка пиров
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

    # Загрузка статуса каналов
    try {
        $chRes = Invoke-RestMethod -Uri "http://localhost:8080/api/channel/status" -ErrorAction Stop
        $listChannels.Items.Clear()
        if ($chRes.ok -and $chRes.data) {
            foreach ($c in $chRes.data) {
                $stText = if ($c.available) { "🟢 Доступен" } else { "🔴 Недоступен" }
                $item = New-Object System.Windows.Forms.ListViewItem($c.name)
                $item.SubItems.Add($stText) | Out-Null
                $item.SubItems.Add("1") | Out-Null
                $item.SubItems.Add($c.last_error) | Out-Null
                $listChannels.Items.Add($item) | Out-Null
            }
        }
    } catch {}

    # Чтение новых логов
    if (Test-Path $LogPath) {
        $recent = Get-Content $LogPath -Tail 15 -ErrorAction SilentlyContinue
        foreach ($line in $recent) {
            if ($line -and -not $txtLogs.Text.Contains($line)) {
                Append-LogLine $line
            }
        }
    }
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

$btnSwitchCh.Add_Click({
    $targetCh = $cmbSwitchCh.SelectedItem.ToString()
    try {
        $body = @{ name = $targetCh } | ConvertTo-Json
        $res = Invoke-RestMethod -Uri "http://localhost:8080/api/channel/switch" -Method Post -Body $body -ContentType "application/json"
        [System.Windows.Forms.MessageBox]::Show("Канал переключен на: $targetCh", "NatBypass", "OK", "Information")
        Refresh-Dashboard
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Ошибка переключения: $_", "Ошибка", "OK", "Error")
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

$btnOpenConfig.Add_Click({
    [System.Diagnostics.Process]::Start("notepad.exe", $ConfigPath)
})

$btnOpenDir.Add_Click({
    [System.Diagnostics.Process]::Start("explorer.exe", $DistDir)
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

# Таймер автообновления GUI (каждые 3 сек)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Refresh-Dashboard })
$timer.Start()

Refresh-Dashboard
Refresh-ServiceStatus
$btnFetchWG.PerformClick()

[void]$form.ShowDialog()