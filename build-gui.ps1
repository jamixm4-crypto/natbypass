Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }
$DistDir = Join-Path $ProjectRoot "dist"
$SoftDir = Join-Path $ProjectRoot "soft"
$BuildWinScript = Join-Path $ProjectRoot "build-win.ps1"

# Создаем главное окно
$form = New-Object System.Windows.Forms.Form
$form.Text = "NatBypass — Cross-Platform Builder"
$form.Size = New-Object System.Drawing.Size(780, 720)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(26, 29, 36)
$form.ForeColor = [System.Drawing.Color]::FromArgb(225, 230, 235)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "🚀 NatBypass Builder — Сборщик кроссплатформенных пакетов"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$titleLabel.Size = New-Object System.Drawing.Size(720, 25)
$form.Controls.Add($titleLabel)

$subLabel = New-Object System.Windows.Forms.Label
$subLabel.Text = "Задайте параметры для вшивания в бинарник и выберите целевые платформы:"
$subLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 150, 160)
$subLabel.Location = New-Object System.Drawing.Point(20, 42)
$subLabel.Size = New-Object System.Drawing.Size(720, 20)
$form.Controls.Add($subLabel)

# ── Группа настроек сигнализации ─────────────────────────────────
$grpSig = New-Object System.Windows.Forms.GroupBox
$grpSig.Text = " 📡 Сигнальные каналы (Fallback) "
$grpSig.Location = New-Object System.Drawing.Point(20, 70)
$grpSig.Size = New-Object System.Drawing.Size(725, 150)
$grpSig.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$form.Controls.Add($grpSig)

# Telegram
$lblTgToken = New-Object System.Windows.Forms.Label
$lblTgToken.Text = "Telegram Bot Token:"
$lblTgToken.Location = New-Object System.Drawing.Point(15, 28)
$lblTgToken.Size = New-Object System.Drawing.Size(150, 20)
$lblTgToken.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpSig.Controls.Add($lblTgToken)

$txtTgToken = New-Object System.Windows.Forms.TextBox
$txtTgToken.Location = New-Object System.Drawing.Point(170, 25)
$txtTgToken.Size = New-Object System.Drawing.Size(260, 24)
$txtTgToken.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtTgToken.ForeColor = [System.Drawing.Color]::White
$txtTgToken.UseSystemPasswordChar = $true
$grpSig.Controls.Add($txtTgToken)

$lblTgChat = New-Object System.Windows.Forms.Label
$lblTgChat.Text = "Chat/Channel ID:"
$lblTgChat.Location = New-Object System.Drawing.Point(445, 28)
$lblTgChat.Size = New-Object System.Drawing.Size(110, 20)
$lblTgChat.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpSig.Controls.Add($lblTgChat)

$txtTgChat = New-Object System.Windows.Forms.TextBox
$txtTgChat.Location = New-Object System.Drawing.Point(560, 25)
$txtTgChat.Size = New-Object System.Drawing.Size(150, 24)
$txtTgChat.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtTgChat.ForeColor = [System.Drawing.Color]::White
$grpSig.Controls.Add($txtTgChat)

# MQTT
$lblMqttBroker = New-Object System.Windows.Forms.Label
$lblMqttBroker.Text = "MQTT Broker URL:"
$lblMqttBroker.Location = New-Object System.Drawing.Point(15, 68)
$lblMqttBroker.Size = New-Object System.Drawing.Size(150, 20)
$lblMqttBroker.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpSig.Controls.Add($lblMqttBroker)

$txtMqttBroker = New-Object System.Windows.Forms.TextBox
$txtMqttBroker.Text = "tcp://mqtt.eclipseprojects.io:1883"
$txtMqttBroker.Location = New-Object System.Drawing.Point(170, 65)
$txtMqttBroker.Size = New-Object System.Drawing.Size(260, 24)
$txtMqttBroker.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtMqttBroker.ForeColor = [System.Drawing.Color]::White
$grpSig.Controls.Add($txtMqttBroker)

$lblMqttTopic = New-Object System.Windows.Forms.Label
$lblMqttTopic.Text = "MQTT Topic:"
$lblMqttTopic.Location = New-Object System.Drawing.Point(445, 68)
$lblMqttTopic.Size = New-Object System.Drawing.Size(110, 20)
$lblMqttTopic.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpSig.Controls.Add($lblMqttTopic)

$txtMqttTopic = New-Object System.Windows.Forms.TextBox
$txtMqttTopic.Text = "natbypass/mynet/peers"
$txtMqttTopic.Location = New-Object System.Drawing.Point(560, 65)
$txtMqttTopic.Size = New-Object System.Drawing.Size(150, 24)
$txtMqttTopic.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtMqttTopic.ForeColor = [System.Drawing.Color]::White
$grpSig.Controls.Add($txtMqttTopic)

# Webhook
$lblWebhook = New-Object System.Windows.Forms.Label
$lblWebhook.Text = "Webhook URL (опция):"
$lblWebhook.Location = New-Object System.Drawing.Point(15, 108)
$lblWebhook.Size = New-Object System.Drawing.Size(150, 20)
$lblWebhook.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpSig.Controls.Add($lblWebhook)

$txtWebhook = New-Object System.Windows.Forms.TextBox
$txtWebhook.Location = New-Object System.Drawing.Point(170, 105)
$txtWebhook.Size = New-Object System.Drawing.Size(540, 24)
$txtWebhook.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtWebhook.ForeColor = [System.Drawing.Color]::White
$grpSig.Controls.Add($txtWebhook)

# ── Группа настроек приложения ──────────────────────────────────
$grpApp = New-Object System.Windows.Forms.GroupBox
$grpApp.Text = " ⚙ Общие параметры "
$grpApp.Location = New-Object System.Drawing.Point(20, 230)
$grpApp.Size = New-Object System.Drawing.Size(725, 75)
$grpApp.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$form.Controls.Add($grpApp)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = "Web UI Port:"
$lblPort.Location = New-Object System.Drawing.Point(15, 28)
$lblPort.Size = New-Object System.Drawing.Size(85, 20)
$lblPort.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpApp.Controls.Add($lblPort)

$txtPort = New-Object System.Windows.Forms.TextBox
$txtPort.Text = "8080"
$txtPort.Location = New-Object System.Drawing.Point(105, 25)
$txtPort.Size = New-Object System.Drawing.Size(65, 24)
$txtPort.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtPort.ForeColor = [System.Drawing.Color]::White
$grpApp.Controls.Add($txtPort)

$lblUser = New-Object System.Windows.Forms.Label
$lblUser.Text = "Логин:"
$lblUser.Location = New-Object System.Drawing.Point(190, 28)
$lblUser.Size = New-Object System.Drawing.Size(50, 20)
$lblUser.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpApp.Controls.Add($lblUser)

$txtUser = New-Object System.Windows.Forms.TextBox
$txtUser.Text = "admin"
$txtUser.Location = New-Object System.Drawing.Point(245, 25)
$txtUser.Size = New-Object System.Drawing.Size(95, 24)
$txtUser.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtUser.ForeColor = [System.Drawing.Color]::White
$grpApp.Controls.Add($txtUser)

$lblPass = New-Object System.Windows.Forms.Label
$lblPass.Text = "Пароль:"
$lblPass.Location = New-Object System.Drawing.Point(360, 28)
$lblPass.Size = New-Object System.Drawing.Size(60, 20)
$lblPass.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpApp.Controls.Add($lblPass)

$txtPass = New-Object System.Windows.Forms.TextBox
$txtPass.Location = New-Object System.Drawing.Point(425, 25)
$txtPass.Size = New-Object System.Drawing.Size(110, 24)
$txtPass.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$txtPass.ForeColor = [System.Drawing.Color]::White
$txtPass.UseSystemPasswordChar = $true
$grpApp.Controls.Add($txtPass)

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Лог:"
$lblLog.Location = New-Object System.Drawing.Point(555, 28)
$lblLog.Size = New-Object System.Drawing.Size(40, 20)
$lblLog.ForeColor = [System.Drawing.Color]::FromArgb(220, 225, 230)
$grpApp.Controls.Add($lblLog)

$cmbLog = New-Object System.Windows.Forms.ComboBox
$cmbLog.Items.AddRange(@("info", "debug", "warn", "error"))
$cmbLog.SelectedIndex = 0
$cmbLog.DropDownStyle = "DropDownList"
$cmbLog.Location = New-Object System.Drawing.Point(600, 25)
$cmbLog.Size = New-Object System.Drawing.Size(110, 24)
$cmbLog.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$cmbLog.ForeColor = [System.Drawing.Color]::White
$grpApp.Controls.Add($cmbLog)

# ── Группа платформ ──────────────────────────────────────────────
$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = " 🎯 Целевые платформы "
$grpTarget.Location = New-Object System.Drawing.Point(20, 315)
$grpTarget.Size = New-Object System.Drawing.Size(725, 60)
$grpTarget.ForeColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
$form.Controls.Add($grpTarget)

$chkWin = New-Object System.Windows.Forms.CheckBox
$chkWin.Text = "Windows x64 (.exe)"
$chkWin.Checked = $true
$chkWin.Location = New-Object System.Drawing.Point(15, 25)
$chkWin.Size = New-Object System.Drawing.Size(150, 22)
$chkWin.ForeColor = [System.Drawing.Color]::White
$grpTarget.Controls.Add($chkWin)

$chkLinuxAmd64 = New-Object System.Windows.Forms.CheckBox
$chkLinuxAmd64.Text = "Linux x64"
$chkLinuxAmd64.Checked = $true
$chkLinuxAmd64.Location = New-Object System.Drawing.Point(175, 25)
$chkLinuxAmd64.Size = New-Object System.Drawing.Size(100, 22)
$chkLinuxAmd64.ForeColor = [System.Drawing.Color]::White
$grpTarget.Controls.Add($chkLinuxAmd64)

$chkArm64 = New-Object System.Windows.Forms.CheckBox
$chkArm64.Text = "ARM64 (Keenetic/RPi)"
$chkArm64.Checked = $true
$chkArm64.Location = New-Object System.Drawing.Point(285, 25)
$chkArm64.Size = New-Object System.Drawing.Size(160, 22)
$chkArm64.ForeColor = [System.Drawing.Color]::White
$grpTarget.Controls.Add($chkArm64)

$chkMips = New-Object System.Windows.Forms.CheckBox
$chkMips.Text = "MIPS (Big Endian)"
$chkMips.Checked = $true
$chkMips.Location = New-Object System.Drawing.Point(455, 25)
$chkMips.Size = New-Object System.Drawing.Size(130, 22)
$chkMips.ForeColor = [System.Drawing.Color]::White
$grpTarget.Controls.Add($chkMips)

$chkMipsle = New-Object System.Windows.Forms.CheckBox
$chkMipsle.Text = "MIPSLE (Keenetic)"
$chkMipsle.Checked = $true
$chkMipsle.Location = New-Object System.Drawing.Point(595, 25)
$chkMipsle.Size = New-Object System.Drawing.Size(125, 22)
$chkMipsle.ForeColor = [System.Drawing.Color]::White
$grpTarget.Controls.Add($chkMipsle)

# ── Кнопки сборки ────────────────────────────────────────────────
$btnBuildAll = New-Object System.Windows.Forms.Button
$btnBuildAll.Text = "🔨 Начать сборку"
$btnBuildAll.Location = New-Object System.Drawing.Point(20, 385)
$btnBuildAll.Size = New-Object System.Drawing.Size(230, 36)
$btnBuildAll.BackColor = [System.Drawing.Color]::FromArgb(35, 134, 54)
$btnBuildAll.ForeColor = [System.Drawing.Color]::White
$btnBuildAll.Font = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Bold)
$btnBuildAll.FlatStyle = "Flat"
$form.Controls.Add($btnBuildAll)

$btnBuildRouter = New-Object System.Windows.Forms.Button
$btnBuildRouter.Text = "📡 Только для роутеров"
$btnBuildRouter.Location = New-Object System.Drawing.Point(260, 385)
$btnBuildRouter.Size = New-Object System.Drawing.Size(220, 36)
$btnBuildRouter.BackColor = [System.Drawing.Color]::FromArgb(31, 111, 235)
$btnBuildRouter.ForeColor = [System.Drawing.Color]::White
$btnBuildRouter.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnBuildRouter.FlatStyle = "Flat"
$form.Controls.Add($btnBuildRouter)

$btnOpenDist = New-Object System.Windows.Forms.Button
$btnOpenDist.Text = "📂 Открыть папку dist\"
$btnOpenDist.Location = New-Object System.Drawing.Point(490, 385)
$btnOpenDist.Size = New-Object System.Drawing.Size(255, 36)
$btnOpenDist.BackColor = [System.Drawing.Color]::FromArgb(45, 50, 60)
$btnOpenDist.ForeColor = [System.Drawing.Color]::White
$btnOpenDist.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnOpenDist.FlatStyle = "Flat"
$form.Controls.Add($btnOpenDist)

# ── Окно лога сборки ─────────────────────────────────────────────
$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Location = New-Object System.Drawing.Point(20, 435)
$txtLog.Size = New-Object System.Drawing.Size(725, 230)
$txtLog.BackColor = [System.Drawing.Color]::FromArgb(15, 17, 23)
$txtLog.ForeColor = [System.Drawing.Color]::FromArgb(200, 210, 220)
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$txtLog.ReadOnly = $true
$txtLog.BorderStyle = "FixedSingle"
$form.Controls.Add($txtLog)

function Log-Message {
    param([string]$text, [System.Drawing.Color]$color = [System.Drawing.Color]::FromArgb(200, 210, 220))
    $txtLog.SelectionStart = $txtLog.TextLength
    $txtLog.SelectionLength = 0
    $txtLog.SelectionColor = $color
    $txtLog.AppendText("$text`r`n")
    $txtLog.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

$btnOpenDist.Add_Click({
    if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Force -Path $DistDir | Out-Null }
    [System.Diagnostics.Process]::Start("explorer.exe", $DistDir)
})

function Run-BuildJob {
    param([string]$targetMode)

    $btnBuildAll.Enabled = $false
    $btnBuildRouter.Enabled = $false
    $txtLog.Clear()

    Log-Message "============================================================" ([System.Drawing.Color]::FromArgb(88, 166, 255))
    Log-Message " Запуск сборки NatBypass ($targetMode)..." ([System.Drawing.Color]::FromArgb(88, 166, 255))
    Log-Message "============================================================" ([System.Drawing.Color]::FromArgb(88, 166, 255))

    $tgT = $txtTgToken.Text.Trim()
    $tgC = $txtTgChat.Text.Trim()
    $mqB = $txtMqttBroker.Text.Trim()
    $mqT = $txtMqttTopic.Text.Trim()
    $webH = $txtWebhook.Text.Trim()
    $p = $txtPort.Text.Trim()
    $u = $txtUser.Text.Trim()
    $pw = $txtPass.Text.Trim()
    $lvl = $cmbLog.SelectedItem.ToString()

    $argsList = @(
        "-ExecutionPolicy", "Bypass",
        "-File", $BuildWinScript,
        "-Unattended",
        "-Target", $targetMode,
        "-TgToken", $tgT,
        "-TgChatID", $tgC,
        "-MQTTBroker", $mqB,
        "-MQTTTopic", $mqT,
        "-WebhookURL", $webH,
        "-WebUIPort", $p,
        "-WebUIUser", $u,
        "-WebUIPass", $pw,
        "-LogLevel", $lvl
    )

    Log-Message ">> Параметры конфигурации переданы в сборщик." ([System.Drawing.Color]::Yellow)

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "powershell.exe"
    $pinfo.Arguments = ($argsList -join " ")
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null

    while (-not $proc.HasExited) {
        $line = $proc.StandardOutput.ReadLine()
        if ($line) {
            $col = [System.Drawing.Color]::FromArgb(200, 210, 220)
            if ($line -match "OK|SUCCESS") { $col = [System.Drawing.Color]::FromArgb(63, 185, 80) }
            elseif ($line -match "ERROR|FAILED|ОШИБКА") { $col = [System.Drawing.Color]::FromArgb(248, 81, 73) }
            elseif ($line -match ">>|---") { $col = [System.Drawing.Color]::FromArgb(210, 153, 34) }
            Log-Message $line $col
        }
        [System.Windows.Forms.Application]::DoEvents()
    }

    $err = $proc.StandardError.ReadToEnd()
    if ($err) {
        Log-Message $err ([System.Drawing.Color]::FromArgb(248, 81, 73))
    }

    if ($proc.ExitCode -eq 0) {
        Log-Message "`r`n✓ СБОРКА УСПЕШНО ЗАВЕРШЕНА!" ([System.Drawing.Color]::FromArgb(63, 185, 80))
        [System.Windows.Forms.MessageBox]::Show("Сборка успешно завершена!`r`nБинарники сохранены в папку dist\", "Успех", "OK", "Information")
    } else {
        Log-Message "`r`n✗ ОШИБКА СБОРКИ (Exit code: $($proc.ExitCode))" ([System.Drawing.Color]::FromArgb(248, 81, 73))
    }

    $btnBuildAll.Enabled = $true
    $btnBuildRouter.Enabled = $true
}

$btnBuildAll.Add_Click({ Run-BuildJob "all" })
$btnBuildRouter.Add_Click({ Run-BuildJob "router" })

Log-Message "Готов к сборке. Нажмите 'Начать сборку' или 'Только для роутеров'." ([System.Drawing.Color]::FromArgb(140, 150, 160))
[void]$form.ShowDialog()