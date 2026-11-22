$ErrorActionPreference = 'Stop'
$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $Project
$Node = (Get-Command node.exe -ErrorAction Stop).Source
$Cli = Join-Path $Project 'dist\cli\index.js'

function Write-Banner([string]$Message) {
    Write-Host ''
    Write-Host '  RITTEN  //  LOCAL CONTROL' -ForegroundColor Cyan
    Write-Host '  -----------------------------------------------' -ForegroundColor DarkGray
    Write-Host "  $Message" -ForegroundColor White
    Write-Host ''
}
function Invoke-RittenCli([string[]]$Arguments) {
    $Output = & $Node $Cli @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($Output -join [Environment]::NewLine) }
    return ($Output -join [Environment]::NewLine)
}
function Format-AuditLine([string]$Line) {
    try { $Event = $Line | ConvertFrom-Json } catch { return }
    $Time = try { ([datetime]$Event.time).ToLocalTime().ToString('HH:mm:ss.fff') } catch { '??:??:??' }
    $Name = if ($Event.event) { $Event.event } else { 'audit.event' }
    $Client = if ($Event.client) { "client=$($Event.client)" } else { '' }
    $Tool = if ($Event.tool) { "tool=$($Event.tool)" } else { '' }
    $Outcome = if ($Event.decision.decision) { "decision=$($Event.decision.decision)" } elseif ($Event.error) { "error=$($Event.error)" } elseif ($Event.cancelled) { 'cancelled=true' } else { '' }
    $Color = switch -Regex ($Name) { 'failed|denied|rejected|panic' { 'Red'; break } 'requested|pending|approval' { 'Yellow'; break } 'completed|started|login' { 'Green'; break } default { 'Gray' } }
    $Fields = @($Client,$Tool,$Outcome) | Where-Object { $_ }
    Write-Host "  $Time  " -NoNewline -ForegroundColor DarkGray
    Write-Host ('{0,-22}' -f $Name) -NoNewline -ForegroundColor $Color
    if ($Fields.Count) { Write-Host ('  ' + ($Fields -join '  ')) -ForegroundColor Gray } else { Write-Host '' }
}

Write-Banner 'Reading active config and runtime paths…'
try {
    $Paths = Invoke-RittenCli @('paths') | ConvertFrom-Json
    $Config = Invoke-RittenCli @('config','show','--effective') | ConvertFrom-Json
    Invoke-RittenCli @('config','validate') | Out-Null
} catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$LockFile = Join-Path $Paths.data 'instance.lock'
$LogDirectory = $Paths.logs
$McpPort = [int]$Config.server.port
$OwnerPort = [int]$Config.server.owner_port
$ExpectedPattern = '(?i)(dist[\\/]cli[\\/]index\.js|ritten).*(start)(\s+--foreground)?'

if (Test-Path -LiteralPath $LockFile) {
    $LockText = (Get-Content -LiteralPath $LockFile -Raw).Trim()
    $ExistingPid = 0
    if (-not [int]::TryParse($LockText, [ref]$ExistingPid) -or $ExistingPid -le 0) {
        Write-Host "  [ERROR] Lock file has no valid process ID: $LockFile" -ForegroundColor Red
        Write-Host '  Leaving it untouched because its owner cannot be verified.' -ForegroundColor Yellow
        exit 1
    }
    $Existing = Get-CimInstance Win32_Process -Filter "ProcessId=$ExistingPid" -ErrorAction SilentlyContinue
    if ($Existing) {
        if ($Existing.Name -ne 'node.exe' -or $Existing.CommandLine -notmatch $ExpectedPattern) {
            Write-Host "  [ERROR] Lock PID $ExistingPid belongs to a process that does not look like Ritten." -ForegroundColor Red
            Write-Host '  Refusing to stop it or remove its lock.' -ForegroundColor Yellow
            exit 1
        }
        Write-Host "  Stopping verified Ritten process $ExistingPid…" -ForegroundColor Yellow
        Stop-Process -Id $ExistingPid -Force
        try { Wait-Process -Id $ExistingPid -Timeout 10 -ErrorAction Stop } catch {}
        if (Get-Process -Id $ExistingPid -ErrorAction SilentlyContinue) {
            Write-Host '  [ERROR] Ritten is still running; keeping its lock.' -ForegroundColor Red
            exit 1
        }
    }
    Remove-Item -LiteralPath $LockFile -Force
    Write-Host '  Removed lock only after its recorded process was confirmed stopped.' -ForegroundColor Green
}

foreach ($Port in @($McpPort,$OwnerPort)) {
    $Listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Listener) {
        $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$($Listener.OwningProcess)" -ErrorAction SilentlyContinue
        Write-Host "  [ERROR] Port $Port is already held by PID $($Listener.OwningProcess) ($($Process.Name))." -ForegroundColor Red
        Write-Host '  Ritten was not started and no unrelated process was stopped.' -ForegroundColor Yellow
        exit 1
    }
}
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
$Offsets = @{}
Get-ChildItem -LiteralPath $LogDirectory -Filter 'audit-*.jsonl' -File -ErrorAction SilentlyContinue | ForEach-Object { $Offsets[$_.FullName] = [long]$_.Length }
$StartupOutput = Join-Path $Paths.data 'start.stdout.log'
$StartupError = Join-Path $Paths.data 'start.stderr.log'
$Server = $null
try {
    $Server = Start-Process -FilePath $Node -ArgumentList @('dist/cli/index.js','start','--foreground') -WorkingDirectory $Project -RedirectStandardOutput $StartupOutput -RedirectStandardError $StartupError -PassThru
    $Deadline = [datetime]::UtcNow.AddSeconds(15)
    while ([datetime]::UtcNow -lt $Deadline) {
        Start-Sleep -Milliseconds 250
        if ($Server.HasExited) {
            $ErrorText = if (Test-Path $StartupError) { Get-Content $StartupError -Raw } else { '' }
            $OutText = if (Test-Path $StartupOutput) { Get-Content $StartupOutput -Raw } else { '' }
            throw "Ritten exited during startup.`n$OutText`n$ErrorText"
        }
        $Mcp = Get-NetTCPConnection -State Listen -LocalPort $McpPort -ErrorAction SilentlyContinue | Select-Object -First 1
        $Owner = Get-NetTCPConnection -State Listen -LocalPort $OwnerPort -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($Mcp -and $Owner) { break }
    }
    if (-not $Mcp -or -not $Owner) { throw 'Ritten did not open both configured ports within 15 seconds.' }
    Write-Banner 'RUNNING  /  live audit monitor'
    Write-Host "  MCP       http://127.0.0.1:$McpPort/mcp" -ForegroundColor Cyan
    Write-Host "  OWNER     http://127.0.0.1:$OwnerPort/local" -ForegroundColor Cyan
    if ($Config.server.public_url) { Write-Host "  PUBLIC    $($Config.server.public_url)/mcp" -ForegroundColor DarkCyan }
    Write-Host "  LOGS      $LogDirectory" -ForegroundColor DarkGray
    Write-Host '  Press Ctrl+C to stop Ritten and return here.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  TIME          EVENT                   DETAILS' -ForegroundColor DarkGray
    Write-Host '  ---------------------------------------------------------------' -ForegroundColor DarkGray
    while (-not $Server.HasExited) {
        $Files = Get-ChildItem -LiteralPath $LogDirectory -Filter 'audit-*.jsonl' -File -ErrorAction SilentlyContinue | Sort-Object Name
        foreach ($File in $Files) {
            $Key = $File.FullName
            $Offset = if ($Offsets.ContainsKey($Key)) { [long]$Offsets[$Key] } else { [long]$File.Length }
            $Stream = [IO.File]::Open($Key,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                if ($Stream.Length -lt $Offset) { $Offset = 0L }
                [void]$Stream.Seek($Offset,[IO.SeekOrigin]::Begin)
                $Reader = [IO.StreamReader]::new($Stream)
                while ($null -ne ($Line = $Reader.ReadLine())) { Format-AuditLine $Line }
                $Offsets[$Key] = $Stream.Position
            } finally { $Stream.Dispose() }
        }
        Start-Sleep -Milliseconds 400
    }
    Write-Host '  Ritten stopped.' -ForegroundColor Yellow
} catch {
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($Server -and -not $Server.HasExited) {
        Stop-Process -Id $Server.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Server.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    if ($Server -and $Server.HasExited -and (Test-Path -LiteralPath $LockFile)) {
        $Recorded = (Get-Content -LiteralPath $LockFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($Recorded -eq [string]$Server.Id) { Remove-Item -LiteralPath $LockFile -Force -ErrorAction SilentlyContinue }
    }
}
