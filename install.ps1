$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    Start-Process -FilePath 'powershell.exe' -ArgumentList $arg -Verb RunAs
    exit
}

$root = Split-Path -Parent $PSCommandPath
$sources = @(Get-ChildItem -Path $root -Filter '*.cs' | Sort-Object Name | ForEach-Object { $_.FullName })
if ($sources.Count -eq 0) {
    throw 'No .cs source files found next to install.ps1'
}

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path $csc)) {
    throw 'csc.exe (.NET Framework 4) not found. Install .NET Framework 4.8 and retry.'
}

$dest = Join-Path $env:ProgramData 'WinLockerGuard'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$exe = Join-Path $dest 'WinLockerGuard.exe'
$tempExe = Join-Path $env:TEMP 'WinLockerGuard_build.exe'

Write-Host 'Compiling WinLockerGuard...'
$cscArgs = @(
    '/nologo',
    '/target:winexe',
    '/optimize+',
    '/codepage:65001',
    ('/out:' + $tempExe),
    '/r:System.dll',
    '/r:System.Core.dll',
    '/r:System.Drawing.dll',
    '/r:System.Windows.Forms.dll',
    '/r:Microsoft.CSharp.dll'
)
$cscArgs += $sources
& $csc $cscArgs
if (-not (Test-Path $tempExe)) {
    $prebuilt = Join-Path $root 'WinLockerGuard.exe'
    if (Test-Path $prebuilt) {
        Write-Host 'Compiler failed, using prebuilt WinLockerGuard.exe.'
        Copy-Item -Force $prebuilt $tempExe
    } else {
        throw 'Compilation failed and no prebuilt WinLockerGuard.exe found.'
    }
}

Get-Process WinLockerGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Copy-Item -Force $tempExe $exe
Remove-Item -Force $tempExe -ErrorAction SilentlyContinue

$ini = Join-Path $dest 'settings.ini'
if (-not (Test-Path $ini)) {
    @(
        '# 1 = delete detected files permanently, 0 = move to quarantine (safer)',
        'PermanentDelete=0',
        '# how often to check windows, milliseconds',
        'ScanIntervalMs=700',
        '# how often to check autostart, seconds',
        'AutostartScanSeconds=5',
        '# show tray icon',
        'ShowTray=1'
    ) | Set-Content -Encoding ASCII $ini
}

$quotedExe = '"' + $exe + '"'
$taskCreated = $false
try {
    & schtasks.exe /Create /TN 'WinLockerGuard' /TR $quotedExe /SC ONLOGON /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $taskCreated = $true
    }
    & schtasks.exe /Create /TN 'WinLockerGuardWatchdog' /TR ($quotedExe + ' --ensure') /SC MINUTE /MO 1 /RL HIGHEST /F | Out-Null
} catch {
    $taskCreated = $false
}

if (-not $taskCreated) {
    Write-Host 'Scheduled task failed, using HKCU Run fallback.'
    $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if (-not (Test-Path $run)) {
        New-Item -Path $run -Force | Out-Null
    }
    Set-ItemProperty -Path $run -Name 'WinLockerGuard' -Value $quotedExe
}

Start-Process -FilePath $exe
Start-Sleep -Seconds 2

Write-Host ''
Write-Host 'WinLockerGuard installed.'
Write-Host ('Program:    ' + $exe)
Write-Host ('Log:        ' + (Join-Path $dest 'guard.log'))
Write-Host ('Quarantine: ' + (Join-Path $dest 'Quarantine'))
Write-Host ''
Write-Host 'It starts with Windows and checks every 700 ms.'
Write-Host 'To remove it, run Uninstall.bat.'
Write-Host ''
Read-Host 'Press Enter to close'
