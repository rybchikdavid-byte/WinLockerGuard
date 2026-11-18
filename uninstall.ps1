$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    Start-Process -FilePath 'powershell.exe' -ArgumentList $arg -Verb RunAs
    exit
}

$dest = Join-Path $env:ProgramData 'WinLockerGuard'
$exe = Join-Path $dest 'WinLockerGuard.exe'

Get-Process WinLockerGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

& schtasks.exe /Delete /TN 'WinLockerGuard' /F 2>$null | Out-Null
& schtasks.exe /Delete /TN 'WinLockerGuardWatchdog' /F 2>$null | Out-Null

Get-Process WinLockerGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $run) {
    Remove-ItemProperty -Path $run -Name 'WinLockerGuard' -ErrorAction SilentlyContinue
}
$runHklm = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $runHklm) {
    Remove-ItemProperty -Path $runHklm -Name 'WinLockerGuard' -ErrorAction SilentlyContinue
}

if (Test-Path $exe) {
    Remove-Item -Force $exe -ErrorAction SilentlyContinue
}
$ini = Join-Path $dest 'settings.ini'
if (Test-Path $ini) {
    Remove-Item -Force $ini -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'WinLockerGuard removed.'
Write-Host ('Quarantine kept at: ' + (Join-Path $dest 'Quarantine'))
Write-Host 'Delete that folder yourself if you do not need the quarantined files.'
Write-Host ''
Read-Host 'Press Enter to close'
