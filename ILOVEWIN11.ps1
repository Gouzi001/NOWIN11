# Revert Windows 10 Update Suppression Script Restores system update, telemetry, and notification settings
# -------------------------------------------
# Run as Administrator  
# powershell -ExecutionPolicy Bypass -File revert_win10_update_unlock.ps1
# -------------------------------------------
# Check Admin Rights
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator."
    Start-Sleep -Seconds 3
    exit 1
}

Write-Host "[*] Reverting system lockdown..." -ForegroundColor Cyan

# 1. Restore renamed DLL
$dllBackup = "C:\Windows\System32\UpdateNotificationMgr.dll.bak"
$dllOriginal = "C:\Windows\System32\UpdateNotificationMgr.dll"
if (Test-Path $dllBackup) {
    Rename-Item $dllBackup $dllOriginal -Force
    Write-Host "[OK] Restored UpdateNotificationMgr.dll"
}

# 2. Remove deny ACL from UNP folder
$unpPath = "C:\Windows\System32\UNP"
if (Test-Path $unpPath) {
    cmd.exe /c 'icacls "' + $unpPath + '" /remove:d Everyone'
    Write-Host "[OK] UNP folder access restored."
}

# 3. Re-enable Windows Update and Orchestrator services
foreach ($svc in "wuauserv", "usosvc") {
    sc.exe config $svc start= auto | Out-Null
    sc.exe start $svc | Out-Null
    Write-Host "[OK] Re-enabled service: $svc"
}

# 4. Re-enable DiagTrack (telemetry)
sc.exe config DiagTrack start= auto | Out-Null
sc.exe start DiagTrack | Out-Null
Write-Host "[OK] Re-enabled DiagTrack"

# 5. Restore CompatTelRunner.exe ACL
$compatPath = "C:\Windows\System32\CompatTelRunner.exe"
if (Test-Path $compatPath) {
    cmd.exe /c 'icacls "' + $compatPath + '" /remove:d Everyone'
    Write-Host "[OK] CompatTelRunner access restored."
}

# 6. Remove MS telemetry firewall rule
netsh advfirewall firewall delete rule name="Block MS Telemetry" | Out-Null
Write-Host "[OK] Telemetry firewall rule removed."

# 7. Delete scheduled tasks that re-locked update services
schtasks /Delete /TN "LockUpdateService" /F | Out-Null
schtasks /Delete /TN "LockUsoSvc" /F | Out-Null
Write-Host "[OK] Scheduled service lock tasks deleted."

# 8. Remove registry GPO locks
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Registry policy locks removed."

# 9. Reminder: Manual reinstall
Write-Host "[INFO] You may reinstall UWP apps manually via Store if needed."
Write-Host "[INFO] To reinstall Microsoft Edge, visit: https://www.microsoft.com/edge"

Write-Host "`n[RESTORE COMPLETE] System has been returned to update/default state." -ForegroundColor Green
