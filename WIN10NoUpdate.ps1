# Windows 10 End-of-Support Popup Suppression & Update Lockdown Script
# ------------------------------------------------------
# Run as Administrator  
# powershell -ExecutionPolicy Bypass -File WIN10NUUPDATE.ps1
# ------------------------------------------------------

# Check Admin Rights
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator."
    Start-Sleep -Seconds 3
    exit 1
}


Write-Host "[*] Starting Windows 10 nag and update suppression..." -ForegroundColor Cyan

# 1. Take Ownership of UNP folder
$unpPath = "C:\Windows\System32\UNP"
if (Test-Path $unpPath) {
    takeown /f $unpPath /r /d Y | Out-Null
    icacls $unpPath /grant Administrators:F /t | Out-Null
    Write-Host "[OK] Ownership of UNP folder taken."
} else {
    Write-Host "[INFO] UNP folder not found."
}

# 2. Rename UpdateNotificationMgr.dll if it exists
$dllPath = "C:\Windows\System32\UpdateNotificationMgr.dll"
if (Test-Path $dllPath) {
    Rename-Item $dllPath "$dllPath.bak" -Force
    Write-Host "[OK] Renamed UpdateNotificationMgr.dll"
} else {
    Write-Host "[INFO] UpdateNotificationMgr.dll not found."
}

# 3. Remove annoying UWP apps
Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage
Write-Host "[OK] Removed UWP communication and help apps."

# 4. Block Microsoft telemetry IPs
netsh advfirewall firewall add rule name="Block MS Telemetry" dir=out action=block remoteip=13.107.0.0/16,20.190.128.0/18,40.76.0.0/14 enable=yes
Write-Host "[OK] Firewall rule for telemetry blocking applied."

$unpPath = "C:\Windows\System32\UNP"
$dllPath = "C:\Windows\System32\UpdateNotificationMgr.dll"
$compatPath = "C:\Windows\System32\CompatTelRunner.exe"

# 5. Deny access to UNP folder
# Deny ACL on CompatTelRunner.exe
if (Test-Path $compatPath) {
    takeown /f $compatPath | Out-Null
    cmd.exe /c 'icacls "' + $compatPath + '" /deny Everyone:(X)'
    Write-Host "[OK] Disabled CompatTelRunner.exe"
}




# 6. Stop and disable Update Orchestrator and Windows Update services
foreach ($svc in "wuauserv", "usosvc") {
    sc.exe stop $svc | Out-Null
    sc.exe config $svc start= disabled | Out-Null
    Write-Host "[OK] Service $svc disabled."
}

# 7. Registry-based GPO Locks
$wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
New-Item -Path $wuRegPath -Force | Out-Null
Set-ItemProperty -Path $wuRegPath -Name "DisableOSUpgrade" -Type DWord -Value 1

$auRegPath = "$wuRegPath\AU"
New-Item -Path $auRegPath -Force | Out-Null
Set-ItemProperty -Path $auRegPath -Name "NoAutoUpdate" -Type DWord -Value 1
Set-ItemProperty -Path $auRegPath -Name "AUOptions" -Type DWord -Value 1

$uxRegPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
New-Item -Path $uxRegPath -Force | Out-Null
Set-ItemProperty -Path $uxRegPath -Name "HideMCTLink" -Type DWord -Value 1
Set-ItemProperty -Path $uxRegPath -Name "IsConvergedUpdateStackEnabled" -Type DWord -Value 0
Write-Host "[OK] Group Policy registry keys applied."

# 8. Scheduled Tasks to re-disable services at logon (persistence)
schtasks /Create /TN "LockUpdateService" /TR "sc config wuauserv start= disabled" /SC ONLOGON /RL HIGHEST /RU SYSTEM /F | Out-Null
schtasks /Create /TN "LockUsoSvc" /TR "sc config usosvc start= disabled" /SC ONLOGON /RL HIGHEST /RU SYSTEM /F | Out-Null
Write-Host "[OK] Scheduled tasks created to persist service lockdown."

# 9. Optional Cleanup
$foldersToRemove = @(
    "C:\Windows10Upgrade",
    "C:\$WINDOWS.~BT"
)
foreach ($folder in $foldersToRemove) {
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed: $folder"
    }
}


# 10. Kill DiagTrack (telemetry service)
sc.exe stop DiagTrack | Out-Null
sc.exe config DiagTrack start= disabled | Out-Null
Write-Host "[OK] Disabled DiagTrack service."


# 11. Remove Microsoft Edge (both legacy & Chromium)
# Try both package and system uninstall
try {
    Get-AppxPackage *Microsoft.MicrosoftEdge* | Remove-AppxPackage -AllUsers
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application"
    if (Test-Path $edgePath) {
        takeown /f $edgePath /r /d Y | Out-Null
        icacls $edgePath /grant Administrators:F /t | Out-Null
        Remove-Item -Path $edgePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Edge directory deleted."
    }
    Write-Host "[OK] Microsoft Edge removed."
} catch {
    Write-Warning "Edge removal failed or partially skipped."
}




Write-Host "`n[COMPLETE] Windows 10 update popup & upgrade suppression finished." -ForegroundColor Green
