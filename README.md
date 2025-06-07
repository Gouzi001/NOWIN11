This scripts are for everyone who's happy with their stable, working Windows 10 system — and tired of being nagged to upgrade or shown ads for things they never asked for.
No nags. No telemetry. No forced updates..

🔧 WIN10NUUPDATE.ps1 — Windows 10 Update Suppression Script
This script disables Windows 10 upgrade nag popups, blocks telemetry, and locks down update services to prevent unwanted feature updates or Windows 11 upgrade suggestions.

Key actions:
Renames UpdateNotificationMgr.dll to block EOS popups
Blocks telemetry IP ranges via firewall
Disables wuauserv, usosvc, DiagTrack, and CompatTelRunner.exe
Locks UNP folder and CompatTelRunner.exe via ACL
Removes selected UWP bloat (GetHelp, Communications)
Removes Microsoft Edge (if possible)
Applies registry-based GPO locks
Sets scheduled tasks to keep updates disabled

💡 Recommended for hardened, stable Windows 10 systems that should not upgrade



♻️ ILOVEWIN11.ps1 — Restore Script
This script reverts all changes made by WIN10NUUPDATE.ps1, restoring update functionality, telemetry services, and system files.
Probably you will never need it as Windows 12 will be released soon.

Key actions:
Restores UpdateNotificationMgr.dll if backed up
Re-enables wuauserv, usosvc, DiagTrack
Removes deny ACLs from UNP and CompatTelRunner.exe
Deletes firewall rule blocking telemetry
Removes registry-based GPO locks
Deletes scheduled lockdown tasks

🛠 Useful if system needs to return to default update behavior
💡 Can be used before manually upgrading to Windows 11
