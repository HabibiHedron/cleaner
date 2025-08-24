$ErrorActionPreference = "Stop"
function Stop-Explorer {
    Write-Host "Stopping explorer.exe..." -ForegroundColor Yellow
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
}
function Start-Explorer {
    Write-Host "Restarting explorer.exe..." -ForegroundColor Green
    Start-Process explorer.exe
}
function Stop-EventLog {
    Write-Host "Stopping Windows Event Log service..." -ForegroundColor Yellow
    Stop-Service -Name eventlog -Force
    Start-Sleep -Seconds 2
}
function Start-EventLog {
    Write-Host "Starting Windows Event Log service..." -ForegroundColor Green
    Start-Service -Name eventlog
}
function Clear-RegistryKey {
    param ($path)
    try {
        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        Write-Host "Cleared $path" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Couldn't clear $path - $_" -ForegroundColor Red
    }
}
function Clear-Prefetch {
    Write-Host "Clearing Prefetch..." -ForegroundColor Yellow
    Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue
}
function Clear-Temp {
    Write-Host "Clearing Temp files..." -ForegroundColor Yellow
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
}
function Clear-PSHistory {
    Write-Host "Clearing PSReadLine history..." -ForegroundColor Yellow
    Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
}
function Clear-RecentFiles {
    Write-Host "Clearing Recent Files..." -ForegroundColor Yellow
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue
}
function Clear-EventLogs {
    Write-Host "Clearing Event Logs..." -ForegroundColor Yellow
    wevtutil el | ForEach-Object { 
        try {
            wevtutil cl $_
            Write-Host "Cleared event log: $_" -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear event log: $_ - $_" -ForegroundColor Red
        }
    }
}
function Clear-USNJournal {
    Write-Host "Deleting USN Journal on C:..." -ForegroundColor Yellow
    try {
        fsutil usn deletejournal /d c:
        Write-Host "Deleted USN Journal on C:" -ForegroundColor Green
    } catch {
        Write-Host "Failed to delete USN Journal: $_" -ForegroundColor Red
    }
}
function Main {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
        Write-Warning "Please run this script as Administrator!"
        exit
    }
    Stop-Explorer
    Stop-EventLog
    Write-Host "`n--- Clearing Artifacts ---`n" -ForegroundColor Cyan
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AppSwitch"
    Clear-RegistryKey "HKCU:\Software\Microsoft\Windows\Shell\MUICache"
    Clear-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    Clear-Prefetch
    Clear-EventLogs
    Clear-RecentFiles
    Clear-PSHistory
    Clear-Temp
    Clear-USNJournal

    try {
        Remove-Item "$env:windir\System32\sru\*" -Force -ErrorAction SilentlyContinue
        Write-Host "Cleared SRUM" -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear SRUM: $_" -ForegroundColor Red
    }

    try {
        Remove-Item "$env:LOCALAPPDATA\NVIDIA\NvAppTimestamps\*" -Force -ErrorAction SilentlyContinue
        Write-Host "Cleared NvAppTimestamps" -ForegroundColor Green
    } catch {
        Write-Host "Failed to clear NvAppTimestamps: $_" -ForegroundColor Red
    }

    Start-EventLog
    Start-Explorer

    Write-Host "`n All selected traces cleared." -ForegroundColor Green
    Read-Host "`n[Press ENTER to exit]"
}

