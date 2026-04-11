param(
    [string]$TargetApp = "MEGAsync"
) # <-- enter display name of target app

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "[*] Starting forced removal for: $TargetApp" -ForegroundColor Cyan

$results = @()

# Get all user profiles
$profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($profile in $profiles) {
    $user = $profile.Name
    $userPath = $profile.FullName

    Write-Host "`n[+] Processing user: $user" -ForegroundColor Yellow

    # -------- FILE SYSTEM --------
    $paths = @(
        "$userPath\AppData\Local\$TargetApp",
        "$userPath\AppData\Roaming\$TargetApp"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-Host "[!] Found directory: $path" -ForegroundColor Red

            # Kill any locking process first
            Get-Process | Where-Object {
                $_.Path -and $_.Path -like "*$TargetApp*"
            } | ForEach-Object {
                Stop-Process -Id $_.Id -Force
            }

            Remove-Item $path -Recurse -Force

            $results += [PSCustomObject]@{
                User = $user
                Type = "File"
                Path = $path
                Action = "Removed"
            }
        }
    }

    # -------- STARTUP FOLDER --------
    $startup = "$userPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startup) {
        Get-ChildItem $startup | Where-Object {
            $_.Name -match $TargetApp
        } | ForEach-Object {

            Remove-Item $_.FullName -Force

            $results += [PSCustomObject]@{
                User = $user
                Type = "Startup"
                Path = $_.FullName
                Action = "Removed"
            }
        }
    }

    # -------- REGISTRY (HKU) --------
    $sid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
        Where-Object { $_.ProfileImagePath -eq $userPath }).PSChildName

    if ($sid) {
        $runKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"

        if (Test-Path $runKey) {
            $props = Get-ItemProperty $runKey

            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Value -match $TargetApp) {

                    Remove-ItemProperty -Path $runKey -Name $prop.Name

                    $results += [PSCustomObject]@{
                        User = $user
                        Type = "Registry"
                        Path = $prop.Value
                        Action = "Removed"
                    }
                }
            }
        }
    }
}

# -------- RUNNING PROCESSES --------
Get-Process | Where-Object {
    $_.Path -and $_.Path -match $TargetApp
} | ForEach-Object {

    Stop-Process -Id $_.Id -Force

    $results += [PSCustomObject]@{
        User = $_.UserName
        Type = "Process"
        Path = $_.Path
        Action = "Terminated"
    }
}

# -------- SCHEDULED TASKS --------
Get-ScheduledTask | ForEach-Object {
    $task = $_
    foreach ($action in $task.Actions) {
        if ($action.Execute -match $TargetApp) {

            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false

            $results += [PSCustomObject]@{
                User = "N/A"
                Type = "ScheduledTask"
                Path = $action.Execute
                Action = "Removed"
            }
        }
    }
}

# -------- OUTPUT LOG --------
$logPath = "C:\ProgramData\${TargetApp}_removal_log.csv"
$results | Export-Csv $logPath -NoTypeInformation

Write-Host "`n[*] Removal complete. Log saved to $logPath" -ForegroundColor Cyan
