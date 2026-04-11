param (
    [Parameter(Mandatory = $true)]
    [string]$FileName
)

Write-Host "🔍 Starting search for file: $FileName" -ForegroundColor Cyan
$fileFound = $false
$drives = Get-PSDrive -PSProvider FileSystem

foreach ($drive in $drives) {
    Write-Host "`n📂 Searching in drive: $($drive.Name) ($($drive.Root))..." -ForegroundColor Yellow

    try {
        Get-ChildItem -Path "$($drive.Root)" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$FileName*" } |
        ForEach-Object {
            $fullPath = $_.FullName
            $location = Split-Path -Path $fullPath -Parent
            Write-Host "✅ File found!" -ForegroundColor Green
            Write-Host "   📁 Location: $location"
            Write-Host "   📄 Full Path: $fullPath`n"
            $fileFound = $true
        }
    } catch {
        Write-Warning "⚠️ Could not access $($drive.Root): $_"
    }
}

if (-not $fileFound) {
    Write-Host "`n🔁 No results found in drives. Searching Downloads folder as fallback..." -ForegroundColor Magenta

    $downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"

    try {
        Get-ChildItem -Path $downloadsPath -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$FileName*" } |
        ForEach-Object {
            $fullPath = $_.FullName
            $location = Split-Path -Path $fullPath -Parent
            Write-Host "✅ File found in Downloads!" -ForegroundColor Green
            Write-Host "   📁 Location: $location"
            Write-Host "   📄 Full Path: $fullPath`n"
            $fileFound = $true
        }
    } catch {
        Write-Warning "⚠️ Could not access Downloads folder: $_"
    }
}

if (-not $fileFound) {
    Write-Host "`n❌ File not found on this system." -ForegroundColor Red
}
