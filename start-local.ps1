param(
    [string]$FrontendPath = "C:\\Users\\Admin\\Downloads\\Telegram Desktop\\proffzoom\\proffzoom\\proFFZoom",
    [switch]$SkipAndroid
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Starting backend services..."
Push-Location $repoRoot
docker compose up -d --build
docker compose up -d migrator
Pop-Location

if (-not $SkipAndroid) {
    if (-not (Test-Path $FrontendPath)) {
        Write-Host "Frontend path not found: $FrontendPath"
        Write-Host "Run with -FrontendPath <path> or -SkipAndroid."
        exit 1
    }

    $gradlew = Join-Path $FrontendPath "gradlew.bat"
    if (-not (Test-Path $gradlew)) {
        Write-Host "gradlew.bat not found in: $FrontendPath"
        Write-Host "Open the project in Android Studio and run the app manually."
        exit 1
    }

    Write-Host "Launching Android build/install..."
    Start-Process -FilePath $gradlew -ArgumentList ":composeApp:installDebug" -WorkingDirectory $FrontendPath
}

Write-Host ""
Write-Host "Backend health: http://localhost:8080/health"
Write-Host "OTP bot health: http://localhost:8081/health"
Write-Host "Android emulator API base URL: http://10.0.2.2:8080"
Write-Host ""
Write-Host "Note: the mobile app currently uses legacy /api/v1 + phone auth stubs."
Write-Host "For full integration, update the app to the Telegram-based auth flow."
