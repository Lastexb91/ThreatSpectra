$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$distDir = Join-Path $root "dist"
$zipPath = Join-Path $distDir "threatspectra-extension.zip"

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

$itemsToPack = @(
    "manifest.json",
    "background.js",
    "content.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "assets\shield.jpg"
) | ForEach-Object { Join-Path $root $_ }

Compress-Archive -Path $itemsToPack -DestinationPath $zipPath -Force
Write-Host "Extension package created: $zipPath"
