# Builds answer.iso containing only Autounattend.xml
$iso = "answer.iso"
$xml = "Autounattend.xml"

if (-Not (Test-Path $xml)) {
    Write-Error "Missing $xml"
    exit 1
}

# Create a temporary folder
$temp = "$PSScriptRoot\temp-ans"
New-Item -ItemType Directory -Force -Path $temp | Out-Null
Copy-Item $xml -Destination "$temp\Autounattend.xml"

$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

& $oscdimg -u2 -udfver102 -lANS -m $temp answer.iso
Write-Host "✅ Created answer.iso"

# Optional: Clean up
Remove-Item -Recurse -Force $temp
