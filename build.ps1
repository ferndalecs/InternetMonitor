<#
.SYNOPSIS
    Builds dist\InternetMonitor.exe.

.DESCRIPTION
    Uses the C# compiler that is built in to Windows (.NET Framework 4.x), so nothing
    needs to be installed: no Visual Studio, no SDK, no internet access.

.PARAMETER SignThumbprint
    Optional. Thumbprint of a code-signing certificate in your personal certificate
    store. When given, the EXE is signed (needs signtool.exe from the Windows SDK).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build.ps1
#>
param(
    [string]$SignThumbprint = ''
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src = Join-Path $root 'src'
$dist = Join-Path $root 'dist'

$csc = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) { throw '.NET Framework 4.x compiler (csc.exe) was not found.' }

$icon = Join-Path $src 'app.ico'
if (-not (Test-Path $icon)) { & (Join-Path $root 'tools\make-icon.ps1') -OutFile $icon }

New-Item -ItemType Directory -Force $dist | Out-Null
$exe = Join-Path $dist 'InternetMonitor.exe'

$cscArgs = @(
    '/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', '/warn:4', '/utf8output',
    "/out:$exe",
    "/win32icon:$icon",
    "/win32manifest:$(Join-Path $src 'app.manifest')",
    "/resource:$(Join-Path $src 'ReportTemplate.html'),ReportTemplate.html",
    "/resource:$icon,app.ico",
    '/r:System.dll', '/r:System.Core.dll', '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll', '/r:System.Web.Extensions.dll'
) + (Get-ChildItem (Join-Path $src '*.cs') | ForEach-Object { $_.FullName })

& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw "Build failed (csc exit code $LASTEXITCODE)." }

$sample = Join-Path $root 'InternetMonitor.sample.ini'
if (Test-Path $sample) { Copy-Item $sample $dist -Force }

if ($SignThumbprint) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK signing tools.' }
    & $signtool.FullName sign /sha1 $SignThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $exe
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
}

$info = Get-Item $exe
Write-Host ("Built {0} ({1:N0} KB)" -f $info.FullName, ($info.Length / 1KB))
