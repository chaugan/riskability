<#
.SYNOPSIS
    Riskability -- build an offline vulnerability feed bundle (Windows).

.DESCRIPTION
    Run this on a machine WITH internet access, then carry the resulting file
    to your Splunk search head and import it on the Riskability
    "Feed administration" page.

    Windows software is not installed by a package manager, so it carries no
    PURL. NVD's CPE data is the only source that can assess it, which is why
    -Windows is the default here and optional on the Linux script.

.PARAMETER Profile
    Linux      distributions and language ecosystems only
    Windows    adds NVD CPE data (default)
    Everything every distribution, every ecosystem, all NVD years

.EXAMPLE
    .\build-feed.ps1
    .\build-feed.ps1 -Profile Everything -OutDir D:\feeds

.NOTES
    Requires Python 3.8+. Everything else ships in the same archive as this
    script -- keep the files together after unzipping.
#>
[CmdletBinding()]
param(
    [ValidateSet('Linux', 'Windows', 'Everything')]
    [string]$Profile = 'Windows',
    [string]$OutDir = '.',
    [string]$FeedTool = ''
)

$ErrorActionPreference = 'Stop'

function Find-FeedTool {
    param([string]$Explicit)
    # The builder ships beside this script as a Python zipapp, so the download
    # works on its own. An earlier version looked for a separately-installed
    # "riskability-feed" that nobody downloading from Splunkbase could obtain.
    if ($Explicit -and (Test-Path $Explicit)) { return (Resolve-Path $Explicit).Path }
    $here = Split-Path -Parent $PSCommandPath
    $pyz = Join-Path $here 'riskability-feed.pyz'
    if (Test-Path $pyz) { return (Resolve-Path $pyz).Path }
    throw ("riskability-feed.pyz not found next to this script. Download " +
           "riskability-feedbuilder.zip from the Riskability app's Feed " +
           "administration page and unpack it, keeping the files together.")
}

function Find-Python {
    foreach ($name in @('python3', 'python', 'py')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            # 'py' needs -3 to select Python 3.
            if ($name -eq 'py') { return @($cmd.Source, '-3') }
            return @($cmd.Source)
        }
    }
    throw "Python 3 was not found on PATH. Install it from python.org or the Microsoft Store."
}

$tool = Find-FeedTool -Explicit $FeedTool
$python = Find-Python
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
$out = Join-Path $OutDir "riskability-feed-$stamp.tar.gz"

# Trim these lists to what your fleet actually runs: every entry is a download,
# and a feed you do not need is only bulk to carry across the air gap.
$args = @(
    'build', '--out', $out, '--version', $stamp,
    '--ecosystem', 'Ubuntu',
    '--ecosystem', 'Debian',
    '--ecosystem', 'Alpine',
    '--ecosystem', 'npm',
    '--ecosystem', 'PyPI',
    '--ecosystem', 'Go',
    '--ecosystem', 'Maven',
    '--kev', '--epss', '--mitre'
)

switch ($Profile) {
    'Windows' { $args += @('--nvd', '2015-2026') }
    'Everything' {
        $args += @(
            '--ecosystem', 'Red Hat', '--ecosystem', 'Rocky Linux',
            '--ecosystem', 'AlmaLinux', '--ecosystem', 'SUSE',
            '--ecosystem', 'openSUSE', '--ecosystem', 'NuGet',
            '--ecosystem', 'RubyGems', '--ecosystem', 'crates.io',
            '--ecosystem', 'Packagist',
            '--nvd', 'all'
        )
    }
}

Write-Host "Building $out ..." -ForegroundColor Cyan
& $python[0] @($python[1..($python.Length - 1)]) $tool @args
if ($LASTEXITCODE -ne 0) { throw "riskability-feed exited with $LASTEXITCODE" }

Write-Host ""
Write-Host "Done. Copy $out to the search head and import it on the" -ForegroundColor Green
Write-Host "Riskability > Feed administration page." -ForegroundColor Green
