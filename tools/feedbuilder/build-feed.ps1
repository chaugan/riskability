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

.PARAMETER FeedProfile
    Linux      distributions and language ecosystems only
    Windows    adds NVD CPE data (default)
    Everything every distribution, every ecosystem, all NVD years

.PARAMETER NvdSource
    Where NVD data comes from.
    Auto    (default) a daily regeneration of the bulk feeds NIST retired,
            topped up from the NIST API with whatever changed since that
            regeneration ran. About a minute, and no API key needed.
    Mirror  the regenerated feeds only, skipping the top-up.
    Api     NIST directly and nothing else. Authoritative, but the API serves
            2000 CVEs a request and takes about 20 seconds over each one, so
            expect an hour or more.

.PARAMETER NvdApiKey
    A free NVD API key, which softens the rate limiting on -NvdSource Api. The
    default source does not need one. Request it at
    https://nvd.nist.gov/developers/request-an-api-key
    The NVD_API_KEY environment variable is used when this is not given.

.EXAMPLE
    .\build-feed.ps1
    .\build-feed.ps1 -FeedProfile Everything -OutDir D:\feeds
    .\build-feed.ps1 -FeedProfile Everything -NvdApiKey 'your-key'

.NOTES
    Requires Python 3.8+. Everything else ships in the same archive as this
    script -- keep the files together after unzipping.
#>
[CmdletBinding()]
param(
    [ValidateSet('Linux', 'Windows', 'Everything')]
    [string]$FeedProfile = 'Windows',
    [switch]$WithCveList,
    [string]$OutDir = '.',
    [string]$FeedTool = '',
    [string]$NvdApiKey = '',
    [ValidateSet('Auto', 'Mirror', 'Api')]
    [string]$NvdSource = 'Auto'
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
    # Returns an object rather than an array on purpose. PowerShell unrolls a
    # single-element array on return, so "return @($cmd.Source)" hands back a
    # STRING; indexing it then yields one character. An object cannot unroll.
    foreach ($name in @('python3', 'python', 'py')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            # The py launcher needs -3 to select Python 3.
            $pre = if ($name -eq 'py') { @('-3') } else { @() }
            return [pscustomobject]@{ Exe = $cmd.Source; Pre = $pre }
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
$buildArgs = @(
    'build', '--out', $out, '--version', $stamp,
    '--ecosystem', 'Ubuntu',
    '--ecosystem', 'Debian',
    '--ecosystem', 'Alpine',
    '--ecosystem', 'npm',
    '--ecosystem', 'PyPI',
    '--ecosystem', 'Go',
    '--ecosystem', 'Maven',
    '--kev', '--epss', '--mitre',
    # Support lifecycles. Small, and the only source that answers "is anyone
    # still fixing this at all", which no advisory ever states.
    '--lifecycle'
)

switch ($FeedProfile) {
    'Windows' { $buildArgs += @('--nvd', '2015-2026') }
    'Everything' {
        $buildArgs += @(
            '--ecosystem', 'Red Hat', '--ecosystem', 'Rocky Linux',
            '--ecosystem', 'AlmaLinux', '--ecosystem', 'SUSE',
            '--ecosystem', 'openSUSE', '--ecosystem', 'NuGet',
            '--ecosystem', 'RubyGems', '--ecosystem', 'crates.io',
            '--ecosystem', 'Packagist',
            '--nvd', 'all',
            # The CVE Program catalogue, which is what gives the CVE
            # encyclopaedia a description and a product name. Only in this
            # profile: about 600 MB to fetch and roughly 120 MB in the bundle,
            # which is a real decision on an air gap, not a default.
            '--cve-list'
        )
    }
}

# Any profile plus the encyclopaedia's source, so a Linux or Windows build can
# have it without taking every ecosystem as well.
if ($WithCveList) { $buildArgs += @('--cve-list') }
$buildArgs += @('--nvd-source', $NvdSource.ToLower())

# The builder reads NVD_API_KEY from the environment. Accepting it as a
# parameter as well is friendlier on Windows, where setting an environment
# variable for one command is awkward.
if ($NvdApiKey) { $env:NVD_API_KEY = $NvdApiKey }
# The default source needs no key, so only warn where the rate limit bites.
if (-not $env:NVD_API_KEY -and $NvdSource -eq 'Api') {
    Write-Warning ("-NvdSource Api with no NVD_API_KEY is rate limited to 5 " +
        "requests per 30 seconds. This will take well over an hour. A free " +
        "key from https://nvd.nist.gov/developers/request-an-api-key helps, " +
        "though the API is slow regardless.")
}

Write-Host "Building $out ..." -ForegroundColor Cyan
& $python.Exe @($python.Pre) $tool @buildArgs
if ($LASTEXITCODE -ne 0) { throw "riskability-feed exited with $LASTEXITCODE" }

Write-Host ""
Write-Host "Done. Copy $out to the search head and import it on the" -ForegroundColor Green
Write-Host "Riskability > Feed administration page." -ForegroundColor Green
