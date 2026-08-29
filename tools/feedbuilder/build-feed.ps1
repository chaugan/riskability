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
    # No ValidateSet here on purpose. It is checked in the body instead, because
    # validation on a positional parameter runs before any of this script does,
    # and a reader who copies the shell spelling of an option gets told their
    # file name is not a valid profile rather than being told the real problem.
    [Parameter(Position = 0)]
    [string]$FeedProfile = 'Windows',
    [switch]$WithCveList,
    [string]$OutDir = '.',
    [string]$FeedTool = '',
    [string]$NvdApiKey = '',
    [ValidateSet('Auto', 'Mirror', 'Api')]
    [string]$NvdSource = 'Auto',
    # Sources fetched by hand. A build host that cannot reach CISA, FIRST,
    # the CVE Program or endoflife.date can still carry them: download the file
    # on a machine that can, and name it here. Feed administration tells you to
    # do this whenever its connectivity check finds a source unreachable.
    [string]$KevFile = '',
    [string]$EpssFile = '',
    [string]$CveListFile = '',
    [string]$LifecycleFile = '',
    # Anything else the caller typed, so the shell spellings can be accepted
    # rather than refused. Feed administration and the Linux wrapper both use
    # --kev-file, and somebody moving between them should not have to notice
    # that PowerShell spells its parameters differently.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Extra
)

$ErrorActionPreference = 'Stop'

# Drop empties first. @($null) is an array holding one null, not an empty one,
# so combining a missing $Extra with anything used to leave a null token that
# then reported itself as an unrecognised argument with no name.
$Extra = @($Extra | Where-Object { $_ })

# PowerShell binds the first option it sees to the positional parameter, so a
# caller who leads with a flag lands it in $FeedProfile. Put it back.
if ($FeedProfile -like '-*') {
    $Extra = @($FeedProfile) + $Extra
    $FeedProfile = 'Windows'
}

# Translate the shell spellings into the parameters above. Two forms are
# accepted for each, "--kev-file path" and "--kev-file=path", because both are
# ordinary things to type.
$rest = @()
for ($i = 0; $i -lt $Extra.Count; $i++) {
    $arg = $Extra[$i]
    $val = $null
    if ($arg -match '^(--[a-z-]+)=(.*)$') {
        $arg = $Matches[1]
        $val = $Matches[2]
    }
    switch ($arg) {
        '--kev-file'       { if ($null -eq $val) { $i++; $val = $Extra[$i] }; $KevFile = $val }
        '--epss-file'      { if ($null -eq $val) { $i++; $val = $Extra[$i] }; $EpssFile = $val }
        '--cve-list-file'  { if ($null -eq $val) { $i++; $val = $Extra[$i] }; $CveListFile = $val }
        '--lifecycle-file' { if ($null -eq $val) { $i++; $val = $Extra[$i] }; $LifecycleFile = $val }
        '--with-cve-list'  { $WithCveList = $true }
        default            { $rest += $Extra[$i] }
    }
}
if ($rest.Count -gt 0) {
    throw ("unrecognised argument: {0}. Run Get-Help .\build-feed.ps1 -Detailed for the options." -f ($rest -join ' '))
}

foreach ($n in @($KevFile, $EpssFile, $CveListFile, $LifecycleFile)) {
    if ($n -and -not (Test-Path -LiteralPath $n)) {
        throw ("no such file: {0}" -f $n)
    }
}

$validProfiles = @('Linux', 'Windows', 'Everything')
if ($validProfiles -notcontains $FeedProfile) {
    throw ("{0} is not a feed profile. Choose one of {1}, or leave it out for Windows." -f
           $FeedProfile, ($validProfiles -join ', '))
}

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

# A hand downloaded source is resolved to a full path before it is handed over,
# so a relative path still works after the builder changes directory. Written as
# four plain calls rather than a loop over pairs, because a nested array is one
# of the things PowerShell is happy to flatten when you least want it to.
function Add-SourceFile {
    param([string]$Flag, [string]$Path)
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw ("{0}: no such file: {1}" -f $Flag, $Path)
    }
    $script:buildArgs += $Flag
    $script:buildArgs += (Resolve-Path -LiteralPath $Path).Path
}
Add-SourceFile '--kev-file'       $KevFile
Add-SourceFile '--epss-file'      $EpssFile
Add-SourceFile '--cve-list-file'  $CveListFile
Add-SourceFile '--lifecycle-file' $LifecycleFile

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
