#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Scans the Azure Misconfiguration Lab against Microsoft Defender for Cloud
    (free foundational CSPM) and reports Secure Score + unhealthy findings,
    each mapped to a CIS Microsoft Azure Foundations Benchmark control.

.DESCRIPTION
    Pulls two things from the Microsoft.Security REST API via Invoke-AzRestMethod
    (which ships with Az.Accounts - no Az.Security module required):
      1. The subscription Secure Score (percentage + raw points).
      2. Every security assessment, filtered to the lab resource group, with any
         Unhealthy finding flagged and mapped to its CIS control.
    Writes a timestamped CSV evidence file to ..\evidence\ so pre/post-remediation
    runs can be compared side by side.

.PARAMETER SubscriptionId
    Target subscription. Defaults to the current Az context.

.PARAMETER ResourceGroup
    Lab resource group to scope findings to. Default: RG-MisconfigLab.

.PARAMETER Label
    Evidence label so files don't overwrite. Default: before.
    Use 'after' once remediation has run.

.EXAMPLE
    .\scan-azure-misconfig.ps1 -SubscriptionId <sub> -Label before

.NOTES
    Findings depend on Defender for Cloud having finished its first assessment
    pass (~15-30 min after the resources are created / the Security RP is
    registered). An empty result usually means the crawl hasn't completed yet.
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup = 'RG-MisconfigLab',
    [ValidateSet('before','after')]
    [string]$Label = 'before'
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','HIGH','ERROR')][string]$Level = 'INFO')
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'HIGH'  { 'Red' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# --- Map a Defender assessment to a CIS control by matching its display name ---
function Get-CisControl {
    param([string]$Name)
    switch -regex ($Name) {
        'secure transfer|https'                 { return 'CIS 3.1  - Secure transfer (HTTPS) required' }
        'public (access|network|blob)|anonymous' { return 'CIS 3.7  - Public blob/network access disabled' }
        'tls'                                    { return 'CIS 3.x  - Minimum TLS 1.2' }
        'RDP|3389|management ports|remote'       { return 'CIS 6.x  - RDP/mgmt ports not open to internet' }
        'SSH|22'                                 { return 'CIS 6.x  - SSH not open to internet' }
        'network security group|NSG'             { return 'CIS 6.x  - NSG restricts inbound' }
        default                                  { return 'CIS (unmapped)' }
    }
}

# --- Connect / set subscription context ---
$ctx = Get-AzContext
if (-not $ctx) { Write-Log 'No Az context - run Connect-AzAccount first.' 'ERROR'; return }
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}
$sub = (Get-AzContext).Subscription.Id
Write-Log "Subscription: $sub" 'OK'
Write-Log "Scope: resource group '$ResourceGroup'  |  label: $Label" 'INFO'

# ============================================================
# 1. SECURE SCORE
# ============================================================
$scoreUri = "/subscriptions/$sub/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
try {
    $scoreResp = Invoke-AzRestMethod -Method GET -Path $scoreUri
    if ($scoreResp.StatusCode -eq 200) {
        $score = ($scoreResp.Content | ConvertFrom-Json).properties.score
        $pct = [math]::Round($score.percentage * 100, 1)
        Write-Log "SECURE SCORE: $pct%  ($($score.current) / $($score.max) points)" 'HIGH'
    } else {
        Write-Log "Secure Score not ready yet (HTTP $($scoreResp.StatusCode)). Defender may still be crawling." 'WARN'
        $pct = $null
    }
} catch {
    Write-Log "Secure Score call failed: $($_.Exception.Message)" 'WARN'
    $pct = $null
}

# ============================================================
# 2. SECURITY ASSESSMENTS (filtered to the lab RG)
# ============================================================
$assessUri = "/subscriptions/$sub/providers/Microsoft.Security/assessments?api-version=2021-06-01"
$findings = @()
try {
    $resp = Invoke-AzRestMethod -Method GET -Path $assessUri
    if ($resp.StatusCode -ne 200) {
        Write-Log "Assessments not ready yet (HTTP $($resp.StatusCode)). Give Defender ~15-30 min after deploy, then re-run." 'WARN'
    } else {
        $all = ($resp.Content | ConvertFrom-Json).value
        $rgFilter = "/resourceGroups/$ResourceGroup/"
        foreach ($a in $all) {
            $resId = $a.properties.resourceDetails.Id
            if (-not $resId) { $resId = $a.id }
            if ($resId -inotmatch [regex]::Escape($rgFilter)) { continue }

            $statusCode = $a.properties.status.code          # Healthy / Unhealthy / NotApplicable
            $display    = $a.properties.displayName
            $resName    = ($resId -split '/')[-1]

            $findings += [pscustomobject]@{
                Resource   = $resName
                Finding    = $display
                Status     = $statusCode
                Severity   = $a.properties.metadata.severity
                CIS        = (Get-CisControl -Name $display)
                ResourceId = $resId
            }
        }
    }
} catch {
    Write-Log "Assessment call failed: $($_.Exception.Message)" 'WARN'
}

# ============================================================
# 3. REPORT
# ============================================================
$unhealthy = @($findings | Where-Object { $_.Status -eq 'Unhealthy' })

if ($findings.Count -eq 0) {
    Write-Log "No assessments returned for '$ResourceGroup' yet. If you just deployed, wait for the crawl and re-run." 'WARN'
} else {
    Write-Log "Found $($findings.Count) assessment(s) on the lab RG - $($unhealthy.Count) UNHEALTHY:" 'INFO'
    $unhealthy |
        Sort-Object Severity, Resource |
        Format-Table Resource, Severity, Finding, CIS -AutoSize -Wrap |
        Out-String | Write-Host
}

# ============================================================
# 4. EVIDENCE CSV
# ============================================================
$evidenceDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'evidence'
if (-not (Test-Path $evidenceDir)) { New-Item -ItemType Directory -Path $evidenceDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $evidenceDir "misconfig-scan-$Label-$stamp.csv"

$findings | Sort-Object Status, Resource | Export-Csv -Path $csvPath -NoTypeInformation
Write-Log "Evidence written: $csvPath" 'OK'
if ($pct -ne $null) { Write-Log "Snapshot Secure Score for this run: $pct%" 'OK' }
Write-Log "Next: run remediate-misconfig.ps1, then re-scan with -Label after to prove the score climbed." 'INFO'
