#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Storage, Az.Network

<#
.SYNOPSIS
    Remediates the Azure Misconfiguration Lab - flips every intentionally-insecure
    setting back to a CIS-aligned secure baseline.

.DESCRIPTION
    Undoes what deploy-misconfig-lab.ps1 planted:
      STORAGE -> HTTPS-only ON, min TLS 1.2, public blob OFF, public network DISABLED
      NSG     -> removes the internet-facing RDP (3389) allow rule
    Supports -WhatIf so you can preview every change before it touches anything.
    Ends with a verification pass that re-reads both resources and prints the
    post-remediation state, so you can confirm the fix without opening the portal.

.PARAMETER SubscriptionId
    Target subscription. Defaults to the current Az context.
.PARAMETER ResourceGroup
    Lab resource group. Default: RG-MisconfigLab.
.PARAMETER StorageAccountName
    Storage account to harden. Auto-discovers the stmisconfig* account if omitted.
.PARAMETER NsgName
    NSG to clean up. Default: nsg-misconfig.
.PARAMETER RdpRuleName
    Name of the open RDP rule to remove. Default: Allow-RDP-FromInternet.

.EXAMPLE
    .\remediate-misconfig.ps1 -SubscriptionId <sub> -WhatIf   # preview
    .\remediate-misconfig.ps1 -SubscriptionId <sub>           # apply

.NOTES
    Capture the baseline first, remediate, then re-check config to prove the fix.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup = 'RG-MisconfigLab',
    [string]$StorageAccountName,
    [string]$NsgName = 'nsg-misconfig',
    [string]$RdpRuleName = 'Allow-RDP-FromInternet'
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERROR')][string]$Level = 'INFO')
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# --- Context ---
$ctx = Get-AzContext
if (-not $ctx) { Write-Log 'No Az context - run Connect-AzAccount first.' 'ERROR'; return }
if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }
$sub = (Get-AzContext).Subscription.Id
Write-Log "Subscription: $sub" 'OK'

# --- Discover storage account if not supplied ---
if (-not $StorageAccountName) {
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroup |
          Where-Object { $_.StorageAccountName -like 'stmisconfig*' } |
          Select-Object -First 1
    if (-not $sa) { Write-Log "No stmisconfig* account found in $ResourceGroup" 'ERROR'; return }
    $StorageAccountName = $sa.StorageAccountName
}
Write-Log "Target storage: $StorageAccountName   |   NSG: $NsgName" 'INFO'

# ============================================================
# 1. HARDEN STORAGE
# ============================================================
if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Harden: HTTPS-only ON, TLS1.2, public blob OFF, public network DISABLED')) {
    Set-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName `
        -EnableHttpsTrafficOnly $true `
        -MinimumTlsVersion TLS1_2 `
        -AllowBlobPublicAccess $false `
        -PublicNetworkAccess Disabled | Out-Null
    Write-Log "Storage hardened." 'OK'
}

# ============================================================
# 2. CLOSE RDP TO THE INTERNET
# ============================================================
$nsg  = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -Name $NsgName
$rule = $nsg.SecurityRules | Where-Object { $_.Name -eq $RdpRuleName }
if ($rule) {
    if ($PSCmdlet.ShouldProcess($NsgName, "Remove internet-facing RDP rule '$RdpRuleName'")) {
        Remove-AzNetworkSecurityRuleConfig -Name $RdpRuleName -NetworkSecurityGroup $nsg | Out-Null
        $nsg | Set-AzNetworkSecurityGroup | Out-Null
        Write-Log "Removed open RDP rule '$RdpRuleName'." 'OK'
    }
} else {
    Write-Log "Rule '$RdpRuleName' not found on $NsgName (already clean)." 'WARN'
}

# ============================================================
# 3. VERIFY
# ============================================================
if (-not $WhatIfPreference) {
    Write-Log "Verification pass:" 'INFO'
    $saNow  = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName
    $nsgNow = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -Name $NsgName
    $rdpNow = $nsgNow.SecurityRules | Where-Object { $_.Name -eq $RdpRuleName }

    [pscustomobject]@{
        'HTTPS-only'          = $saNow.EnableHttpsTrafficOnly
        'Min TLS'             = $saNow.MinimumTlsVersion
        'Public blob allowed' = $saNow.AllowBlobPublicAccess
        'Public network'      = $saNow.PublicNetworkAccess
        'Open RDP rule'       = if ($rdpNow) { 'STILL PRESENT' } else { 'removed' }
    } | Format-List | Out-String | Write-Host

    Write-Log "Done. Re-run the config check to prove every setting flipped secure." 'OK'
} else {
    Write-Log "WhatIf preview only - no changes made. Drop -WhatIf to apply." 'WARN'
}
