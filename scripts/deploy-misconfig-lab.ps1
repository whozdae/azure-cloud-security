#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.Storage, Az.Network

<#
.SYNOPSIS
    Deploy a small set of INTENTIONALLY misconfigured Azure resources so a misconfiguration
    hunt has real findings to catch, score, and remediate. Lab use only.

.DESCRIPTION
    Creates one resource group containing:
      1. A storage account with insecure settings:
         - HTTPS-only OFF  (data can travel in cleartext)   -> CIS 3.1
         - Minimum TLS 1.0 (weak transport)                 -> CIS 3.x
         - Public blob access ALLOWED                        -> CIS 3.7
         - Public network access ENABLED (no firewall)       -> CIS 3.x
      2. A network security group with RDP (3389) open to the internet (Source *)  -> CIS 6.x

    These are the classic cloud misconfigurations Defender for Cloud and a custom scanner
    flag immediately. Everything is Standard_LRS / free-tier-ish, so credit impact is cents.

    Supports -WhatIf and -Remove (tears the whole RG down).

.PARAMETER SubscriptionId  Target subscription (pass your trial sub to avoid the wrong-context 403).
.PARAMETER ResourceGroup   RG to hold the lab. Default RG-MisconfigLab.
.PARAMETER Location        Azure region. Default eastus.
.PARAMETER Remove          Delete the resource group and everything in it.

.EXAMPLE  .\deploy-misconfig-lab.ps1 -SubscriptionId <sub> -WhatIf
.EXAMPLE  .\deploy-misconfig-lab.ps1 -SubscriptionId <sub>
.EXAMPLE  .\deploy-misconfig-lab.ps1 -SubscriptionId <sub> -Remove

.NOTES
    INTENTIONALLY INSECURE. Never deploy outside a lab subscription you own. Remove when done.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup = 'RG-MisconfigLab',
    [string]$Location       = 'eastus',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $c = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; HIGH='Red' }[$Level]; if (-not $c) { $c = 'Gray' }
    Write-Host ("[{0}] {1}" -f $Level, $Msg) -ForegroundColor $c
}

try {
    $ctx = Get-AzContext
    if (-not $ctx) { Connect-AzAccount | Out-Null; $ctx = Get-AzContext }
    if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null; $ctx = Get-AzContext
    }
    Write-Log ("Subscription: {0} ({1})" -f $ctx.Subscription.Name, $ctx.Subscription.Id) 'OK'
}
catch { Write-Log "Azure connect failed: $($_.Exception.Message)" 'HIGH'; throw }

# ----------------------------------------------------------------- REMOVE
if ($Remove) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, 'DELETE resource group and all misconfig resources')) {
        Remove-AzResourceGroup -Name $ResourceGroup -Force | Out-Null
        Write-Log "Removed resource group '$ResourceGroup' (lab torn down)." 'OK'
    }
    return
}

# ----------------------------------------------------------------- CREATE
$rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if (-not $rg) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, "Create resource group in $Location")) {
        New-AzResourceGroup -Name $ResourceGroup -Location $Location | Out-Null
        Write-Log "Created resource group '$ResourceGroup'." 'OK'
    }
}

# --- Misconfig 1: insecure storage account ---
$stName = "stmisconfig$(Get-Random -Minimum 10000 -Maximum 99999)"
if ($PSCmdlet.ShouldProcess($stName, 'CREATE storage account with INSECURE settings (HTTP, TLS1.0, public blob, public network)')) {
    New-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $stName -Location $Location `
        -SkuName Standard_LRS -Kind StorageV2 `
        -EnableHttpsTrafficOnly $false `
        -MinimumTlsVersion TLS1_0 `
        -AllowBlobPublicAccess $true `
        -PublicNetworkAccess Enabled | Out-Null
    Write-Log "Created INSECURE storage account '$stName' (HTTPS off, TLS1.0, public blob, public network)." 'WARN'
}

# --- Misconfig 2: NSG with RDP open to the internet ---
if ($PSCmdlet.ShouldProcess('nsg-misconfig', 'CREATE NSG allowing RDP 3389 from the internet (Source *)')) {
    $rdpRule = New-AzNetworkSecurityRuleConfig -Name 'Allow-RDP-FromInternet' `
        -Description 'INTENTIONAL MISCONFIG: RDP open to the world' `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 `
        -SourceAddressPrefix '*' -SourcePortRange '*' `
        -DestinationAddressPrefix '*' -DestinationPortRange 3389
    New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -Name 'nsg-misconfig' `
        -Location $Location -SecurityRules $rdpRule | Out-Null
    Write-Log "Created NSG 'nsg-misconfig' with RDP 3389 open to 0.0.0.0/0." 'WARN'
}

# ----------------------------------------------------------------- SUMMARY
if (-not $WhatIfPreference) {
    Write-Log ''
    Write-Log '=== MISCONFIG LAB DEPLOYED (intentionally insecure) ===' 'WARN'
    Write-Log "Resource group : $ResourceGroup"
    Write-Log "Storage account: $stName  (HTTPS-only off, TLS1.0, public blob, public network)"
    Write-Log "NSG            : nsg-misconfig  (inbound RDP 3389 from *)"
    Write-Log ''
    Write-Log 'NEXT: run scan-azure-misconfig.ps1 to detect + score these against CIS.' 'OK'
    Write-Log 'Also: enable Microsoft Defender for Cloud (free CSPM) and check Secure Score in ~15-30 min.' 'INFO'
    Write-Log "Tear down when done:  .\deploy-misconfig-lab.ps1 -SubscriptionId $($ctx.Subscription.Id) -Remove" 'INFO'
}
