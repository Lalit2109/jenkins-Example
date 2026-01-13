#Requires -Modules Az.Accounts, Az.Storage, Az.Monitor

<#
.SYNOPSIS
    Analyzes Azure storage accounts (RAGRS/GRS/ZRS/LRS) to identify cost optimization opportunities.

.DESCRIPTION
    This script analyzes all storage accounts with RAGRS, GRS, ZRS, and LRS redundancy across Azure subscriptions to:
    - Check if secondary read endpoint is being used (for RAGRS accounts)
    - Identify environment type (Prod/Non-Prod) based on account name and subscription name
    - Calculate data sizes and potential cost savings
    - Recommend conversions: Non-Prod accounts to LRS, Prod accounts (without secondary read) to GRS
    - Generate CSV and HTML reports for business presentation

.PARAMETER ConfigPath
    Path to the storage-pricing.json configuration file. Default: ./storage-pricing.json

.PARAMETER OutputPath
    Path to output directory. Default: ./output

.PARAMETER AnalysisPeriodDays
    Number of days to analyze for secondary read usage. Overrides config file value.

.EXAMPLE
    .\analyze-ragrs-storage.ps1

.EXAMPLE
    .\analyze-ragrs-storage.ps1 -AnalysisPeriodDays 60 -OutputPath "C:\Reports"
#>

param(
    [string]$ConfigPath = "./storage-pricing.json",
    [string]$OutputPath = "",
    [int]$AnalysisPeriodDays = 0
)

$ErrorActionPreference = "Continue"
$script:ErrorLog = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    if ($Level -eq "ERROR") {
        $script:ErrorLog += $logMessage
    }
}

function Get-Config {
    param([string]$ConfigFilePath)
    
    if (-not (Test-Path $ConfigFilePath)) {
        Write-Log "Configuration file not found: $ConfigFilePath" "ERROR"
        throw "Configuration file not found"
    }
    
    try {
        $config = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json
        Write-Log "Configuration loaded successfully"
        return $config
    }
    catch {
        Write-Log "Failed to parse configuration file: $_" "ERROR"
        throw
    }
}

function Get-RedundancyTypeFromSku {
    param([string]$SkuName)
    
    if ($SkuName -like "*RAGRS*") { return "RAGRS" }
    if ($SkuName -like "*GRS*" -and $SkuName -notlike "*RA*") { return "GRS" }
    if ($SkuName -like "*ZRS*") { return "ZRS" }
    if ($SkuName -like "*LRS*") { return "LRS" }
    
    return $SkuName
}

function Get-PricingForRegion {
    param(
        [object]$Config,
        [string]$Region,
        [string]$RedundancyType,
        [string]$StorageType = "Blob"
    )
    
    $regionLower = $Region.ToLower().Replace(" ", "")
    
    # Normalize region name (e.g., "UK South" -> "uksouth")
    $regionMappings = @{
        "uksouth" = "uksouth"
        "uk south" = "uksouth"
        "uk-south" = "uksouth"
        "ukwest" = "ukwest"
        "uk west" = "ukwest"
        "uk-west" = "ukwest"
    }
    
    if ($regionMappings.ContainsKey($regionLower)) {
        $regionLower = $regionMappings[$regionLower]
    }
    
    # Check if new structure exists (with storage types)
    if ($Config.pricing.regions.PSObject.Properties.Name -contains $regionLower) {
        $regionPricing = $Config.pricing.regions.$regionLower
        
        # Check if it's new structure with storage types
        if ($regionPricing.PSObject.Properties.Name -contains $StorageType) {
            $storagePricing = $regionPricing.$StorageType
            if ($storagePricing.PSObject.Properties.Name -contains $RedundancyType) {
                return $storagePricing.$RedundancyType
            }
        }
        # Fallback to old structure (backward compatibility)
        elseif ($regionPricing.PSObject.Properties.Name -contains $RedundancyType) {
            return $regionPricing.$RedundancyType
        }
    }
    
    # Use default pricing
    if ($Config.pricing.default.PSObject.Properties.Name -contains $StorageType) {
        $defaultStorage = $Config.pricing.default.$StorageType
        if ($defaultStorage.PSObject.Properties.Name -contains $RedundancyType) {
            return $defaultStorage.$RedundancyType
        }
    }
    
    # Final fallback to old default structure
    return $Config.pricing.default.$RedundancyType
}

function Get-EnvironmentType {
    param(
        [string]$StorageAccountName,
        [string]$SubscriptionName,
        [object]$Config
    )
    
    $subscriptionLower = $SubscriptionName.ToLower()
    if ($subscriptionLower -match "production") {
        return "Prod"
    }
    
    $nameLower = $StorageAccountName.ToLower()
    
    foreach ($pattern in $Config.environmentPatterns.nonProd) {
        if ($nameLower -like "*$pattern*") {
            return "Non-Prod"
        }
    }
    
    foreach ($pattern in $Config.environmentPatterns.prod) {
        if ($nameLower -like "*$pattern*") {
            return "Prod"
        }
    }
    
    return "Unknown"
}

function Get-StorageAccountType {
    param(
        [object]$StorageAccount
    )
    
    try {
        $context = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
        
        if (-not $context) {
            return "Blob"
        }
        
        $services = @()
        
        try {
            $blobService = Get-AzStorageServiceProperty -ServiceType Blob -Context $context -ErrorAction SilentlyContinue
            if ($blobService) { $services += "Blob" }
        }
        catch { }
        
        try {
            $fileService = Get-AzStorageServiceProperty -ServiceType File -Context $context -ErrorAction SilentlyContinue
            if ($fileService) { $services += "File" }
        }
        catch { }
        
        try {
            $tableService = Get-AzStorageAccount -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue
            if ($tableService) { $services += "Table" }
        }
        catch { }
        
        if ($services -contains "Blob") { return "Blob" }
        if ($services -contains "File") { return "File" }
        if ($services -contains "Table") { return "Table" }
        
        return "Blob"
    }
    catch {
        return "Blob"
    }
}

function Get-StorageAccountUsage {
    param(
        [string]$ResourceGroupName,
        [string]$StorageAccountName
    )
    
    try {
        $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        
        # Try to get usage from metrics - suppress deprecation warnings
        $ErrorActionPreferenceBackup = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        
        # Try multiple time grains and metric names
        $timeGrains = @("01:00:00", "1:00:00", "00:05:00")
        $metricNames = @("UsedCapacity", "Capacity")
        
        foreach ($metricName in $metricNames) {
            foreach ($timeGrain in $timeGrains) {
                try {
                    $metrics = Get-AzMetric -ResourceId $storageAccount.Id -MetricName $metricName -TimeGrain $timeGrain -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    
                    if ($metrics -and $metrics.Data -and $metrics.Data.Count -gt 0) {
                        $latestMetric = $metrics.Data | Where-Object { $_.Average -ne $null } | Sort-Object Timestamp -Descending | Select-Object -First 1
                        if ($latestMetric -and $latestMetric.Average -and $latestMetric.Average -gt 0) {
                            $ErrorActionPreference = $ErrorActionPreferenceBackup
                            return [math]::Round($latestMetric.Average / 1GB, 2)
                        }
                    }
                }
                catch {
                    # Continue to next attempt
                }
            }
        }
        
        # Fallback: Try to get from storage account properties if available
        try {
            $context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
            if ($context) {
                # Try to get blob service stats
                $blobService = Get-AzStorageServiceProperty -ServiceType Blob -Context $context -ErrorAction SilentlyContinue
                if ($blobService -and $blobService.Metrics -and $blobService.Metrics.Capacity) {
                    $ErrorActionPreference = $ErrorActionPreferenceBackup
                    return [math]::Round($blobService.Metrics.Capacity / 1GB, 2)
                }
            }
        }
        catch {
            # Continue
        }
        
        $ErrorActionPreference = $ErrorActionPreferenceBackup
        Write-Log "Could not retrieve usage metrics for $StorageAccountName, using 0" "WARN"
        return 0
    }
    catch {
        Write-Log "Error getting storage usage for $StorageAccountName : $_" "ERROR"
        return 0
    }
}

function Get-SecondaryReadUsage {
    param(
        [string]$ResourceId,
        [string]$RedundancyType,
        [int]$Days
    )
    
    if ($RedundancyType -notlike "*RAGRS*") {
        return @{
            Count = 0
            Percentage = 0
            IsUsed = $false
        }
    }
    
    try {
        $startTime = (Get-Date).AddDays(-$Days)
        $endTime = Get-Date
        
        $ErrorActionPreferenceBackup = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        
        $allMetrics = Get-AzMetric -ResourceId $ResourceId -MetricName "Transactions" -TimeGrain 01:00:00 -StartTime $startTime -EndTime $endTime -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        
        if (-not $allMetrics -or -not $allMetrics.Data) {
            $ErrorActionPreference = $ErrorActionPreferenceBackup
            return @{
                Count = 0
                Percentage = 0
                IsUsed = $false
            }
        }
        
        $totalSecondaryTransactions = 0
        $totalPrimaryTransactions = 0
        
        foreach ($metric in $allMetrics.Data) {
            if ($metric.Dimensions) {
                $geoType = $metric.Dimensions | Where-Object { $_.Name -eq "GeoType" } | Select-Object -ExpandProperty Value
                if ($geoType -eq "Secondary") {
                    if ($metric.Total) {
                        $totalSecondaryTransactions += $metric.Total
                    }
                }
                elseif ($geoType -eq "Primary") {
                    if ($metric.Total) {
                        $totalPrimaryTransactions += $metric.Total
                    }
                }
            }
        }
        
        $totalTransactions = $totalPrimaryTransactions + $totalSecondaryTransactions
        
        $ErrorActionPreference = $ErrorActionPreferenceBackup
        
        $percentage = 0
        if ($totalTransactions -gt 0) {
            $percentage = [math]::Round(($totalSecondaryTransactions / $totalTransactions) * 100, 2)
        }
        
        $isUsed = $totalSecondaryTransactions -gt 0 -or $percentage -gt 1
        
        return @{
            Count = [math]::Round($totalSecondaryTransactions, 0)
            Percentage = $percentage
            IsUsed = $isUsed
        }
    }
    catch {
        Write-Log "Error getting secondary read usage: $_" "ERROR"
        return @{
            Count = 0
            Percentage = 0
            IsUsed = $false
        }
    }
}

function Calculate-CostSavings {
    param(
        [double]$DataSizeGB,
        [object]$Config,
        [string]$Region,
        [string]$CurrentRedundancy,
        [string]$StorageType = "Blob"
    )
    
    $currentPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType $CurrentRedundancy -StorageType $StorageType
    $lrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "LRS" -StorageType $StorageType
    $zrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "ZRS" -StorageType $StorageType
    $grsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "GRS" -StorageType $StorageType
    $ragrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "RAGRS" -StorageType $StorageType
    
    $currentCost = $DataSizeGB * $currentPrice
    $lrsCost = $DataSizeGB * $lrsPrice
    $zrsCost = $DataSizeGB * $zrsPrice
    $grsCost = $DataSizeGB * $grsPrice
    
    return @{
        CurrentMonthlyCost = [math]::Round($currentCost, 2)
        LRSMonthlyCost = [math]::Round($lrsCost, 2)
        LRSSavings = [math]::Round($currentCost - $lrsCost, 2)
        LRSAnnualSavings = [math]::Round(($currentCost - $lrsCost) * 12, 2)
        ZRSMonthlyCost = [math]::Round($zrsCost, 2)
        ZRSSavings = [math]::Round($currentCost - $zrsCost, 2)
        ZRSAnnualSavings = [math]::Round(($currentCost - $zrsCost) * 12, 2)
        GRSMonthlyCost = [math]::Round($grsCost, 2)
        GRSSavings = [math]::Round($currentCost - $grsCost, 2)
        GRSAnnualSavings = [math]::Round(($currentCost - $grsCost) * 12, 2)
    }
}

function Calculate-RecommendedSavings {
    param(
        [double]$DataSizeGB,
        [object]$Config,
        [string]$Region,
        [string]$CurrentRedundancy,
        [string]$RecommendedAction,
        [string]$StorageType = "Blob"
    )
    
    $currentPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType $CurrentRedundancy -StorageType $StorageType
    
    if ($RecommendedAction -eq "No Action Required" -or $RecommendedAction -like "Keep*") {
        return @{
            RecommendedTargetRedundancy = $CurrentRedundancy
            RecommendedMonthlyCost = $DataSizeGB * $currentPrice
            RecommendedAnnualSavings = 0
        }
    }
    
    $targetRedundancy = "LRS"
    if ($RecommendedAction -like "*GRS*") {
        $targetRedundancy = "GRS"
    }
    elseif ($RecommendedAction -like "*LRS*") {
        $targetRedundancy = "LRS"
    }
    elseif ($RecommendedAction -like "*ZRS*") {
        $targetRedundancy = "ZRS"
    }
    
    $targetPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType $targetRedundancy -StorageType $StorageType
    $currentCost = $DataSizeGB * $currentPrice
    $targetCost = $DataSizeGB * $targetPrice
    
    return @{
        RecommendedTargetRedundancy = $targetRedundancy
        RecommendedMonthlyCost = [math]::Round($targetCost, 2)
        RecommendedAnnualSavings = [math]::Round(($currentCost - $targetCost) * 12, 2)
    }
}

function Get-RecommendedAction {
    param(
        [string]$CurrentRedundancy,
        [bool]$IsSecondaryReadUsed,
        [string]$Environment
    )
    
    if ($CurrentRedundancy -like "*LRS*") {
        return "No Action Required"
    }
    
    if ($Environment -eq "Non-Prod") {
        if ($CurrentRedundancy -like "*RAGRS*" -or $CurrentRedundancy -like "*GRS*" -or $CurrentRedundancy -like "*ZRS*") {
            return "Convert to LRS"
        }
    }
    elseif ($Environment -eq "Prod") {
        if ($CurrentRedundancy -like "*RAGRS*") {
            if ($IsSecondaryReadUsed) {
                return "Keep RAGRS"
            }
            else {
                return "Convert to GRS"
            }
        }
        elseif ($CurrentRedundancy -like "*GRS*") {
            return "Keep GRS"
        }
        elseif ($CurrentRedundancy -like "*ZRS*") {
            return "Keep ZRS"
        }
    }
    
    return "Review Required"
}

function Export-ToCsv {
    param(
        [array]$Data,
        [string]$FilePath
    )
    
    try {
        # Ensure the directory exists
        $directory = Split-Path -Path $FilePath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            Write-Log "Created directory: $directory"
        }
        
        $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV report exported to: $FilePath"
    }
    catch {
        Write-Log "Error exporting CSV: $_" "ERROR"
        throw
    }
}

function Export-ToHtml {
    param(
        [array]$Data,
        [string]$FilePath
    )
    
    try {
        $totalAccounts = $Data.Count
        $totalDataGB = ($Data | Measure-Object -Property DataSizeGB -Sum).Sum
        $totalDataTB = [math]::Round($totalDataGB / 1024, 2)
        $totalCurrentCost = ($Data | Measure-Object -Property CurrentMonthlyCost -Sum).Sum
        $totalRecommendedSavings = ($Data | Measure-Object -Property RecommendedAnnualSavings -Sum).Sum
        $accountsWithSecondaryRead = ($Data | Where-Object { $_.IsSecondaryReadUsed -eq $true }).Count
        $accountsWithoutSecondaryRead = $totalAccounts - $accountsWithSecondaryRead
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Azure Storage Redundancy Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 14px; opacity: 0.9; }
        .summary-card .value { font-size: 28px; font-weight: bold; margin: 10px 0; }
        .summary-card .label { font-size: 12px; opacity: 0.8; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 12px; }
        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .used { color: #d32f2f; font-weight: bold; }
        .not-used { color: #388e3c; font-weight: bold; }
        .recommendation { padding: 5px 10px; border-radius: 4px; font-weight: bold; }
        .convert-zrs { background-color: #fff3cd; color: #856404; }
        .convert-grs { background-color: #d1ecf1; color: #0c5460; }
        .convert-lrs { background-color: #d4edda; color: #155724; }
        .keep { background-color: #f8d7da; color: #721c24; }
        .no-action { background-color: #e2e3e5; color: #383d41; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 11px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Storage Redundancy Analysis Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>Total Accounts Analyzed</h3>
                <div class="value">$totalAccounts</div>
                <div class="label">RAGRS/GRS/ZRS/LRS Accounts</div>
            </div>
            <div class="summary-card">
                <h3>Total Data Stored</h3>
                <div class="value">$totalDataTB TB</div>
                <div class="label">$([math]::Round($totalDataGB, 2)) GB</div>
            </div>
            <div class="summary-card">
                <h3>Current Monthly Cost</h3>
                <div class="value">&pound;$([math]::Round($totalCurrentCost, 2))</div>
                <div class="label">Current Redundancy Pricing</div>
            </div>
            <div class="summary-card">
                <h3>Secondary Read Usage</h3>
                <div class="value">$accountsWithSecondaryRead</div>
                <div class="label">$accountsWithoutSecondaryRead accounts not using it</div>
            </div>
            <div class="summary-card">
                <h3>Potential Annual Savings</h3>
                <div class="value">&pound;$([math]::Round($totalRecommendedSavings, 2))</div>
                <div class="label">Non-Prod→LRS, Prod→GRS</div>
            </div>
        </div>
        
        <h2>Detailed Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Subscription</th>
                    <th>Storage Account</th>
                    <th>Resource Group</th>
                    <th>Location</th>
                    <th>Current Redundancy</th>
                    <th>Storage Type</th>
                    <th>Environment</th>
                    <th>Data Size (GB)</th>
                    <th>Secondary Read Used</th>
                    <th>Current Cost/Month</th>
                    <th>Recommended Savings/Year</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($row in $Data) {
            $secondaryReadStatus = if ($row.IsSecondaryReadUsed) { '<span class="used">Yes</span>' } else { '<span class="not-used">No</span>' }
            $recClass = switch -Wildcard ($row.RecommendedAction) {
                "*ZRS*" { "convert-zrs" }
                "*GRS*" { "convert-grs" }
                "*LRS*" { "convert-lrs" }
                "*No Action*" { "no-action" }
                "*Keep*" { "keep" }
                default { "keep" }
            }
            
            $html += @"
                <tr>
                    <td>$($row.SubscriptionName)</td>
                    <td>$($row.StorageAccountName)</td>
                    <td>$($row.ResourceGroupName)</td>
                    <td>$($row.Location)</td>
                    <td>$($row.CurrentRedundancy)</td>
                    <td>$($row.StorageType)</td>
                    <td>$($row.Environment)</td>
                    <td>$([math]::Round($row.DataSizeGB, 2))</td>
                    <td>$secondaryReadStatus</td>
                    <td>&pound;$([math]::Round($row.CurrentMonthlyCost, 2))</td>
                    <td>&pound;$([math]::Round($row.RecommendedAnnualSavings, 2))</td>
                    <td><span class="recommendation $recClass">$($row.RecommendedAction)</span></td>
                </tr>
"@
        }
        
        $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            <p>Report generated by Azure Storage Redundancy Analysis Script</p>
            <p>Note: Pricing may vary by region. Recommendations: Non-Prod accounts → LRS, Prod accounts (without secondary read) → GRS.</p>
        </div>
    </div>
</body>
</html>
"@
        
        # Ensure the directory exists
        $directory = Split-Path -Path $FilePath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            Write-Log "Created directory: $directory"
        }
        
        # Use UTF8 with BOM to ensure proper currency symbol encoding
        $utf8WithBom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($FilePath, $html, $utf8WithBom)
        Write-Log "HTML report exported to: $FilePath"
    }
    catch {
        Write-Log "Error exporting HTML: $_" "ERROR"
        throw
    }
}

function Main {
    Write-Log "Starting Azure Storage Redundancy Analysis"
    
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Log "Not connected to Azure. Please run Connect-AzAccount first." "ERROR"
            exit 1
        }
        Write-Log "Connected to Azure as: $($context.Account.Id)"
    }
    catch {
        Write-Log "Error checking Azure connection: $_" "ERROR"
        exit 1
    }
    
    $config = Get-Config -ConfigFilePath $ConfigPath
    
    if ($AnalysisPeriodDays -gt 0) {
        $config.analysisPeriodDays = $AnalysisPeriodDays
    }
    
    if ($OutputPath -eq "") {
        $OutputPath = $config.outputDirectory
    }
    
    # Resolve relative paths to absolute paths
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $OutputPath
    }
    
    # Normalize the path (remove .\ or ./)
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Created output directory: $OutputPath"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = Join-Path $OutputPath "storage-redundancy-analysis_$timestamp.csv"
    $htmlPath = Join-Path $OutputPath "storage-redundancy-analysis_$timestamp.html"
    $errorLogPath = Join-Path $OutputPath "storage-redundancy-analysis_errors_$timestamp.log"
    
    $results = @()
    $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
    
    if (-not $subscriptions) {
        Write-Log "No subscriptions found or access denied" "ERROR"
        exit 1
    }
    
    Write-Log "Found $($subscriptions.Count) subscription(s)"
    
    foreach ($subscription in $subscriptions) {
        Write-Log "Processing subscription: $($subscription.Name) ($($subscription.Id))"
        
        try {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "Cannot access subscription $($subscription.Name): $_" "ERROR"
            continue
        }
        
        try {
            $storageAccounts = Get-AzStorageAccount -ErrorAction Stop
        }
        catch {
            Write-Log "Error retrieving storage accounts for subscription $($subscription.Name): $_" "ERROR"
            continue
        }
        
        $targetAccounts = $storageAccounts | Where-Object { 
            $sku = $_.Sku.Name
            $sku -like "*RAGRS*" -or 
            ($sku -like "*GRS*" -and $sku -notlike "*RA*") -or 
            $sku -like "*ZRS*" -or 
            $sku -like "*LRS*"
        }
        
        Write-Log "Found $($targetAccounts.Count) storage account(s) (RAGRS/GRS/ZRS/LRS) in subscription $($subscription.Name)"
        
        foreach ($account in $targetAccounts) {
            Write-Log "Analyzing: $($account.StorageAccountName) ($($account.Sku.Name))"
            
            try {
                $skuName = $account.Sku.Name
                $currentRedundancy = Get-RedundancyTypeFromSku -SkuName $skuName
                $dataSizeGB = Get-StorageAccountUsage -ResourceGroupName $account.ResourceGroupName -StorageAccountName $account.StorageAccountName
                $secondaryRead = Get-SecondaryReadUsage -ResourceId $account.Id -RedundancyType $currentRedundancy -Days $config.analysisPeriodDays
                $storageType = Get-StorageAccountType -StorageAccount $account
                $environment = Get-EnvironmentType -StorageAccountName $account.StorageAccountName -SubscriptionName $subscription.Name -Config $config
                $recommendation = Get-RecommendedAction -CurrentRedundancy $currentRedundancy -IsSecondaryReadUsed $secondaryRead.IsUsed -Environment $environment
                
                $costSavings = Calculate-CostSavings -DataSizeGB $dataSizeGB -Config $config -Region $account.Location -CurrentRedundancy $currentRedundancy -StorageType $storageType
                $recommendedSavings = Calculate-RecommendedSavings -DataSizeGB $dataSizeGB -Config $config -Region $account.Location -CurrentRedundancy $currentRedundancy -RecommendedAction $recommendation -StorageType $storageType
                
                $result = [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceGroupName = $account.ResourceGroupName
                    StorageAccountName = $account.StorageAccountName
                    Location = $account.Location
                    CurrentRedundancy = $skuName
                    StorageTier = if ($skuName -like "Premium*") { "Premium" } else { "Standard" }
                    StorageType = $storageType
                    DataSizeGB = $dataSizeGB
                    DataSizeTB = [math]::Round($dataSizeGB / 1024, 2)
                    SecondaryReadCount = $secondaryRead.Count
                    SecondaryReadPercentage = $secondaryRead.Percentage
                    IsSecondaryReadUsed = $secondaryRead.IsUsed
                    CurrentMonthlyCost = $costSavings.CurrentMonthlyCost
                    LRSMonthlyCost = $costSavings.LRSMonthlyCost
                    LRSSavings = $costSavings.LRSSavings
                    LRSAnnualSavings = $costSavings.LRSAnnualSavings
                    ZRSMonthlyCost = $costSavings.ZRSMonthlyCost
                    ZRSSavings = $costSavings.ZRSSavings
                    ZRSAnnualSavings = $costSavings.ZRSAnnualSavings
                    GRSMonthlyCost = $costSavings.GRSMonthlyCost
                    GRSSavings = $costSavings.GRSSavings
                    GRSAnnualSavings = $costSavings.GRSAnnualSavings
                    RecommendedAction = $recommendation
                    RecommendedTargetRedundancy = $recommendedSavings.RecommendedTargetRedundancy
                    RecommendedAnnualSavings = $recommendedSavings.RecommendedAnnualSavings
                    Environment = $environment
                }
                
                $results += $result
                Write-Log "Completed: $($account.StorageAccountName) - Redundancy: $currentRedundancy, Data: $dataSizeGB GB, Secondary Read: $($secondaryRead.IsUsed), Recommendation: $recommendation"
            }
            catch {
                Write-Log "Error analyzing account $($account.StorageAccountName): $_" "ERROR"
                continue
            }
        }
    }
    
    if ($results.Count -eq 0) {
        Write-Log "No storage accounts found (RAGRS/GRS/ZRS/LRS)" "WARN"
        exit 0
    }
    
    Write-Log "Exporting results..."
    Export-ToCsv -Data $results -FilePath $csvPath
    Export-ToHtml -Data $results -FilePath $htmlPath
    
    if ($script:ErrorLog.Count -gt 0) {
        $script:ErrorLog | Out-File -FilePath $errorLogPath -Encoding UTF8
        Write-Log "Error log saved to: $errorLogPath"
    }
    
    Write-Log "Analysis complete! Processed $($results.Count) storage account(s)"
    Write-Log "Reports saved to: $OutputPath"
}

Main

