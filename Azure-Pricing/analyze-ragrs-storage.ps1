#Requires -Modules Az.Accounts, Az.Storage, Az.Monitor

<#
.SYNOPSIS
    Analyzes Azure RAGRS storage accounts to identify cost optimization opportunities.

.DESCRIPTION
    This script analyzes all RAGRS storage accounts across Azure subscriptions to:
    - Check if secondary read endpoint is being used
    - Calculate data sizes and potential cost savings
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
        [object]$Config
    )
    
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
        [int]$Days
    )
    
    try {
        $startTime = (Get-Date).AddDays(-$Days)
        $endTime = Get-Date
        
        # Suppress deprecation warnings
        $ErrorActionPreferenceBackup = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        
        $metrics = Get-AzMetric -ResourceId $ResourceId -MetricName "GeoSecondaryRead" -TimeGrain 01:00:00 -StartTime $startTime -EndTime $endTime -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        
        if (-not $metrics -or -not $metrics.Data) {
            return @{
                Count = 0
                Percentage = 0
                IsUsed = $false
            }
        }
        
        $totalReads = ($metrics.Data | Measure-Object -Property Total -Sum).Sum
        $avgReads = ($metrics.Data | Measure-Object -Property Average -Average).Average
        
        $primaryMetrics = Get-AzMetric -ResourceId $ResourceId -MetricName "Transactions" -TimeGrain 01:00:00 -StartTime $startTime -EndTime $endTime -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $totalTransactions = 0
        if ($primaryMetrics -and $primaryMetrics.Data) {
            $totalTransactions = ($primaryMetrics.Data | Measure-Object -Property Total -Sum).Sum
        }
        
        $ErrorActionPreference = $ErrorActionPreferenceBackup
        
        $percentage = 0
        if ($totalTransactions -gt 0) {
            $percentage = [math]::Round(($totalReads / $totalTransactions) * 100, 2)
        }
        
        $isUsed = $totalReads -gt 0 -or $percentage -gt 1
        
        return @{
            Count = [math]::Round($totalReads, 0)
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
        [string]$StorageType = "Blob"
    )
    
    $ragrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "RAGRS" -StorageType $StorageType
    $lrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "LRS" -StorageType $StorageType
    $zrsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "ZRS" -StorageType $StorageType
    $grsPrice = Get-PricingForRegion -Config $Config -Region $Region -RedundancyType "GRS" -StorageType $StorageType
    
    $currentCost = $DataSizeGB * $ragrsPrice
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

function Get-RecommendedAction {
    param(
        [bool]$IsSecondaryReadUsed,
        [string]$Environment,
        [object]$CostSavings
    )
    
    if ($IsSecondaryReadUsed) {
        return "Keep RAGRS"
    }
    
    if ($Environment -eq "Non-Prod") {
        if ($CostSavings.ZRSSavings -gt $CostSavings.LRSSavings) {
            return "Convert to ZRS"
        }
        else {
            return "Convert to LRS"
        }
    }
    elseif ($Environment -eq "Prod") {
        return "Convert to GRS"
    }
    
    return "Review Required"
}

function Export-ToCsv {
    param(
        [array]$Data,
        [string]$FilePath
    )
    
    try {
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
        $totalLRSSavings = ($Data | Measure-Object -Property LRSAnnualSavings -Sum).Sum
        $totalZRSSavings = ($Data | Measure-Object -Property ZRSAnnualSavings -Sum).Sum
        $totalGRSSavings = ($Data | Measure-Object -Property GRSAnnualSavings -Sum).Sum
        $accountsWithSecondaryRead = ($Data | Where-Object { $_.IsSecondaryReadUsed -eq $true }).Count
        $accountsWithoutSecondaryRead = $totalAccounts - $accountsWithSecondaryRead
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Azure RAGRS Storage Analysis Report</title>
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
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 11px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure RAGRS Storage Account Analysis Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>Total RAGRS Accounts</h3>
                <div class="value">$totalAccounts</div>
                <div class="label">Storage Accounts</div>
            </div>
            <div class="summary-card">
                <h3>Total Data Stored</h3>
                <div class="value">$totalDataTB TB</div>
                <div class="label">$([math]::Round($totalDataGB, 2)) GB</div>
            </div>
            <div class="summary-card">
                <h3>Current Monthly Cost</h3>
                <div class="value">&pound;$([math]::Round($totalCurrentCost, 2))</div>
                <div class="label">RAGRS Pricing</div>
            </div>
            <div class="summary-card">
                <h3>Secondary Read Usage</h3>
                <div class="value">$accountsWithSecondaryRead</div>
                <div class="label">$accountsWithoutSecondaryRead accounts not using it</div>
            </div>
            <div class="summary-card">
                <h3>Potential Annual Savings</h3>
                <div class="value">&pound;$([math]::Round([Math]::Max($totalZRSSavings, [Math]::Max($totalLRSSavings, $totalGRSSavings)), 2))</div>
                <div class="label">If converted appropriately</div>
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
                    <th>Storage Type</th>
                    <th>Environment</th>
                    <th>Data Size (GB)</th>
                    <th>Secondary Read Used</th>
                    <th>Current Cost/Month</th>
                    <th>ZRS Savings/Year</th>
                    <th>GRS Savings/Year</th>
                    <th>LRS Savings/Year</th>
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
                default { "keep" }
            }
            
            $html += @"
                <tr>
                    <td>$($row.SubscriptionName)</td>
                    <td>$($row.StorageAccountName)</td>
                    <td>$($row.ResourceGroupName)</td>
                    <td>$($row.Location)</td>
                    <td>$($row.StorageType)</td>
                    <td>$($row.Environment)</td>
                    <td>$([math]::Round($row.DataSizeGB, 2))</td>
                    <td>$secondaryReadStatus</td>
                    <td>&pound;$([math]::Round($row.CurrentMonthlyCost, 2))</td>
                    <td>&pound;$([math]::Round($row.ZRSAnnualSavings, 2))</td>
                    <td>&pound;$([math]::Round($row.GRSAnnualSavings, 2))</td>
                    <td>&pound;$([math]::Round($row.LRSAnnualSavings, 2))</td>
                    <td><span class="recommendation $recClass">$($row.RecommendedAction)</span></td>
                </tr>
"@
        }
        
        $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            <p>Report generated by Azure RAGRS Storage Analysis Script</p>
            <p>Note: Pricing may vary by region. Please verify current Azure pricing before making conversion decisions.</p>
        </div>
    </div>
</body>
</html>
"@
        
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
    Write-Log "Starting Azure RAGRS Storage Analysis"
    
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
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Created output directory: $OutputPath"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = Join-Path $OutputPath "ragrs-analysis_$timestamp.csv"
    $htmlPath = Join-Path $OutputPath "ragrs-analysis_$timestamp.html"
    $errorLogPath = Join-Path $OutputPath "ragrs-analysis_errors_$timestamp.log"
    
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
        
        $ragrsAccounts = $storageAccounts | Where-Object { 
            $_.Sku.Name -like "*RAGRS*" 
        }
        
        Write-Log "Found $($ragrsAccounts.Count) RAGRS storage account(s) in subscription $($subscription.Name)"
        
        foreach ($account in $ragrsAccounts) {
            Write-Log "Analyzing: $($account.StorageAccountName)"
            
            try {
                $dataSizeGB = Get-StorageAccountUsage -ResourceGroupName $account.ResourceGroupName -StorageAccountName $account.StorageAccountName
                $secondaryRead = Get-SecondaryReadUsage -ResourceId $account.Id -Days $config.analysisPeriodDays
                $storageType = Get-StorageAccountType -StorageAccount $account
                $costSavings = Calculate-CostSavings -DataSizeGB $dataSizeGB -Config $config -Region $account.Location -StorageType $storageType
                $environment = Get-EnvironmentType -StorageAccountName $account.StorageAccountName -Config $config
                $recommendation = Get-RecommendedAction -IsSecondaryReadUsed $secondaryRead.IsUsed -Environment $environment -CostSavings $costSavings
                
                $result = [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceGroupName = $account.ResourceGroupName
                    StorageAccountName = $account.StorageAccountName
                    Location = $account.Location
                    CurrentRedundancy = $account.Sku.Name
                    StorageTier = if ($account.Sku.Name -like "Premium*") { "Premium" } else { "Standard" }
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
                    Environment = $environment
                }
                
                $results += $result
                Write-Log "Completed: $($account.StorageAccountName) - Data: $dataSizeGB GB, Secondary Read: $($secondaryRead.IsUsed)"
            }
            catch {
                Write-Log "Error analyzing account $($account.StorageAccountName): $_" "ERROR"
                continue
            }
        }
    }
    
    if ($results.Count -eq 0) {
        Write-Log "No RAGRS storage accounts found" "WARN"
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

