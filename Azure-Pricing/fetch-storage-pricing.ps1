#Requires -Version 5.1

<#
.SYNOPSIS
    Fetches Azure Storage pricing from Retail Prices API and generates pricing JSON file.

.DESCRIPTION
    This script queries the Azure Retail Prices API to fetch current pricing for
    Blob, File, and Table storage across specified regions and generates a JSON
    configuration file for use with the analysis script.

.PARAMETER Regions
    Array of Azure regions to fetch pricing for. Default: Common regions.

.PARAMETER OutputFile
    Path to output JSON file. Default: ./storage-pricing.json

.EXAMPLE
    .\fetch-storage-pricing.ps1

.EXAMPLE
    .\fetch-storage-pricing.ps1 -Regions @("uksouth", "eastus", "westeurope") -OutputFile "./pricing.json"
#>

param(
    [string[]]$Regions = @(
        "eastus", "eastus2", "westus", "westus2", "westus3",
        "centralus", "northcentralus", "southcentralus", "westcentralus",
        "canadacentral", "canadaeast", "brazilsouth",
        "westeurope", "northeurope", "uksouth", "ukwest",
        "francecentral", "francesouth", "switzerlandnorth", "switzerlandwest",
        "germanywestcentral", "norwayeast",
        "southeastasia", "eastasia", "japaneast", "japanwest",
        "koreacentral", "koreasouth",
        "australiaeast", "australiasoutheast", "australiacentral", "australiacentral2",
        "centralindia", "southindia", "westindia",
        "southafricanorth", "southafricawest", "uaenorth", "uaecentral"
    ),
    [string]$OutputFile = "./storage-pricing.json"
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
}

function Normalize-RegionName {
    param([string]$Region)
    
    $regionLower = $Region.ToLower().Replace(" ", "")
    
    $regionMappings = @{
        "uksouth" = "uksouth"
        "uk south" = "uksouth"
        "uk-south" = "uksouth"
        "ukwest" = "ukwest"
        "uk west" = "ukwest"
        "uk-west" = "ukwest"
    }
    
    if ($regionMappings.ContainsKey($regionLower)) {
        return $regionMappings[$regionLower]
    }
    
    return $regionLower
}

function Get-StoragePricingFromApi {
    param(
        [string]$Region,
        [string]$StorageType
    )
    
    try {
        $baseUrl = "https://prices.azure.com/api/retail/prices"
        $apiVersion = "2023-01-01-preview"
        
        $normalizedRegion = Normalize-RegionName -Region $Region
        
        $filter = "serviceFamily eq 'Storage' and armRegionName eq '$normalizedRegion' and priceType eq 'Consumption'"
        
        $url = "$baseUrl`?api-version=$apiVersion&`$filter=$filter"
        
        $allPrices = @()
        $nextPage = $url
        $pageCount = 0
        
        Write-Log "Fetching pricing for $StorageType in region $normalizedRegion..."
        
        while ($nextPage) {
            $pageCount++
            try {
                $response = Invoke-RestMethod -Uri $nextPage -Method Get -ErrorAction Stop -TimeoutSec 30
                
                if ($response.Items) {
                    $allPrices += $response.Items
                }
                
                $nextPage = $response.NextPageLink
                
                if ($pageCount % 10 -eq 0) {
                    Write-Log "  Processed $pageCount pages, found $($allPrices.Count) pricing items..."
                }
            }
            catch {
                Write-Log "Error fetching page: $_" "WARN"
                break
            }
        }
        
        Write-Log "  Total pricing items retrieved: $($allPrices.Count)"
        
        $pricing = @{
            LRS = $null
            ZRS = $null
            GRS = $null
            RAGRS = $null
        }
        
        $storageTypePatterns = @{
            "Blob" = @("Block Blob", "Blob")
            "File" = @("File", "Files")
            "Table" = @("Table", "Tables")
        }
        
        $patterns = $storageTypePatterns[$StorageType]
        if (-not $patterns) {
            $patterns = @("Block Blob", "Blob")
        }
        
        foreach ($pattern in $patterns) {
            $matchingPrices = $allPrices | Where-Object {
                $meterName = $_.meterName
                $unitOfMeasure = $_.unitOfMeasure
                
                ($meterName -like "*$pattern*" -or $meterName -like "*$StorageType*") -and
                ($unitOfMeasure -like "*GB*" -or $unitOfMeasure -like "*Gigabyte*") -and
                $meterName -notlike "*Premium*" -and
                $meterName -notlike "*Archive*" -and
                $meterName -notlike "*Cool*"
            }
            
            foreach ($priceItem in $matchingPrices) {
                $meterName = $priceItem.meterName
                $price = $priceItem.retailPrice
                
                if ($meterName -like "*LRS*" -and -not $pricing.LRS) {
                    $pricing.LRS = [double]$price
                    Write-Log "    Found LRS: `$$price per GB"
                }
                elseif ($meterName -like "*ZRS*" -and -not $pricing.ZRS) {
                    $pricing.ZRS = [double]$price
                    Write-Log "    Found ZRS: `$$price per GB"
                }
                elseif (($meterName -like "*RA-GRS*" -or $meterName -like "*RAGRS*" -or $meterName -like "*RA GRS*") -and -not $pricing.RAGRS) {
                    $pricing.RAGRS = [double]$price
                    Write-Log "    Found RAGRS: `$$price per GB"
                }
                elseif ($meterName -like "*GRS*" -and $meterName -notlike "*RA*" -and -not $pricing.GRS) {
                    $pricing.GRS = [double]$price
                    Write-Log "    Found GRS: `$$price per GB"
                }
            }
        }
        
        return $pricing
    }
    catch {
        Write-Log "Error fetching pricing for $StorageType in $Region : $_" "ERROR"
        return @{
            LRS = $null
            ZRS = $null
            GRS = $null
            RAGRS = $null
        }
    }
}

function Main {
    Write-Log "Starting Azure Storage Pricing Fetch"
    Write-Log "Regions to process: $($Regions.Count)"
    
    $config = @{
        analysisPeriodDays = 30
        outputDirectory = "./output"
        environmentPatterns = @{
            nonProd = @("dev", "test", "qa", "staging", "nonprod", "non-prod")
            prod = @("prod", "production")
        }
        pricing = @{
            default = @{
                Blob = @{
                    LRS = 0.0184
                    ZRS = 0.023
                    GRS = 0.0368
                    RAGRS = 0.046
                }
                File = @{
                    LRS = 0.0184
                    ZRS = 0.023
                    GRS = 0.0368
                    RAGRS = 0.046
                }
                Table = @{
                    LRS = 0.0184
                    ZRS = 0.023
                    GRS = 0.0368
                    RAGRS = 0.046
                }
            }
            regions = @{}
        }
    }
    
    $storageTypes = @("Blob", "File", "Table")
    
    foreach ($region in $Regions) {
        $normalizedRegion = Normalize-RegionName -Region $region
        Write-Log "Processing region: $normalizedRegion"
        
        $regionPricing = @{
            Blob = @{}
            File = @{}
            Table = @{}
        }
        
        foreach ($storageType in $storageTypes) {
            $pricing = Get-StoragePricingFromApi -Region $normalizedRegion -StorageType $storageType
            
            if ($pricing.LRS) { $regionPricing.$storageType.LRS = $pricing.LRS }
            if ($pricing.ZRS) { $regionPricing.$storageType.ZRS = $pricing.ZRS }
            if ($pricing.GRS) { $regionPricing.$storageType.GRS = $pricing.GRS }
            if ($pricing.RAGRS) { $regionPricing.$storageType.RAGRS = $pricing.RAGRS }
            
            Start-Sleep -Seconds 1
        }
        
        $config.pricing.regions[$normalizedRegion] = $regionPricing
        
        Write-Log "Completed region: $normalizedRegion"
        Write-Log ""
    }
    
    $jsonContent = $config | ConvertTo-Json -Depth 10
    $jsonContent | Out-File -FilePath $OutputFile -Encoding UTF8
    
    Write-Log "Pricing data saved to: $OutputFile"
    Write-Log "Fetch complete!"
}

Main


