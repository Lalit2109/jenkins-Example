<# 
    Azure Blob policy-based cleanup script
    - Attempts to delete all blobs in a storage account (or a single container)
    - Respects existing immutability/retention policies (those blobs will fail to delete)
    - Supports -WhatIf via SupportsShouldProcess for dry-run behaviour
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName,

    [Parameter(Mandatory = $false)]
    [int]$MinAgeInDays = 0
)

function Format-Bytes {
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    if ($Bytes -lt 1KB) { return "$Bytes B" }
    elseif ($Bytes -lt 1MB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
    elseif ($Bytes -lt 1GB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    elseif ($Bytes -lt 1TB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
    else { return ("{0:N2} TB" -f ($Bytes / 1TB)) }
}

Write-Verbose "Ensuring Az.Accounts and Az.Storage modules are available."

try {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw "Az PowerShell modules (Az.Accounts) are not installed. Install with: Install-Module Az -Scope CurrentUser"
    }
    if (-not (Get-Module -ListAvailable -Name Az.Storage)) {
        throw "Az PowerShell modules (Az.Storage) are not installed. Install with: Install-Module Az.Storage -Scope CurrentUser"
    }
}
catch {
    Write-Error $_.Exception.Message
    return
}

Write-Verbose "Connecting to Azure and setting subscription context."

try {
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Failed to authenticate or set Azure context: $($_.Exception.Message)"
    return
}

Write-Verbose "Retrieving storage account context."

try {
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $ctx = $storageAccount.Context
}
catch {
    Write-Error "Failed to get storage account '$StorageAccountName' in resource group '$ResourceGroupName': $($_.Exception.Message)"
    return
}

$cutoffDateUtc = $null
if ($MinAgeInDays -gt 0) {
    $cutoffDateUtc = [DateTime]::UtcNow.AddDays(-1 * $MinAgeInDays)
    Write-Verbose "Minimum blob age filter enabled: only blobs last modified on or before $cutoffDateUtc (UTC) will be considered."
}

Write-Verbose "Enumerating containers."

try {
    if ([string]::IsNullOrWhiteSpace($ContainerName)) {
        $containers = Get-AzStorageContainer -Context $ctx -ErrorAction Stop
    }
    else {
        $container = Get-AzStorageContainer -Context $ctx -Name $ContainerName -ErrorAction Stop
        $containers = @($container)
    }
}
catch {
    Write-Error "Failed to list containers: $($_.Exception.Message)"
    return
}

if (-not $containers -or $containers.Count -eq 0) {
    Write-Output "No containers found in storage account '$StorageAccountName'. Nothing to do."
    return
}

$totalBlobsExamined = 0L
$totalBlobsCandidate = 0L
$totalBlobsDeleted = 0L
$totalBlobsWouldDelete = 0L
$totalBytesDeleted = 0L
$totalBytesWouldDelete = 0L
$failures = New-Object System.Collections.Generic.List[object]

$isWhatIf = $WhatIfPreference -eq $true

foreach ($container in $containers) {
    Write-Verbose "Processing container '$($container.Name)'."

    $continuationToken = $null

    do {
        try {
            $blobResult = Get-AzStorageBlob -Container $container.Name -Context $ctx -ContinuationToken $continuationToken -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to list blobs in container '$($container.Name)': $($_.Exception.Message)"
            break
        }

        if (-not $blobResult) {
            break
        }

        $continuationToken = $blobResult.ContinuationToken

        foreach ($blob in $blobResult) {
            $totalBlobsExamined++

            if ($cutoffDateUtc -ne $null) {
                $lastModifiedUtc = $blob.LastModified.UtcDateTime
                if ($lastModifiedUtc -gt $cutoffDateUtc) {
                    continue
                }
            }

            $totalBlobsCandidate++
            $sizeBytes = [long]$blob.Length
            $blobPath = "$($container.Name)/$($blob.Name)"

            Write-Verbose "Candidate blob: $blobPath (Size: $(Format-Bytes -Bytes $sizeBytes), LastModified: $($blob.LastModified))"

            if ($PSCmdlet.ShouldProcess($blobPath, "Delete blob")) {
                try {
                    Remove-AzStorageBlob -Context $ctx -Container $container.Name -Blob $blob.Name -Force -ErrorAction Stop
                    $totalBlobsDeleted++
                    $totalBytesDeleted += $sizeBytes
                    Write-Verbose "Deleted blob: $blobPath"
                }
                catch {
                    Write-Warning "Failed to delete blob '$blobPath': $($_.Exception.Message)"
                    $failures.Add([PSCustomObject]@{
                        Container = $container.Name
                        Blob      = $blob.Name
                        SizeBytes = $sizeBytes
                        Reason    = $_.Exception.Message
                    }) | Out-Null
                }
            }
            else {
                # WhatIf / dry-run path: we record what would be deleted.
                $totalBlobsWouldDelete++
                $totalBytesWouldDelete += $sizeBytes
                Write-Verbose "Would delete blob: $blobPath"
            }
        }
    } while ($continuationToken)
}

Write-Output "========== Azure Blob Cleanup Summary =========="
Write-Output "Storage Account : $StorageAccountName"
if ($ContainerName) {
    Write-Output "Container       : $ContainerName"
}
else {
    Write-Output "Container       : All containers"
}
Write-Output "Subscription    : $SubscriptionId"
Write-Output "MinAgeInDays    : $MinAgeInDays"
Write-Output "Mode            : $(if ($isWhatIf) { 'DRY-RUN (-WhatIf)' } else { 'LIVE (deletions executed)' })"
Write-Output ""
Write-Output "Total blobs examined        : $totalBlobsExamined"
Write-Output "Total candidate blobs       : $totalBlobsCandidate"

if ($isWhatIf) {
    Write-Output "Blobs that would be deleted : $totalBlobsWouldDelete"
    Write-Output "Total size that would delete: $(Format-Bytes -Bytes $totalBytesWouldDelete) ($totalBytesWouldDelete bytes)"
}
else {
    Write-Output "Blobs deleted               : $totalBlobsDeleted"
    Write-Output "Total size deleted          : $(Format-Bytes -Bytes $totalBytesDeleted) ($totalBytesDeleted bytes)"
}

if ($failures.Count -gt 0) {
    Write-Output ""
    Write-Output "Blobs that could not be deleted (likely due to retention/immutability policies or other errors): $($failures.Count)"
    $failures | Select-Object Container, Blob, SizeBytes, Reason | Format-Table -AutoSize | Out-String | Write-Output
}
else {
    Write-Output ""
    Write-Output "No deletion failures were encountered."
}

Write-Output "==============================================="
Write-Output ""
Write-Output "Example usage:"
Write-Output "  # Dry-run across all containers (no actual deletions)"
Write-Output "  .\\azure-blob-cleanup.ps1 -SubscriptionId '<sub-id>' -ResourceGroupName '<rg-name>' -StorageAccountName '<account-name>' -WhatIf"
Write-Output ""
Write-Output "  # Dry-run for blobs older than 90 days in a single container"
Write-Output "  .\\azure-blob-cleanup.ps1 -SubscriptionId '<sub-id>' -ResourceGroupName '<rg-name>' -StorageAccountName '<account-name>' -ContainerName 'my-container' -MinAgeInDays 90 -WhatIf"
Write-Output ""
Write-Output "  # Actual deletion for blobs older than 90 days (no -WhatIf)"
Write-Output "  .\\azure-blob-cleanup.ps1 -SubscriptionId '<sub-id>' -ResourceGroupName '<rg-name>' -StorageAccountName '<account-name>' -MinAgeInDays 90"

