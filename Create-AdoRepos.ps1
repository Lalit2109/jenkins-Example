param(
    [Parameter(Mandatory = $true)]
    [string]$OrganizationUrl,  # e.g. "https://dev.azure.com/myorg"

    [Parameter(Mandatory = $true)]
    [string]$ProjectName,      # e.g. "MyProject"

    [Parameter(Mandatory = $true)]
    [string]$RepoListPath      # Path to text file: one repo name per line
)

Write-Host "=== Azure DevOps Repo Creator ==="

# ---------------------- Pre-checks ----------------------

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "'az' CLI is not installed or not in PATH. Install Azure CLI first (https://learn.microsoft.com/cli/azure/install-azure-cli)."
    exit 1
}

Write-Host "Using Azure DevOps organization: $OrganizationUrl"
Write-Host "Using project            : $ProjectName"
Write-Host "Repo list file           : $RepoListPath"

if (-not (Test-Path -LiteralPath $RepoListPath)) {
    Write-Error "Repo list file not found at '$RepoListPath'."
    exit 1
}

# Make sure Azure DevOps extension is installed
try {
    az devops -h *>$null
}
catch {
    Write-Host "Azure DevOps CLI extension not found. Installing..."
    az extension add --name azure-devops
}

# Configure defaults (this only affects az devops, not global git)
Write-Host "Configuring az devops defaults..."
az devops configure --defaults organization=$OrganizationUrl project=$ProjectName 1>$null

# Make sure user is logged in
try {
    $accountInfo = az account show --only-show-errors 2>$null
}
catch {
    Write-Host "You are not logged into Azure CLI. Launching 'az login'..."
    az login
}

# ---------------------- Load repo list ----------------------

$desiredRepos = Get-Content -LiteralPath $RepoListPath |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_.Length -gt 0 }

if (-not $desiredRepos -or $desiredRepos.Count -eq 0) {
    Write-Host "No repository names found in '$RepoListPath'. Nothing to do."
    exit 0
}

Write-Host "Found $($desiredRepos.Count) repo name(s) in list."

# ---------------------- Get existing repos ----------------------

Write-Host "Fetching existing repos from Azure DevOps..."

try {
    $existingRepoNames = az repos list `
        --query "[].name" `
        -o tsv
}
catch {
    Write-Error "Failed to list existing repositories. Check your organization URL, project name, and Azure login."
    exit 1
}

$repoSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
if ($existingRepoNames) {
    $existingRepoNames -split "`n" | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object {
        [void]$repoSet.Add($_.Trim())
    }
}

Write-Host "Existing repositories in project '$ProjectName': $($repoSet.Count)"

# ---------------------- Create missing repos ----------------------

foreach ($repoName in $desiredRepos) {
    if ($repoSet.Contains($repoName)) {
        Write-Host "Skipping '$repoName' (already exists)."
        continue
    }

    Write-Host "Creating repository '$repoName'..."

    try {
        $result = az repos create `
            --name $repoName `
            --project $ProjectName `
            -o json

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  -> Created repo '$repoName'."
            [void]$repoSet.Add($repoName)
        }
        else {
            Write-Warning "  -> az repos create returned exit code $LASTEXITCODE for '$repoName'."
        }
    }
    catch {
        Write-Warning "  -> Failed to create repo '$repoName': $($_.Exception.Message)"
    }
}

Write-Host "All done."


