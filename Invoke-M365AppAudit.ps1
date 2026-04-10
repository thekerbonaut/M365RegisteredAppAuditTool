#Requires -Version 5.1

<#
.SYNOPSIS
    Audits all registered applications in a Microsoft 365 / Entra ID tenant via Microsoft Graph.

.DESCRIPTION
    Connects to Microsoft Graph and produces a detailed audit report of every app registration
    in the tenant, covering:

      - Display name, Application (client) ID, Object ID, creation date
      - Sign-in audience and publisher domain
      - Owners (UPN / display name)
      - App roles defined by the application
      - Requested API permissions (delegated + application) with human-readable names
      - Granted / consented API permissions (admin consent + user consent)
      - Client secrets and certificates with expiry status
      - Service-principal settings: sign-in enabled, assignment required, visibility
      - SSO mode, login URL, notification e-mails
      - User / group assignment count
      - Credential health summary (EXPIRED / EXPIRING_SOON / OK / NONE)

    Results are written to a CSV file (always) and optionally to JSON.

    NOTE – "Allow users to request access to this application?" is managed through the
    Entitlement Management / My Apps portal and is NOT exposed as a single Graph property.
    Use the Azure portal (Enterprise Apps › [App] › Self service) to review it manually.

.PARAMETER OutputCsvPath
    Destination path for the CSV report.
    Defaults to .\M365AppAudit_<timestamp>.csv in the current directory.

.PARAMETER OutputJsonPath
    Optional destination path for a full JSON report.

.PARAMETER TenantId
    Tenant ID (GUID) or primary domain (e.g. contoso.onmicrosoft.com).
    If omitted the authenticated user's home tenant is used.

.PARAMETER ClientId
    Application (client) ID used for app-only authentication.

.PARAMETER ClientSecret
    Client secret string used for app-only authentication.
    Prefer a certificate (-CertificateThumbprint) in production.

.PARAMETER CertificateThumbprint
    Thumbprint of a local certificate used for app-only authentication.

.PARAMETER FilterDisplayName
    Case-insensitive substring filter applied client-side on the app display name.

.PARAMETER CredentialWarningDays
    Credentials expiring within this many days are flagged as EXPIRING_SOON. Default: 30.

.PARAMETER PassThru
    When specified, the cmdlet also returns the result objects to the pipeline.

.EXAMPLE
    .\Invoke-M365AppAudit.ps1
    Interactive browser sign-in; exports CSV to the current directory.

.EXAMPLE
    .\Invoke-M365AppAudit.ps1 -TenantId contoso.com -OutputCsvPath C:\Reports\apps.csv -OutputJsonPath C:\Reports\apps.json

.EXAMPLE
    .\Invoke-M365AppAudit.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumb>
    App-only authentication using a certificate installed in the current user's certificate store.

.NOTES
    Required Microsoft Graph permissions (delegated OR app-only):
        Application.Read.All
        Directory.Read.All
        AppRoleAssignment.Read.All

    Install the required module once:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param (
    # ── Auth parameters ────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'Interactive')]
    [Parameter(ParameterSetName = 'ClientSecret')]
    [Parameter(ParameterSetName = 'Certificate')]
    [string] $TenantId,

    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string] $ClientId,

    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [string] $ClientSecret,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string] $CertificateThumbprint,

    # ── Output parameters ──────────────────────────────────────────────────────
    [string] $OutputCsvPath,
    [string] $OutputJsonPath,

    # ── Filtering / behaviour ──────────────────────────────────────────────────
    [string] $FilterDisplayName,
    [int]    $CredentialWarningDays = 30,
    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Default CSV output path (evaluated at runtime)
if (-not $OutputCsvPath) {
    $OutputCsvPath = Join-Path $PWD "M365AppAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-MgGraphPaged {
    <#
    .SYNOPSIS Fetches all pages from a Graph endpoint and returns a flat array.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Uri,
        [int] $MaxRetries = 4
    )

    $items   = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-MgGraphWithRetry -Uri $nextUri -MaxRetries $MaxRetries

        if ($null -ne $response.value) {
            foreach ($item in $response.value) { $items.Add($item) }
        }
        $nextUri = $response.'@odata.nextLink'
    }

    return , $items.ToArray()   # comma forces single-element return (array preservation)
}

function Invoke-MgGraphWithRetry {
    <#
    .SYNOPSIS Single GET request with exponential-backoff retry.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Uri,
        [int] $MaxRetries = 4
    )

    $attempt = 0
    while ($true) {
        try {
            return Invoke-MgGraphRequest -Uri $Uri -Method GET -OutputType PSObject
        }
        catch {
            $attempt++
            if ($attempt -ge $MaxRetries) {
                Write-Warning "Graph request failed after $MaxRetries attempts for: $Uri`n$_"
                return $null
            }
            $waitSec = [math]::Pow(2, $attempt)
            Write-Verbose "Retrying ($attempt/$MaxRetries) in ${waitSec}s — $Uri"
            Start-Sleep -Seconds $waitSec
        }
    }
}

function Resolve-GraphPermissions {
    <#
    .SYNOPSIS Converts requiredResourceAccess entries into readable strings.
    #>
    param (
        [object[]] $RequiredResourceAccess,
        [hashtable] $PermissionCache,
        [hashtable] $SpByAppId
    )

    $results = [System.Collections.Generic.List[string]]::new()

    foreach ($resource in $RequiredResourceAccess) {
        $resourceName = ($SpByAppId[$resource.resourceAppId])?.displayName
        if (-not $resourceName) { $resourceName = $resource.resourceAppId }

        foreach ($access in $resource.resourceAccess) {
            $cached = $PermissionCache[$access.id]
            $type   = if ($access.type -eq 'Role') { 'Application' } else { 'Delegated' }

            if ($cached) {
                $results.Add("$($cached.Resource): $($cached.Name) [$type]")
            }
            else {
                $results.Add("${resourceName}: $($access.id) [$type]")
            }
        }
    }

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Prerequisites
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[1/6] Checking prerequisites..." -ForegroundColor Cyan

$authModule = Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue |
              Sort-Object Version -Descending |
              Select-Object -First 1

if (-not $authModule) {
    Write-Error ("Microsoft.Graph.Authentication module not found.`n" +
                 "Install it with:  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser")
    exit 1
}

Write-Host "  Using Microsoft.Graph.Authentication v$($authModule.Version)" -ForegroundColor Gray
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# 2. Connect to Microsoft Graph
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/6] Connecting to Microsoft Graph..." -ForegroundColor Cyan

$connectParams = @{}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

switch ($PSCmdlet.ParameterSetName) {
    'ClientSecret' {
        $secSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ClientId, $secSecret)
        $connectParams['ClientSecretCredential'] = $credential
        Write-Host "  Auth method: Client Secret" -ForegroundColor Gray
    }
    'Certificate' {
        $connectParams['ClientId']               = $ClientId
        $connectParams['CertificateThumbprint']  = $CertificateThumbprint
        Write-Host "  Auth method: Certificate ($CertificateThumbprint)" -ForegroundColor Gray
    }
    default {
        $connectParams['Scopes'] = @(
            'Application.Read.All',
            'Directory.Read.All',
            'AppRoleAssignment.Read.All'
        )
        Write-Host "  Auth method: Interactive (browser)" -ForegroundColor Gray
    }
}

try {
    Connect-MgGraph @connectParams
    $ctx = Get-MgContext
    Write-Host "  Connected  : tenant $($ctx.TenantId)  |  account $($ctx.Account)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. Fetch application registrations
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/6] Fetching application registrations..." -ForegroundColor Cyan

$appSelect = (
    'id', 'appId', 'displayName', 'createdDateTime', 'signInAudience',
    'publisherDomain', 'verifiedPublisher', 'description', 'notes', 'tags',
    'identifierUris', 'web', 'spa', 'publicClient', 'info',
    'requiredResourceAccess', 'appRoles',
    'passwordCredentials', 'keyCredentials'
) -join ','

$appUri       = "https://graph.microsoft.com/v1.0/applications?`$select=$appSelect&`$top=999"
$applications = Invoke-MgGraphPaged -Uri $appUri

# Client-side display name filter
if ($FilterDisplayName) {
    $applications = @($applications | Where-Object {
        $_.displayName -like "*$FilterDisplayName*"
    })
}

Write-Host "  Found $($applications.Count) application registration(s)" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# 4. Fetch service principals (bulk, basic properties)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/6] Fetching service principals..." -ForegroundColor Cyan

$spSelect = (
    'id', 'appId', 'displayName', 'accountEnabled', 'appRoleAssignmentRequired',
    'tags', 'servicePrincipalType', 'description', 'loginUrl',
    'preferredSingleSignOnMode', 'notificationEmailAddresses', 'homepage',
    'replyUrls', 'verifiedPublisher'
) -join ','

$spUri                = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$spSelect&`$top=999"
$allServicePrincipals = Invoke-MgGraphPaged -Uri $spUri

# Build a lookup hashtable: appId → service principal object
$spByAppId = @{}
foreach ($sp in $allServicePrincipals) {
    if ($sp.appId -and -not $spByAppId.ContainsKey($sp.appId)) {
        $spByAppId[$sp.appId] = $sp
    }
}
Write-Host "  Found $($allServicePrincipals.Count) service principal(s)" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# 5. Build permission name cache
#    Resolves permission GUIDs → { Name, Resource, Type }
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/6] Resolving permission definitions..." -ForegroundColor Cyan

# Collect every unique resource-app ID referenced across all registrations
$resourceAppIds = @(
    $applications |
    Where-Object { $_.requiredResourceAccess } |
    ForEach-Object { $_.requiredResourceAccess } |
    ForEach-Object { $_.resourceAppId } |
    Sort-Object -Unique
)

$permissionCache = @{}   # permissionId GUID → @{ Name; Resource; Type }

foreach ($resourceAppId in $resourceAppIds) {
    $resourceSp = $null

    # First check our bulk-fetched SPs
    if ($spByAppId.ContainsKey($resourceAppId)) {
        $existingId = $spByAppId[$resourceAppId].id
        $detail     = Invoke-MgGraphWithRetry -Uri (
            "https://graph.microsoft.com/v1.0/servicePrincipals/$existingId" +
            "?`$select=id,appId,displayName,oauth2PermissionScopes,appRoles"
        )
        if ($detail) { $resourceSp = $detail }
    }

    # Fall back to a filter query
    if (-not $resourceSp) {
        $lookup = Invoke-MgGraphWithRetry -Uri (
            "https://graph.microsoft.com/v1.0/servicePrincipals" +
            "?`$filter=appId eq '$resourceAppId'" +
            "&`$select=id,appId,displayName,oauth2PermissionScopes,appRoles"
        )
        if ($lookup -and $lookup.value) { $resourceSp = $lookup.value[0] }
    }

    if (-not $resourceSp) {
        Write-Verbose "Could not resolve resource app: $resourceAppId"
        continue
    }

    $resourceName = $resourceSp.displayName

    # Cache delegated permission scopes
    if ($resourceSp.oauth2PermissionScopes) {
        foreach ($scope in $resourceSp.oauth2PermissionScopes) {
            if (-not $permissionCache.ContainsKey($scope.id)) {
                $permissionCache[$scope.id] = @{
                    Name     = $scope.value
                    Resource = $resourceName
                    Type     = 'Delegated'
                }
            }
        }
    }

    # Cache application roles
    if ($resourceSp.appRoles) {
        foreach ($role in $resourceSp.appRoles) {
            if (-not $permissionCache.ContainsKey($role.id)) {
                $permissionCache[$role.id] = @{
                    Name     = $role.value
                    Resource = $resourceName
                    Type     = 'Application'
                }
            }
        }
    }
}

Write-Host "  Cached $($permissionCache.Count) permission definition(s)" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
# 6. Process each application
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[6/6] Processing applications..." -ForegroundColor Cyan

$now          = [DateTime]::UtcNow
$auditResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$appTotal     = $applications.Count
$appIndex     = 0

foreach ($app in $applications) {
    $appIndex++
    Write-Progress -Activity 'Auditing applications' `
                   -Status    "$appIndex / $appTotal : $($app.displayName)" `
                   -PercentComplete ([math]::Round(($appIndex / $appTotal) * 100))

    # ── Owners ────────────────────────────────────────────────────────────────
    $ownerList = @()
    try {
        $ownerResponse = Invoke-MgGraphWithRetry -Uri (
            "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners" +
            "?`$select=id,displayName,userPrincipalName,mail"
        )
        if ($ownerResponse -and $ownerResponse.value) {
            $ownerList = @($ownerResponse.value | ForEach-Object {
                if ($_.userPrincipalName) { $_.userPrincipalName }
                elseif ($_.mail)          { "$($_.displayName) <$($_.mail)>" }
                else                      { $_.displayName }
            })
        }
    }
    catch { Write-Verbose "Owners unavailable for '$($app.displayName)': $_" }

    # ── Service principal ─────────────────────────────────────────────────────
    $sp = if ($spByAppId.ContainsKey($app.appId)) { $spByAppId[$app.appId] } else { $null }

    # ── Requested API permissions (from app manifest) ─────────────────────────
    $requestedPerms = if ($app.requiredResourceAccess) {
        Resolve-GraphPermissions -RequiredResourceAccess $app.requiredResourceAccess `
                                 -PermissionCache $permissionCache `
                                 -SpByAppId $spByAppId
    } else { @() }

    # ── Granted permissions (from service principal) ──────────────────────────
    $grantedAppPerms       = [System.Collections.Generic.List[string]]::new()
    $grantedDelegatedPerms = [System.Collections.Generic.List[string]]::new()
    $assignmentCount       = 0

    if ($sp) {
        # Application permissions actually granted to this app (appRoleAssignments FROM the SP)
        try {
            $appGrants = Invoke-MgGraphPaged -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" +
                "?`$select=appRoleId,resourceDisplayName,resourceId&`$top=999"
            )
            foreach ($grant in $appGrants) {
                $perm = $permissionCache[$grant.appRoleId]
                $name = if ($perm) { $perm.Name } else { $grant.appRoleId }
                $grantedAppPerms.Add("$($grant.resourceDisplayName): $name")
            }
        }
        catch { Write-Verbose "App grants unavailable for '$($app.displayName)': $_" }

        # Delegated permissions consented (OAuth2 permission grants)
        try {
            $delegatedGrants = Invoke-MgGraphWithRetry -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/oauth2PermissionGrants" +
                "?`$select=scope,consentType,principalId,resourceId"
            )
            if ($delegatedGrants -and $delegatedGrants.value) {
                foreach ($grant in $delegatedGrants.value) {
                    $resourceName = ($allServicePrincipals |
                        Where-Object { $_.id -eq $grant.resourceId } |
                        Select-Object -First 1).displayName
                    if (-not $resourceName) { $resourceName = $grant.resourceId }

                    $consentLabel = if ($grant.consentType -eq 'AllPrincipals') { 'Admin' } else { 'User' }
                    $scopeNames   = ($grant.scope -split '\s+') | Where-Object { $_ }
                    foreach ($scopeName in $scopeNames) {
                        $grantedDelegatedPerms.Add("${resourceName}: $scopeName [${consentLabel}Consent]")
                    }
                }
            }
        }
        catch { Write-Verbose "Delegated grants unavailable for '$($app.displayName)': $_" }

        # Count of users / groups assigned to this application
        try {
            $assignments = Invoke-MgGraphWithRetry -Uri (
                "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" +
                "?`$select=id&`$top=999"
            )
            if ($assignments -and $assignments.value) {
                $assignmentCount = $assignments.value.Count
                while ($assignments.'@odata.nextLink') {
                    $assignments = Invoke-MgGraphWithRetry -Uri $assignments.'@odata.nextLink'
                    if ($assignments -and $assignments.value) {
                        $assignmentCount += $assignments.value.Count
                    }
                }
            }
        }
        catch { Write-Verbose "Assignment count unavailable for '$($app.displayName)': $_" }
    }

    # ── Client secrets ────────────────────────────────────────────────────────
    $secretDetails = [System.Collections.Generic.List[string]]::new()
    $expiredCreds  = [System.Collections.Generic.List[string]]::new()
    $warnCreds     = [System.Collections.Generic.List[string]]::new()

    foreach ($cred in @($app.passwordCredentials)) {
        if (-not $cred) { continue }
        $label = if ($cred.displayName) { $cred.displayName } else { '(unnamed secret)' }

        if ($cred.endDateTime) {
            $expiry   = [DateTime]$cred.endDateTime
            $daysLeft = [math]::Floor(($expiry - $now).TotalDays)
            $secretDetails.Add("$label | expires $($expiry.ToString('yyyy-MM-dd')) ($daysLeft d)")
            if ($daysLeft -lt 0)                          { $expiredCreds.Add($label) }
            elseif ($daysLeft -le $CredentialWarningDays) { $warnCreds.Add($label)    }
        }
        else {
            $secretDetails.Add("$label | no expiry")
        }
    }

    # ── Certificates ──────────────────────────────────────────────────────────
    $certDetails = [System.Collections.Generic.List[string]]::new()

    foreach ($cert in @($app.keyCredentials)) {
        if (-not $cert) { continue }
        $label = if ($cert.displayName) { $cert.displayName } else { $cert.type }

        if ($cert.endDateTime) {
            $expiry   = [DateTime]$cert.endDateTime
            $daysLeft = [math]::Floor(($expiry - $now).TotalDays)
            $certDetails.Add("$label | expires $($expiry.ToString('yyyy-MM-dd')) ($daysLeft d) | keyId $($cert.keyId)")
            if ($daysLeft -lt 0)                          { $expiredCreds.Add("CERT:$label") }
            elseif ($daysLeft -le $CredentialWarningDays) { $warnCreds.Add("CERT:$label")    }
        }
        else {
            $certDetails.Add("$label | no expiry | keyId $($cert.keyId)")
        }
    }

    # ── Credential status ─────────────────────────────────────────────────────
    $secretCount = @($app.passwordCredentials).Where({ $_ }).Count
    $certCount   = @($app.keyCredentials).Where({ $_ }).Count

    $credStatus = switch ($true) {
        { $expiredCreds.Count -gt 0 }                 { 'EXPIRED';       break }
        { $warnCreds.Count   -gt 0 }                 { 'EXPIRING_SOON'; break }
        { $secretCount -eq 0 -and $certCount -eq 0 } { 'NONE';          break }
        default                                       { 'OK'                  }
    }

    # ── Service-principal properties ──────────────────────────────────────────
    $spTags         = if ($sp -and $sp.tags) { @($sp.tags) } else { @() }
    $visibleToUsers = if ($sp) { -not ($spTags -contains 'HideApp') } else { $null }
    $verifiedPub    = if ($app.verifiedPublisher -and $app.verifiedPublisher.displayName) {
                          $app.verifiedPublisher.displayName
                      } else { '' }

    # ── App roles defined by this application ─────────────────────────────────
    $appRoleNames = if ($app.appRoles) {
        @($app.appRoles | Where-Object { $_.isEnabled } | ForEach-Object { $_.displayName })
    } else { @() }

    # ── Redirect URIs ─────────────────────────────────────────────────────────
    $redirectUris = @()
    if ($app.web          -and $app.web.redirectUris)          { $redirectUris += $app.web.redirectUris          }
    if ($app.spa          -and $app.spa.redirectUris)          { $redirectUris += $app.spa.redirectUris          }
    if ($app.publicClient -and $app.publicClient.redirectUris) { $redirectUris += $app.publicClient.redirectUris }

    # ── Assemble record ───────────────────────────────────────────────────────
    $record = [PSCustomObject][ordered]@{
        # Identity
        DisplayName                 = $app.displayName
        ApplicationClientId         = $app.appId
        ObjectId                    = $app.id
        CreatedDateTime             = $app.createdDateTime
        SignInAudience              = $app.signInAudience
        PublisherDomain             = $app.publisherDomain
        VerifiedPublisher           = $verifiedPub
        Description                 = $app.description
        Notes                       = $app.notes

        # Owners
        Owners                      = $ownerList -join '; '
        OwnerCount                  = $ownerList.Count
        HasNoOwner                  = ($ownerList.Count -eq 0)

        # Service principal / Enterprise App
        ServicePrincipalExists      = [bool]$sp
        ServicePrincipalObjectId    = if ($sp) { $sp.id } else { '' }
        ServicePrincipalType        = if ($sp) { $sp.servicePrincipalType } else { '' }
        EnabledForSignIn            = if ($sp) { $sp.accountEnabled } else { $null }
        AssignmentRequired          = if ($sp) { $sp.appRoleAssignmentRequired } else { $null }
        VisibleToUsers              = $visibleToUsers
        # NOTE: "Allow users to request access?" is not available as a Graph property.
        # Check the Azure portal: Enterprise Apps > [App] > Self service.
        AllowSelfServiceAccess      = 'See portal: Enterprise Apps > Self service'
        SSOMode                     = if ($sp) { $sp.preferredSingleSignOnMode } else { '' }
        LoginUrl                    = if ($sp) { $sp.loginUrl } else { '' }
        Homepage                    = if ($sp) { $sp.homepage } else { '' }
        NotificationEmails          = if ($sp -and $sp.notificationEmailAddresses) {
                                          $sp.notificationEmailAddresses -join '; '
                                      } else { '' }

        # Permissions — requested (app manifest)
        RequestedPermissions        = ($requestedPerms | Sort-Object) -join '; '
        RequestedPermissionCount    = $requestedPerms.Count

        # Permissions — granted / consented
        GrantedAppPermissions       = ($grantedAppPerms    | Sort-Object) -join '; '
        GrantedDelegatedPermissions = ($grantedDelegatedPerms | Sort-Object) -join '; '

        # App roles defined by this app
        AppRolesDefined             = $appRoleNames -join '; '
        AppRolesDefinedCount        = $appRoleNames.Count

        # User / group assignments
        UserGroupAssignmentCount    = $assignmentCount

        # Credentials
        ClientSecretCount           = $secretCount
        ClientSecrets               = $secretDetails -join ' || '
        CertificateCount            = $certCount
        Certificates                = $certDetails   -join ' || '
        CredentialStatus            = $credStatus
        ExpiredCredentials          = $expiredCreds  -join '; '
        ExpiringCredentials         = $warnCreds     -join '; '

        # Misc
        IdentifierUris              = if ($app.identifierUris) { $app.identifierUris -join '; ' } else { '' }
        RedirectUris                = $redirectUris -join '; '
        AppTags                     = if ($app.tags) { $app.tags -join '; ' } else { '' }
        ServicePrincipalTags        = $spTags -join '; '
    }

    $auditResults.Add($record)
}

Write-Progress -Activity 'Auditing applications' -Completed

# ─────────────────────────────────────────────────────────────────────────────
# 7. Export results
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`nExporting results..." -ForegroundColor Cyan

$resultArray = $auditResults.ToArray()

# CSV
$resultArray | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
Write-Host "  CSV  → $OutputCsvPath" -ForegroundColor Green

# JSON (optional)
if ($OutputJsonPath) {
    $resultArray | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputJsonPath -Encoding UTF8
    Write-Host "  JSON → $OutputJsonPath" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. Summary
# ─────────────────────────────────────────────────────────────────────────────
$total          = $resultArray.Count
$noSp           = @($resultArray | Where-Object { -not $_.ServicePrincipalExists }).Count
$signInDisabled = @($resultArray | Where-Object { $_.EnabledForSignIn -eq $false }).Count
$assignmentReqd = @($resultArray | Where-Object { $_.AssignmentRequired -eq $true }).Count
$hiddenFromUsers= @($resultArray | Where-Object { $_.VisibleToUsers -eq $false }).Count
$noOwner        = @($resultArray | Where-Object { $_.HasNoOwner }).Count
$noCreds        = @($resultArray | Where-Object { $_.CredentialStatus -eq 'NONE' }).Count
$expiredCount   = @($resultArray | Where-Object { $_.CredentialStatus -eq 'EXPIRED' }).Count
$expiringCount  = @($resultArray | Where-Object { $_.CredentialStatus -eq 'EXPIRING_SOON' }).Count

$divider = '─' * 48

Write-Host "`n$divider" -ForegroundColor Cyan
Write-Host '  AUDIT SUMMARY' -ForegroundColor Cyan
Write-Host $divider -ForegroundColor Cyan
Write-Host "  Total applications audited     : $total"
Write-Host "  No service principal           : $noSp"
Write-Host "  Sign-in disabled               : $signInDisabled"
Write-Host "  Assignment required            : $assignmentReqd"
Write-Host "  Hidden from My Apps            : $hiddenFromUsers"
Write-Host "  No owners assigned             : $noOwner" -ForegroundColor $(if ($noOwner  -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host "  No credentials (secret/cert)   : $noCreds"
Write-Host "  Credentials EXPIRED            : $expiredCount"  -ForegroundColor $(if ($expiredCount  -gt 0) { 'Red'    } else { 'Gray' })
Write-Host "  Credentials expiring in ${CredentialWarningDays}d   : $expiringCount" -ForegroundColor $(if ($expiringCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host $divider -ForegroundColor Cyan
Write-Host ''

if ($PassThru) {
    return $resultArray
}
