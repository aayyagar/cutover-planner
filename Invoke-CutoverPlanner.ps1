<#
.SYNOPSIS
    Phishing-Resistant Cutover Planner - simulates enforcing passkeys (phishing-resistant MFA) and
    Token Protection, shows who would be locked out and why, and builds a wave-by-wave rollout plan
    with a communications calendar and report-only Conditional Access policies.

.DESCRIPTION
    Before you require phishing-resistant MFA (passkeys, FIDO2 keys, Windows Hello for Business,
    Platform SSO) or Token Protection (device-bound sign-in sessions), you need to know:
      * who has registered a phishing-resistant method, and who would be locked out,
      * which apps, protocols and devices can't take part yet (legacy clients, ROPC scripts, device
        code flow, unsupported OS versions, unregistered or unmanaged devices),
      * in what order to roll out so the help desk isn't overwhelmed.

    The planner reads Microsoft Graph's authentication-method registration report and 30 days of
    sign-in logs, including the tokenProtectionStatusDetails each sign-in recorded, and produces:
      * a readiness assessment per user, persona and platform, with a fix list of blockers,
      * waves sized to your help desk capacity, ordered the way Microsoft's deployment guidance
        recommends (pilot, admins, then personas), each with dates and ticket estimates,
      * a communications countdown per wave (60 days to enforcement) as an .ics calendar,
      * report-only Conditional Access policies per wave, in the same JSON format as the
        Conditional Access Policy Library, ready to test with Policy Replay.

    It is READ-ONLY. It never registers methods, changes policies or contacts users.

.PARAMETER Demo
    Plan the bundled fictional Contoso tenant. Needs no connections.

.PARAMETER InputPath
    Plan from an offline snapshot (same format as demo/sample-tenant.json).

.PARAMETER PersonaGroups
    Hashtable of persona -> group object ID, for example @{ ITPro = '<id>'; Frontline = '<id>'; Regulated = '<id>' }.
    Users not in a group get a persona from their activity (admins, IT pros) or become information workers.

.PARAMETER BreakGlassUpn
    Break-glass accounts to exclude from every wave (they keep their own FIDO2 keys and exclusions).

.PARAMETER StartDate
    Programme start (registration campaign and first communications). Default: next Monday.

.PARAMETER HelpdeskTicketsPerWeek
    Extra tickets the help desk can absorb per week. Waves are sized to stay under it. Default 40.

.PARAMETER WaveIntervalDays
    Days between enforcement dates. Default 14.

.PARAMETER PilotSize
    Maximum users in the pilot wave. Default 25.

.PARAMETER Days
    Days of sign-ins to read when collecting from Graph. Default 30.

.PARAMETER OutputPath
    Plan folder. Default .\CutoverPlan_<timestamp>

.EXAMPLE
    .\Invoke-CutoverPlanner.ps1 -Demo

.EXAMPLE
    Connect-MgGraph -Scopes AuditLog.Read.All,UserAuthenticationMethod.Read.All,User.Read.All,GroupMember.Read.All
    .\Invoke-CutoverPlanner.ps1 -PersonaGroups @{ Frontline = '<group id>' } -BreakGlassUpn breakglass01@contoso.onmicrosoft.com

.NOTES
    Version : 1.0.0
    Requires: PowerShell 7+
    License : MIT
    Author  : Akhilesh Ayyagari
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Demo,
    [string]$InputPath,
    [hashtable]$PersonaGroups = @{},
    [string[]]$BreakGlassUpn = @(),
    [datetime]$StartDate,
    [ValidateRange(1, 10000)][int]$HelpdeskTicketsPerWeek = 40,
    [ValidateRange(7, 60)][int]$WaveIntervalDays = 14,
    [ValidateRange(1, 500)][int]$PilotSize = 25,
    [ValidateRange(1, 30)][int]$Days = 30,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$script:CpVersion = '1.0.0'

# Registered methods (userRegistrationDetails.methodsRegistered) that satisfy phishing-resistant MFA.
$script:PhishingResistantMethods = @('fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello', 'passKeySynced', 'macOsSecureEnclaveKey', 'platformCredential', 'x509CertificateMultiFactor')
$script:MethodNames = @{
    fido2SecurityKey = 'FIDO2 security key'; windowsHelloForBusiness = 'Windows Hello for Business'; passKeyDeviceBound = 'Device-bound passkey'
    passKeyDeviceBoundAuthenticator = 'Passkey in Microsoft Authenticator'; passKeyDeviceBoundWindowsHello = 'Microsoft Entra passkey on Windows'
    passKeySynced = 'Synced passkey'; macOsSecureEnclaveKey = 'Platform SSO (Secure Enclave)'; platformCredential = 'Platform credential'
    x509CertificateMultiFactor = 'Certificate-based authentication'
}
# Token Protection applies to native clients of these resources (Microsoft's deployment guide).
$script:TokenProtectionResources = @{
    '00000002-0000-0ff1-ce00-000000000000' = 'Exchange Online'; '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'; '9cdead84-a844-4324-93f2-b2e6bb768d07' = 'Azure Virtual Desktop'
    '0af06dc6-e4b5-4f28-818e-e78e62d137a5' = 'Windows 365'; '270efc09-cd0d-444b-a71f-39af4910ec45' = 'Windows Cloud Login'
}
$script:TokenProtectionCodes = @{
    1002 = 'No Microsoft Entra device state (device not registered or joined)'; 1003 = 'Device registration type not supported'
    1005 = 'Unbound for another reason'; 1006 = 'Operating system version not supported'; 1008 = 'Client not using the platform broker (WAM)'
}
# Minimum OS versions for phishing-resistant sign-in from Microsoft's planning guidance.
$script:MinOs = @{ windows = 10; macOS = 13; iOS = 17; android = 14 }
$script:PersonaOrder = @('Admin', 'ITPro', 'InformationWorker', 'Regulated', 'Frontline')
$script:PersonaMethods = @{
    Admin = 'FIDO2 security key or passkey in Microsoft Authenticator (two credentials each)'
    ITPro = 'Passkey in Microsoft Authenticator or FIDO2 key, then Windows Hello for Business / Platform SSO'
    InformationWorker = 'Synced passkey, then Windows Hello for Business, Entra passkey on Windows or Platform SSO'
    Regulated = 'Smart card (certificate-based authentication) or FIDO2 key, plus a passkey as backup'
    Frontline = 'FIDO2 security key registered on their behalf, or a synced passkey on a personal phone'
}
$script:PersonaNames = @{ Admin = 'Admins'; ITPro = 'IT pros and DevOps'; InformationWorker = 'Information workers'; Regulated = 'Highly regulated'; Frontline = 'Frontline workers'; External = 'External users'; Service = 'Service accounts'; BreakGlass = 'Break-glass' }

function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [hashtable]) { if ($Object.ContainsKey($Name)) { return $Object[$Name] } else { return $Default } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value } else { return $Default }
}

# ---------------------------------------------------------------------------------------
# Sign-in classification
# ---------------------------------------------------------------------------------------
function Get-CpPlatform {
    <# Returns platform and major version from deviceDetail.operatingSystem. #>
    param([string]$OperatingSystem)
    $v = 0
    if ($OperatingSystem -match '(\d+)(\.\d+)?') { $v = [double]("$($Matches[1])$($Matches[2])") }
    $p = switch -Regex ($OperatingSystem) {
        '^Windows ?Phone' { 'windowsPhone'; break }
        '^Windows' { 'windows'; break }
        '^Mac' { 'macOS'; break }
        '^iOS|^iPadOS' { 'iOS'; break }
        '^Android' { 'android'; break }
        '^Linux|^Ubuntu|^Debian|^Fedora|^Red ?Hat' { 'linux'; break }
        '^ChromeOS|^Chrome OS' { 'chromeOS'; break }
        default { 'unknown' }
    }
    [pscustomobject]@{ Platform = $p; Version = $v; Label = $(if ($OperatingSystem) { $OperatingSystem } else { 'Unknown OS' }) }
}

function Get-CpSignInIssue {
    <# What stops this sign-in from satisfying phishing-resistant MFA, if anything. #>
    param($SignIn)
    $client = Get-Prop $SignIn 'clientAppUsed' ''
    $proto = Get-Prop $SignIn 'authenticationProtocol' 'none'
    $os = Get-CpPlatform (Get-Prop (Get-Prop $SignIn 'deviceDetail') 'operatingSystem' '')
    if ($client -and $client -notmatch '^(Browser|Mobile Apps and Desktop clients)$') {
        return [pscustomobject]@{ Kind = 'Legacy'; Hard = $true; Key = "Legacy client: $client"; Fix = 'Move this mailbox or device to modern authentication (Outlook, the native mail app with OAuth, or SMTP OAuth). Legacy protocols cannot do any MFA.' }
    }
    if ($proto -eq 'ropc') {
        return [pscustomobject]@{ Kind = 'ROPC'; Hard = $true; Key = "Password grant (ROPC) to $(Get-Prop $SignIn 'resourceDisplayName' 'an app')"; Fix = 'A script or app signs in with a username and password. Move it to a workload identity (managed identity or app with certificate).' }
    }
    if ($proto -eq 'deviceCode') {
        return [pscustomobject]@{ Kind = 'DeviceCode'; Hard = $false; Key = "Device code flow to $(Get-Prop $SignIn 'resourceDisplayName' 'an app')"; Fix = 'Device code flow is phishable. Use interactive browser sign-in (az login, Connect-MgGraph) on a passkey-capable device, then block device code flow.' }
    }
    if ($os.Platform -in $script:MinOs.Keys -and $os.Version -gt 0 -and $os.Version -lt $script:MinOs[$os.Platform]) {
        return [pscustomobject]@{ Kind = 'OldOs'; Hard = $true; Key = "Unsupported OS: $($os.Label)"; Fix = "Upgrade to at least $(@{ windows = 'Windows'; macOS = 'macOS'; iOS = 'iOS'; android = 'Android' }[$os.Platform]) $($script:MinOs[$os.Platform]), replace the device, or use a FIDO2 security key." }
    }
    if ($os.Platform -eq 'linux') {
        return [pscustomobject]@{ Kind = 'NeedsKey'; Hard = $false; Key = 'Linux desktop'; Fix = 'Windows Hello and Platform SSO are not available. Issue a FIDO2 security key or use a cross-device passkey from a phone.' }
    }
    $null
}

function Get-CpTokenProtection {
    <# Token Protection outcome for one sign-in: OutOfScope, Bound or Unbound with a reason. #>
    param($SignIn)
    $res = Get-Prop $SignIn 'resourceId' ''
    if (-not $script:TokenProtectionResources.ContainsKey($res)) { return [pscustomobject]@{ State = 'OutOfScope'; Reason = $null } }
    if ((Get-Prop $SignIn 'clientAppUsed' '') -ne 'Mobile Apps and Desktop clients') { return [pscustomobject]@{ State = 'OutOfScope'; Reason = $null } }
    $dev = Get-Prop $SignIn 'deviceDetail'
    $os = Get-CpPlatform (Get-Prop $dev 'operatingSystem' '')
    # Token Protection only applies to Windows, macOS and iOS/iPadOS. Other platforms are a coverage gap, not a readiness problem.
    if ($os.Platform -notin 'windows', 'macOS', 'iOS') { return [pscustomobject]@{ State = 'Uncovered'; Reason = "Not supported on $($os.Platform)"; Platform = $os.Platform } }
    $tp = Get-Prop $SignIn 'tokenProtectionStatusDetails'
    if ($tp) {
        if ((Get-Prop $tp 'signInSessionStatus' '') -eq 'bound') { return [pscustomobject]@{ State = 'Bound'; Reason = $null } }
        $code = [int](Get-Prop $tp 'signInSessionStatusCode' 1005)
        $why = if ($script:TokenProtectionCodes.ContainsKey($code)) { $script:TokenProtectionCodes[$code] } else { "Unbound (code $code)" }
        return [pscustomobject]@{ State = 'Unbound'; Reason = "$why [$code]" }
    }
    # No binding telemetry: infer from Microsoft's supported platforms.
    switch ($os.Platform) {
        'windows' { if (Get-Prop $dev 'trustType' '') { return [pscustomobject]@{ State = 'Bound'; Reason = $null } } else { return [pscustomobject]@{ State = 'Unbound'; Reason = $script:TokenProtectionCodes[1002] + ' [inferred]' } } }
        { $_ -in 'macOS', 'iOS' } { if (Get-Prop $dev 'isManaged' $false) { return [pscustomobject]@{ State = 'Bound'; Reason = $null } } else { return [pscustomobject]@{ State = 'Unbound'; Reason = 'Apple device not MDM-managed [inferred]' } } }
        default { return [pscustomobject]@{ State = 'Unbound'; Reason = 'Unbound [inferred]' } }
    }
}

# ---------------------------------------------------------------------------------------
# Readiness per user
# ---------------------------------------------------------------------------------------
function Get-CpUserReadiness {
    param($Registration, [object[]]$SignIns, [string]$Persona)
    $methods = @(Get-Prop $Registration 'methodsRegistered' @())
    $pr = @($methods | Where-Object { $_ -in $script:PhishingResistantMethods })
    $issues = @{}; $platforms = @{}; $tpIn = 0; $tpBound = 0; $tpReasons = @{}; $tpUncovered = 0; $tpByPlatform = @{}; $usingPr = 0; $total = 0
    foreach ($s in $SignIns) {
        $n = [int](Get-Prop $s 'count' 1); $total += $n
        $os = Get-CpPlatform (Get-Prop (Get-Prop $s 'deviceDetail') 'operatingSystem' '')
        if ($os.Platform -ne 'unknown') { $platforms[$os.Platform] = 1 + (Get-Prop $platforms $os.Platform 0) }
        if (@(Get-Prop $s 'authMethods' @()) -match 'FIDO2|Windows Hello|Passkey|Secure Enclave|Platform|certificate') { $usingPr += $n }
        $iss = Get-CpSignInIssue $s
        if ($iss) { if ($issues.ContainsKey($iss.Key)) { $issues[$iss.Key].SignIns += $n } else { $issues[$iss.Key] = [pscustomobject]@{ Kind = $iss.Kind; Hard = $iss.Hard; Key = $iss.Key; Fix = $iss.Fix; SignIns = $n } } }
        $tp = Get-CpTokenProtection $s
        if ($tp.State -eq 'Uncovered') { $tpUncovered += $n }
        elseif ($tp.State -ne 'OutOfScope') {
            $tpIn += $n
            if (-not $tpByPlatform.ContainsKey($os.Platform)) { $tpByPlatform[$os.Platform] = @{ In = 0; Bound = 0 } }
            $tpByPlatform[$os.Platform].In += $n
            if ($tp.State -eq 'Bound') { $tpBound += $n; $tpByPlatform[$os.Platform].Bound += $n } else { $tpReasons[$tp.Reason] = $n + (Get-Prop $tpReasons $tp.Reason 0) }
        }
    }
    $issueList = @($issues.Values | Sort-Object SignIns -Descending)
    $hard = @($issueList | Where-Object Hard)
    $linuxOnly = ($platforms.Count -gt 0) -and (@($platforms.Keys | Where-Object { $_ -notin 'linux', 'unknown' }).Count -eq 0)
    $status = if ($hard) { 'Blocked' }
    elseif ($pr.Count -and -not ($linuxOnly -and -not ($pr -contains 'fido2SecurityKey' -or $pr -contains 'passKeyDeviceBoundAuthenticator' -or $pr -contains 'passKeySynced'))) { 'Ready' }
    elseif ($linuxOnly) { 'NeedsKey' }
    else { 'NeedsRegistration' }
    $tpStatus = if (-not $tpIn) { 'OutOfScope' } elseif ($tpBound -eq $tpIn) { 'Ready' } elseif ($tpBound -gt 0) { 'Partial' } else { 'NotReady' }
    [pscustomobject][ordered]@{
        Status = $status; PrMethods = @($pr | ForEach-Object { if ($script:MethodNames.ContainsKey($_)) { $script:MethodNames[$_] } else { $_ } })
        SingleCredential = ($pr.Count -eq 1); UsingPhishingResistant = ($usingPr -gt 0)
        Issues = $issueList; Platforms = @($platforms.Keys | Sort-Object)
        TokenProtection = $tpStatus; TokenProtectionSignIns = $tpIn; TokenProtectionBound = $tpBound; TokenProtectionUncovered = $tpUncovered; TokenProtectionByPlatform = $tpByPlatform
        TokenProtectionReasons = @($tpReasons.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ Reason = $_.Key; SignIns = $_.Value } })
        SignIns = $total
    }
}

function Get-CpPersona {
    param($Registration, [object[]]$SignIns, [hashtable]$GroupPersona, [string[]]$BreakGlass)
    $id = $Registration.id; $upn = Get-Prop $Registration 'userPrincipalName' ''
    if ($upn -in $BreakGlass -or $id -in $BreakGlass) { return 'BreakGlass' }
    if ((Get-Prop $Registration 'userType' 'member') -eq 'guest') { return 'External' }
    if ($SignIns.Count -and -not @($SignIns | Where-Object { (Get-Prop $_ 'authenticationProtocol' 'none') -ne 'ropc' }).Count) { return 'Service' }
    if (Get-Prop $Registration 'isAdmin' $false) { return 'Admin' }
    if ($GroupPersona.ContainsKey($id)) { return $GroupPersona[$id] }
    $itSignals = @($SignIns | Where-Object { (Get-Prop $_ 'resourceId') -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013' -or (Get-Prop $_ 'authenticationProtocol') -eq 'deviceCode' })
    if ($itSignals.Count) { return 'ITPro' }
    'InformationWorker'
}

# ---------------------------------------------------------------------------------------
# Wave planning
# ---------------------------------------------------------------------------------------
function Get-CpWorkday {
    <# Moves a date off the weekend: Saturday -> Friday, Sunday -> Monday. #>
    param([datetime]$Date, [switch]$Forward)
    if ($Date.DayOfWeek -eq 'Saturday') { return $(if ($Forward) { $Date.AddDays(2) } else { $Date.AddDays(-1) }) }
    if ($Date.DayOfWeek -eq 'Sunday') { return $Date.AddDays(1) }
    $Date
}

function Get-CpTuesday { param([datetime]$Date) $d = $Date.Date; while ($d.DayOfWeek -ne 'Tuesday') { $d = $d.AddDays(1) }; $d }

function New-CpCommsSchedule {
    <# Communication countdown for one wave. Microsoft recommends starting 60 days before enforcement. #>
    param([datetime]$Enforce, [datetime]$Start, [string]$Type, [string]$Audience)
    $plan = switch ($Type) {
        'Pilot' { @(@(-14, 'Pilot invitation', 'Email + Teams'), @(-7, 'Register your passkey this week', 'Email'), @(-1, 'Pilot starts tomorrow', 'Teams'), @(0, 'Enforcement on for the pilot', 'Change'), @(7, 'Pilot retrospective', 'Meeting')) }
        'Admin' { @(@(-30, 'Admin accounts move to phishing-resistant sign-in', 'Email'), @(-14, 'Register a FIDO2 key or passkey', 'Email + Teams'), @(-7, 'Final reminder', 'Email'), @(-1, 'Enforcement tomorrow', 'Teams'), @(0, 'Enforcement on', 'Change'), @(7, 'Check help desk tickets', 'Review')) }
        default { @(@(-60, 'Announcement: passwordless sign-in is coming', 'Email + intranet'), @(-30, 'Register your passkey now', 'Email + manager briefing'), @(-14, 'Two weeks to go', 'Email + Teams'), @(-7, 'Final reminder', 'Email'), @(-1, 'Your sign-in changes tomorrow', 'Teams'), @(0, 'Enforcement on', 'Change'), @(7, 'Check help desk tickets', 'Review')) }
    }
    foreach ($p in $plan) {
        $d = $Enforce.AddDays($p[0])
        if ($d -lt $Start) { $d = $Start }
        $d = Get-CpWorkday $d -Forward:($p[0] -ge 0)
        [pscustomobject][ordered]@{ Date = $d.ToString('yyyy-MM-dd'); Offset = $p[0]; Title = $p[1]; Channel = $p[2]; Audience = $Audience }
    }
}

function New-CpWavePlan {
    param([object[]]$Users, [datetime]$Start, [int]$TicketsPerWeek, [int]$IntervalDays, [int]$PilotSize)
    $rate = @{ Ready = 0.05; NeedsRegistration = 0.15; NeedsKey = 0.10 }
    $capacity = [math]::Max(1, [math]::Floor($TicketsPerWeek * $IntervalDays / 7))
    $waves = New-Object System.Collections.Generic.List[object]
    $assigned = @{}
    $pool = @($Users | Where-Object { $_.Persona -notin 'External', 'Service', 'BreakGlass' -and $_.Status -ne 'Blocked' })
    $add = {
        param($name, $type, $persona, $members, [datetime]$enforce)
        $members = @($members | Where-Object { -not $assigned.ContainsKey($_.Id) })
        if (-not $members.Count) { return }
        foreach ($m in $members) { $assigned[$m.Id] = $true }
        $tickets = 0; foreach ($m in $members) { $tickets += $rate[$m.Status] }
        $n = $waves.Count
        $platforms = @($members | ForEach-Object { $_.Platforms } | Where-Object { $_ -and $_ -ne 'unknown' } | Select-Object -Unique | Sort-Object)
        # The Token Protection policy targets only users whose in-scope sign-ins are all bound today, on the platforms they use.
        $tpPlat = @()
        foreach ($pl in 'windows', 'macOS', 'iOS') {
            if ($members | Where-Object { $_.TokenProtection -eq 'Ready' -and $_.TokenProtectionByPlatform.ContainsKey($pl) }) { $tpPlat += $pl }
        }
        $w = [pscustomobject][ordered]@{
            Number = $n; Name = $name; Type = $type; Persona = $persona; Users = $members.Count
            Ready = @($members | Where-Object Status -eq 'Ready').Count; NeedsRegistration = @($members | Where-Object Status -eq 'NeedsRegistration').Count; NeedsKey = @($members | Where-Object Status -eq 'NeedsKey').Count
            TokenProtectionReady = @($members | Where-Object TokenProtection -eq 'Ready').Count; TokenProtectionPlatforms = $tpPlat
            Method = $(if ($script:PersonaMethods.ContainsKey($persona)) { $script:PersonaMethods[$persona] } else { '' })
            Departments = @($members | Group-Object Department | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Name) ($($_.Count))" })
            Platforms = $platforms; Enforce = $enforce.ToString('yyyy-MM-dd'); ExpectedTickets = [int][math]::Ceiling($tickets)
            Comms = @(New-CpCommsSchedule -Enforce $enforce -Start $Start -Type $type -Audience $name)
            MemberIds = @($members | ForEach-Object Id)
        }
        $waves.Add($w)
        foreach ($m in $members) { $m.Wave = $n; $m.WaveName = $name; $m.Enforce = $w.Enforce }
    }

    # Wave 0 - pilot: ready IT pros (Microsoft: start small, measure, then expand).
    $pilotDate = Get-CpTuesday $Start.AddDays(21)
    $pilot = @($pool | Where-Object { $_.Persona -eq 'ITPro' -and $_.Status -eq 'Ready' } | Sort-Object { - $_.SignIns } | Select-Object -First $PilotSize)
    & $add 'Pilot: IT pros' 'Pilot' 'ITPro' $pilot $pilotDate

    # Wave 1 - admins, including those who still need to register (they get a TAP or a key first).
    $next = Get-CpTuesday $pilotDate.AddDays($IntervalDays)
    & $add 'Admins' 'Admin' 'Admin' @($pool | Where-Object Persona -eq 'Admin') $next

    # Then each persona: ready users first, then users who must register (after the 60-day campaign).
    $firstUserWave = Get-CpTuesday $Start.AddDays(60)   # Microsoft: start communications 60 days before enforcement
    $cursor = if ($firstUserWave -gt $next.AddDays($IntervalDays)) { $firstUserWave } else { Get-CpTuesday $next.AddDays($IntervalDays) }
    foreach ($persona in 'ITPro', 'InformationWorker', 'Regulated', 'Frontline') {
        foreach ($st in 'Ready', 'NeedsRegistration', 'NeedsKey') {
            $group = @($pool | Where-Object { $_.Persona -eq $persona -and $_.Status -eq $st -and -not $assigned.ContainsKey($_.Id) } | Sort-Object Department, Upn)
            if (-not $group.Count) { continue }
            $per = [math]::Max(1, [math]::Floor($capacity / $rate[$st]))
            $chunks = [math]::Ceiling($group.Count / $per)
            for ($c = 0; $c -lt $chunks; $c++) {
                $slice = @($group | Select-Object -Skip ($c * $per) -First $per)
                $label = "$($script:PersonaNames[$persona])" + $(switch ($st) { 'Ready' { '' } 'NeedsRegistration' { ' - after registration' } 'NeedsKey' { ' - security key holders' } }) + $(if ($chunks -gt 1) { " ($($c + 1) of $chunks)" } else { '' })
                & $add $label 'Users' $persona $slice $cursor
                $cursor = Get-CpTuesday $cursor.AddDays($IntervalDays)
            }
        }
    }
    [pscustomobject]@{ Waves = $waves.ToArray(); Capacity = $capacity }
}

# ---------------------------------------------------------------------------------------
# Conditional Access policies per wave (report-only, Conditional Access Policy Library format)
# ---------------------------------------------------------------------------------------
function New-CpWavePolicies {
    param($Wave)
    $slug = "W{0:D2}" -f $Wave.Number
    $grp = "{{WAVE_$($Wave.Number)_GROUP_ID}}"
    $pr = [ordered]@{
        displayName = "$slug - Require phishing-resistant MFA - $($Wave.Name)"; state = 'enabledForReportingButNotEnforced'
        conditions = [ordered]@{
            users = [ordered]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @($grp); excludeGroups = @('{{BREAK_GLASS_GROUP_ID}}'); includeRoles = @(); excludeRoles = @() }
            applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @() }
            clientAppTypes = @('all')
        }
        grantControls = [ordered]@{ operator = 'OR'; builtInControls = @(); authenticationStrength = [ordered]@{ id = '00000000-0000-0000-0000-000000000004' } }
        sessionControls = $null
    }
    $tpPlatforms = @($Wave.TokenProtectionPlatforms)
    $tp = $null
    if ($Wave.TokenProtectionReady -gt 0 -and $tpPlatforms.Count) {
        $tp = [ordered]@{
            displayName = "$slug - Require Token Protection - $($Wave.Name)"; state = 'enabledForReportingButNotEnforced'
            conditions = [ordered]@{
                users = [ordered]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @("{{WAVE_$($Wave.Number)_TOKEN_PROTECTION_GROUP_ID}}"); excludeGroups = @('{{BREAK_GLASS_GROUP_ID}}'); includeRoles = @(); excludeRoles = @() }
                applications = [ordered]@{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'); excludeApplications = @() }
                clientAppTypes = @('mobileAppsAndDesktopClients')
                platforms = [ordered]@{ includePlatforms = $tpPlatforms; excludePlatforms = @() }
            }
            grantControls = $null
            sessionControls = [ordered]@{ secureSignInSession = [ordered]@{ isEnabled = $true } }
        }
    }
    [pscustomobject]@{ Slug = $slug; PhishingResistant = $pr; TokenProtection = $tp }
}

# ---------------------------------------------------------------------------------------
# Live collection (read-only Microsoft Graph)
# ---------------------------------------------------------------------------------------
function Invoke-CpGraph {
    param([string]$Uri, [switch]$All)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -Headers @{ ConsistencyLevel = 'eventual' }
        if ($r.PSObject.Properties['value']) { foreach ($v in @($r.value)) { $items.Add($v) } } else { return $r }
        $Uri = if ($All -and $r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
    }
    , $items.ToArray()
}

function Get-CpLiveSnapshot {
    param([hashtable]$PersonaGroups, [string[]]$BreakGlassUpn, [int]$Days)
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Install Microsoft.Graph.Authentication and run Connect-MgGraph first (see README for scopes).' }
    Write-Host '  Reading authentication method registrations...'
    $regs = Invoke-CpGraph -All -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    Write-Host '  Reading users...'
    $users = @{}
    foreach ($u in (Invoke-CpGraph -All -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,department,userType,accountEnabled&$top=999')) {
        if ((Get-Prop $u 'accountEnabled' $true) -eq $false) { continue }
        $users[$u.id] = [ordered]@{ upn = $u.userPrincipalName; displayName = $u.displayName; department = (Get-Prop $u 'department' ''); userType = (Get-Prop $u 'userType' 'Member').ToLower() }
    }
    $pg = [ordered]@{}
    foreach ($k in $PersonaGroups.Keys) {
        $m = Invoke-CpGraph -All -Uri "https://graph.microsoft.com/v1.0/groups/$($PersonaGroups[$k])/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
        $pg[$k] = [ordered]@{ displayName = $k; members = @($m | ForEach-Object id) }
    }
    $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "  Reading $Days days of interactive and non-interactive sign-ins (this can take a while)..."
    $raw = Invoke-CpGraph -All -Uri ("https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $since and status/errorCode eq 0 and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')&`$top=1000")
    $agg = @{}
    foreach ($s in $raw) {
        $methods = @(Get-Prop $s 'authenticationDetails' @() | Where-Object { Get-Prop $_ 'succeeded' $true } | ForEach-Object { Get-Prop $_ 'authenticationMethod' } | Where-Object { $_ })
        $dev = Get-Prop $s 'deviceDetail'
        $tp = Get-Prop $s 'tokenProtectionStatusDetails'
        $o = [ordered]@{ userId = $s.userId; resourceId = (Get-Prop $s 'resourceId' (Get-Prop $s 'appId' '')); resourceDisplayName = (Get-Prop $s 'resourceDisplayName' '')
            clientAppUsed = (Get-Prop $s 'clientAppUsed' ''); deviceDetail = [ordered]@{ operatingSystem = (Get-Prop $dev 'operatingSystem' ''); trustType = (Get-Prop $dev 'trustType' ''); isManaged = [bool](Get-Prop $dev 'isManaged' $false) }
            authenticationProtocol = (Get-Prop $s 'authenticationProtocol' 'none'); authMethods = $methods; count = 1 }
        if ($tp -and (Get-Prop $tp 'signInSessionStatus')) { $o.tokenProtectionStatusDetails = [ordered]@{ signInSessionStatus = $tp.signInSessionStatus; signInSessionStatusCode = (Get-Prop $tp 'signInSessionStatusCode' 0) } }
        $k = ($o | ConvertTo-Json -Compress -Depth 4)
        if ($agg.ContainsKey($k)) { $agg[$k].count++ } else { $agg[$k] = $o }
    }
    [pscustomobject]@{ label = 'Live tenant'; now = (Get-Date).ToUniversalTime().ToString('o'); days = $Days; registrations = $regs
        directory = [pscustomobject]@{ users = $users; personaGroups = $pg; breakGlass = $BreakGlassUpn }; signIns = @($agg.Values) } | ConvertTo-Json -Depth 8 | ConvertFrom-Json
}

# ---------------------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------------------
function Invoke-CpAnalysis {
    param([Parameter(Mandatory)]$Snapshot, [datetime]$Start, [int]$TicketsPerWeek = 40, [int]$IntervalDays = 14, [int]$PilotSize = 25, [string[]]$BreakGlass = @())
    $dir = Get-Prop $Snapshot 'directory'
    $dirUsers = Get-Prop $dir 'users'
    $groupPersona = @{}
    $pgs = Get-Prop $dir 'personaGroups'
    if ($pgs) { foreach ($p in $pgs.PSObject.Properties) { foreach ($m in @(Get-Prop $p.Value 'members' @())) { if (-not $groupPersona.ContainsKey($m)) { $groupPersona[$m] = $p.Name } } } }
    $bg = @($BreakGlass) + @(Get-Prop $dir 'breakGlass' @())
    $byUser = @{}
    foreach ($s in @(Get-Prop $Snapshot 'signIns' @())) { if (-not $byUser.ContainsKey($s.userId)) { $byUser[$s.userId] = New-Object System.Collections.Generic.List[object] }; $byUser[$s.userId].Add($s) }

    $users = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-Prop $Snapshot 'registrations' @())) {
        $si = if ($byUser.ContainsKey($r.id)) { $byUser[$r.id].ToArray() } else { @() }
        $persona = Get-CpPersona -Registration $r -SignIns $si -GroupPersona $groupPersona -BreakGlass $bg
        $rd = Get-CpUserReadiness -Registration $r -SignIns $si -Persona $persona
        $du = if ($dirUsers) { Get-Prop $dirUsers $r.id } else { $null }
        $users.Add([pscustomobject][ordered]@{
                Id = $r.id; Upn = (Get-Prop $r 'userPrincipalName' $r.id); Name = (Get-Prop $r 'userDisplayName' (Get-Prop $du 'displayName' ''))
                Department = (Get-Prop $du 'department' ''); Persona = $persona; IsAdmin = [bool](Get-Prop $r 'isAdmin' $false)
                Status = $rd.Status; PrMethods = $rd.PrMethods; SingleCredential = $rd.SingleCredential; UsingPhishingResistant = $rd.UsingPhishingResistant
                Issues = $rd.Issues; Platforms = $rd.Platforms; TokenProtection = $rd.TokenProtection; TokenProtectionReasons = $rd.TokenProtectionReasons
                TokenProtectionUncovered = $rd.TokenProtectionUncovered; TokenProtectionByPlatform = $rd.TokenProtectionByPlatform
                SignIns = $rd.SignIns; Wave = $null; WaveName = $null; Enforce = $null
            })
    }
    $all = $users.ToArray()
    $script:ProgrammeEvents = @(
        [pscustomobject]@{ Date = $Start.ToString('yyyy-MM-dd'); Offset = 0; Title = 'Kick-off: registration campaign opens for everyone'; Channel = 'Email + intranet + Entra registration campaign'; Audience = 'All users' },
        [pscustomobject]@{ Date = (Get-CpWorkday $Start.AddDays(28)).ToString('yyyy-MM-dd'); Offset = 28; Title = 'Readiness checkpoint: re-run the planner'; Channel = 'Review'; Audience = 'Project team' })
    $plan = New-CpWavePlan -Users $all -Start $Start -TicketsPerWeek $TicketsPerWeek -IntervalDays $IntervalDays -PilotSize $PilotSize
    foreach ($u in $all) {
        if (-not $u.WaveName) {
            $u.WaveName = switch ($u.Persona) { 'External' { 'Not in scope: external user (home tenant)' } 'Service' { 'Not in scope: move to a workload identity' } 'BreakGlass' { 'Excluded: break-glass' } default { if ($u.Status -eq 'Blocked') { 'Remediation first' } else { 'Unassigned' } } }
        }
    }

    # Fix list: blockers ranked by how many people they hold back.
    $fix = @($all | ForEach-Object { $u = $_; $_.Issues | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Kind = $_.Kind; Hard = $_.Hard; Fix = $_.Fix; User = $u.Upn; SignIns = $_.SignIns } } } |
        Group-Object Key | ForEach-Object {
            $g = $_.Group
            [pscustomobject][ordered]@{ Blocker = $_.Name; Kind = $g[0].Kind; Hard = $g[0].Hard; Users = @($g.User | Select-Object -Unique).Count; SignIns = [int](($g | Measure-Object SignIns -Sum).Sum); Fix = $g[0].Fix; Examples = @($g.User | Select-Object -Unique -First 5) }
        } | Sort-Object @{ Expression = 'Hard'; Descending = $true }, @{ Expression = 'Users'; Descending = $true })
    $tpFix = @($all | ForEach-Object { $u = $_; $_.TokenProtectionReasons | ForEach-Object { [pscustomobject]@{ Reason = $_.Reason; User = $u.Upn; SignIns = $_.SignIns } } } |
        Group-Object Reason | ForEach-Object { [pscustomobject][ordered]@{ Reason = $_.Name; Users = @($_.Group.User | Select-Object -Unique).Count; SignIns = [int](($_.Group | Measure-Object SignIns -Sum).Sum) } } | Sort-Object Users -Descending)

    $inScope = @($all | Where-Object { $_.Persona -notin 'External', 'Service', 'BreakGlass' })
    $count = { param($f) @($inScope | Where-Object $f).Count }
    $personaRows = foreach ($p in $script:PersonaOrder) {
        $g = @($inScope | Where-Object Persona -eq $p)
        if (-not $g.Count) { continue }
        [pscustomobject][ordered]@{ Persona = $p; Name = $script:PersonaNames[$p]; Users = $g.Count
            Ready = @($g | Where-Object Status -eq 'Ready').Count; NeedsRegistration = @($g | Where-Object Status -eq 'NeedsRegistration').Count
            NeedsKey = @($g | Where-Object Status -eq 'NeedsKey').Count; Blocked = @($g | Where-Object Status -eq 'Blocked').Count
            TokenProtectionReady = @($g | Where-Object TokenProtection -eq 'Ready').Count }
    }
    $platRows = foreach ($pl in 'windows', 'macOS', 'iOS', 'android', 'linux') {
        $g = @($inScope | Where-Object { $_.Platforms -contains $pl })
        if (-not $g.Count) { continue }
        [pscustomobject][ordered]@{ Platform = $pl; Users = $g.Count; Ready = @($g | Where-Object Status -eq 'Ready').Count
            TokenProtection = $(if ($pl -in 'windows', 'macOS', 'iOS') { 'Supported (native apps)' } else { 'Not supported' }) }
    }
    $n = $inScope.Count
    $summary = [pscustomobject][ordered]@{
        Users = $n; Ready = (& $count { $_.Status -eq 'Ready' }); NeedsRegistration = (& $count { $_.Status -eq 'NeedsRegistration' })
        NeedsKey = (& $count { $_.Status -eq 'NeedsKey' }); Blocked = (& $count { $_.Status -eq 'Blocked' })
        Using = (& $count { $_.UsingPhishingResistant }); SingleCredential = (& $count { $_.Status -eq 'Ready' -and $_.SingleCredential })
        TokenProtectionInScope = (& $count { $_.TokenProtection -ne 'OutOfScope' }); TokenProtectionReady = (& $count { $_.TokenProtection -eq 'Ready' })
        TokenProtectionPartial = (& $count { $_.TokenProtection -eq 'Partial' }); TokenProtectionNotReady = (& $count { $_.TokenProtection -eq 'NotReady' })
        LockedOutIfEnforcedToday = (& $count { $_.Status -ne 'Ready' })
        TokenProtectionUncoveredUsers = (& $count { $_.TokenProtectionUncovered -gt 0 })
        Excluded = [pscustomobject]@{ External = @($all | Where-Object Persona -eq 'External').Count; Service = @($all | Where-Object Persona -eq 'Service').Count; BreakGlass = @($all | Where-Object Persona -eq 'BreakGlass').Count }
        Waves = @($plan.Waves).Count; Capacity = $plan.Capacity
        FinalEnforcement = $(if (@($plan.Waves).Count) { @($plan.Waves)[-1].Enforce } else { $null })
        Start = $Start.ToString('yyyy-MM-dd')
    }
    [pscustomobject]@{ Summary = $summary; Users = $all; Waves = $plan.Waves; FixList = $fix; TokenProtectionFixList = $tpFix; Personas = @($personaRows); Platforms = @($platRows) }
}

# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------
function Format-CpIcsLine {
    <# Folds an iCalendar content line at 75 octets (RFC 5545 section 3.1). #>
    param([string]$Line)
    $enc = [System.Text.Encoding]::UTF8
    if ($enc.GetByteCount($Line) -le 75) { return "$Line`r`n" }
    $out = New-Object System.Text.StringBuilder; $cur = ''; $limit = 75
    foreach ($ch in $Line.ToCharArray()) {
        if ($enc.GetByteCount($cur + $ch) -gt $limit) { [void]$out.Append("$cur`r`n "); $cur = ''; $limit = 74 }
        $cur += $ch
    }
    [void]$out.Append("$cur`r`n")
    $out.ToString()
}

function ConvertTo-CpIcs {
    param([object[]]$Waves, [string]$Label)
    $Waves = @([pscustomobject]@{ Number = '-'; Name = 'Programme'; Users = 'all'; Enforce = '-'; Comms = $script:ProgrammeEvents }) + @($Waves)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("BEGIN:VCALENDAR`r`nVERSION:2.0`r`nPRODID:-//Cutover Planner//Phishing-resistant rollout//EN`r`nCALSCALE:GREGORIAN`r`nX-WR-CALNAME:Phishing-resistant rollout`r`n")
    $i = 0
    foreach ($w in $Waves) {
        foreach ($c in $w.Comms) {
            $i++
            $d = ([datetime]$c.Date).ToString('yyyyMMdd'); $e = ([datetime]$c.Date).AddDays(1).ToString('yyyyMMdd')
            $sum = ("$($w.Name): $($c.Title)" -replace '[,;]', '\$0')
            $desc = ("Wave $($w.Number) ($($w.Users) users). Channel: $($c.Channel). Enforcement date: $($w.Enforce). $Label" -replace '[,;]', '\$0')
            [void]$sb.Append("BEGIN:VEVENT`r`nUID:cutover-$i-$d@cutover-planner`r`nDTSTAMP:$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))`r`nDTSTART;VALUE=DATE:$d`r`nDTEND;VALUE=DATE:$e`r`n")
            [void]$sb.Append((Format-CpIcsLine "SUMMARY:$sum")); [void]$sb.Append((Format-CpIcsLine "DESCRIPTION:$desc")); [void]$sb.Append("END:VEVENT`r`n")
        }
    }
    [void]$sb.Append("END:VCALENDAR`r`n")
    $sb.ToString()
}

function ConvertTo-CpMarkdown {
    param($Report)
    $s = $Report.Summary
    $pct = { param($a, $b) if ($b) { [int][math]::Round(100 * $a / $b) } else { 0 } }
    $sb = New-Object System.Text.StringBuilder
    $L = { param($t = '') [void]$sb.AppendLine($t) }
    & $L "# Phishing-resistant cutover plan"
    & $L
    & $L "$($Report.Scope.Label) · generated $($Report.GeneratedAt) · programme start $($s.Start) · final enforcement $($s.FinalEnforcement)"
    & $L
    & $L "## Where we are"
    & $L
    & $L "- **$($s.Ready) of $($s.Users) users ($(& $pct $s.Ready $s.Users)%)** could sign in today if phishing-resistant MFA were enforced. **$($s.LockedOutIfEnforcedToday)** would be locked out."
    & $L "- $($s.NeedsRegistration) need to register a passkey, $($s.NeedsKey) need a FIDO2 security key, and $($s.Blocked) are blocked by an app, protocol or device that must be fixed first."
    & $L "- $($s.Using) users already sign in with a phishing-resistant method. $($s.SingleCredential) ready users have only one credential; Microsoft recommends at least two."
    & $L "- Token Protection: $($s.TokenProtectionReady) of $($s.TokenProtectionInScope) users with in-scope sign-ins (native Exchange, SharePoint and Teams clients on Windows, macOS and iOS) are fully bound today; $($s.TokenProtectionPartial) are partly bound. $($s.TokenProtectionUncoveredUsers) users also use Android or Linux native clients, which Token Protection can't cover: pair it with device compliance and block unknown platforms."
    & $L "- Not in scope: $($s.Excluded.External) external users, $($s.Excluded.Service) service accounts using user credentials, $($s.Excluded.BreakGlass) break-glass accounts."
    & $L
    & $L "## Fix first"
    & $L
    & $L '| Blocker | Users | Sign-ins | Fix |'
    & $L '|---|---:|---:|---|'
    foreach ($f in @($Report.FixList | Select-Object -First 12)) { & $L "| $($f.Blocker)$(if ($f.Hard) { ' (blocks)' }) | $($f.Users) | $('{0:N0}' -f $f.SignIns) | $($f.Fix) |" }
    & $L
    & $L "## Waves"
    & $L
    & $L '| # | Wave | Users | Enforce | Ready / register / key | Token Protection (users, platforms) | Expected tickets | Recommended method |'
    & $L '|---:|---|---:|---|---|---|---:|---|'
    foreach ($w in $Report.Waves) { & $L "| $($w.Number) | $($w.Name) | $($w.Users) | $($w.Enforce) | $($w.Ready) / $($w.NeedsRegistration) / $($w.NeedsKey) | $($w.TokenProtectionReady)$(if (@($w.TokenProtectionPlatforms).Count) { ', ' + (@($w.TokenProtectionPlatforms) -join ', ') } else { ', not yet' }) | $($w.ExpectedTickets) | $($w.Method) |" }
    & $L
    & $L "Waves are sized to $($Report.Settings.HelpdeskTicketsPerWeek) extra help desk tickets per week, with enforcement every $($Report.Settings.WaveIntervalDays) days. Slow down if ticket volume rises."
    & $L
    & $L "## Communications calendar"
    & $L
    & $L '| Date | Wave | Message | Channel |'
    & $L '|---|---|---|---|'
    foreach ($c in @(@($Report.Programme) + @($Report.Waves | ForEach-Object { $_.Comms }) | Sort-Object Date)) { & $L "| $($c.Date) | $($c.Audience) | $($c.Title) | $($c.Channel) |" }
    & $L
    & $L "## How to run each wave"
    & $L
    & $L "1. Create a security group for the wave from ``waves.csv``, and a second group with the users marked ``TokenProtectionGroup``."
    & $L "2. Import the wave's policies from ``policies/`` (report-only). Replace ``{{WAVE_n_GROUP_ID}}``, ``{{WAVE_n_TOKEN_PROTECTION_GROUP_ID}}`` and ``{{BREAK_GLASS_GROUP_ID}}`` with your group IDs."
    & $L "3. Test them with Policy Replay before switching them on."
    & $L "4. Send the communications on the calendar. Offer a Temporary Access Pass to anyone who can't register."
    & $L "5. On the enforcement date, switch the wave's policies from report-only to on. Review tickets after a week before the next wave."
    $sb.ToString()
}

function Invoke-CutoverPlanner {
    [CmdletBinding()]
    param($Demo, $InputPath, [hashtable]$PersonaGroups = @{}, [string[]]$BreakGlassUpn = @(), $StartDate, $HelpdeskTicketsPerWeek = 40, $WaveIntervalDays = 14, $PilotSize = 25, $Days = 30, $OutputPath)
    $root = $PSScriptRoot; if (-not $root) { $root = (Get-Location).Path }
    if ($Demo -or $InputPath) {
        $file = if ($Demo) { Join-Path $root 'demo/sample-tenant.json' } else { $InputPath }
        $snap = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    else { $snap = Get-CpLiveSnapshot -PersonaGroups $PersonaGroups -BreakGlassUpn $BreakGlassUpn -Days $Days }
    $now = if (Get-Prop $snap 'now') { ([datetime](Get-Prop $snap 'now')).Date } else { (Get-Date).Date }
    if (-not $StartDate) { $StartDate = $now.AddDays(1); while ($StartDate.DayOfWeek -ne 'Monday') { $StartDate = $StartDate.AddDays(1) } }
    $start = ([datetime]$StartDate).Date

    $a = Invoke-CpAnalysis -Snapshot $snap -Start $start -TicketsPerWeek $HelpdeskTicketsPerWeek -IntervalDays $WaveIntervalDays -PilotSize $PilotSize -BreakGlass $BreakGlassUpn
    $report = [pscustomobject][ordered]@{
        Tool = 'Phishing-Resistant Cutover Planner'; Version = $script:CpVersion; GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Scope = [pscustomobject]@{ Label = "$(Get-Prop $snap 'label' 'Tenant'), $((Get-Prop $snap 'days' $Days)) days of sign-ins"; Demo = [bool]$Demo }
        Settings = [pscustomobject]@{ HelpdeskTicketsPerWeek = $HelpdeskTicketsPerWeek; WaveIntervalDays = $WaveIntervalDays; PilotSize = $PilotSize }
        Summary = $a.Summary; Personas = $a.Personas; Platforms = $a.Platforms; FixList = $a.FixList; TokenProtectionFixList = $a.TokenProtectionFixList
        Programme = $script:ProgrammeEvents
        Waves = @($a.Waves | Select-Object * -ExcludeProperty MemberIds)
        Users = @($a.Users | Select-Object Upn, Name, Department, Persona, Status, @{ n = 'Methods'; e = { $_.PrMethods -join ', ' } }, TokenProtection, WaveName, Enforce, @{ n = 'Blockers'; e = { ($_.Issues | ForEach-Object Key) -join '; ' } })
    }

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ('CutoverPlan_' + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    $pol = Join-Path $OutputPath 'policies'
    New-Item -ItemType Directory -Path $pol -Force | Out-Null
    $report | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputPath 'cutover-plan.json') -Encoding UTF8
    $a.Users | Select-Object Upn, Name, Department, Persona, Status, @{ n = 'PhishingResistantMethods'; e = { $_.PrMethods -join '; ' } }, @{ n = 'SingleCredential'; e = { $_.SingleCredential } },
    TokenProtection, @{ n = 'Platforms'; e = { $_.Platforms -join '; ' } }, @{ n = 'Blockers'; e = { ($_.Issues | ForEach-Object Key) -join '; ' } }, Wave, WaveName, Enforce |
        Export-Csv (Join-Path $OutputPath 'readiness.csv') -NoTypeInformation -Encoding UTF8
    @($a.Waves | ForEach-Object { $w = $_; $a.Users | Where-Object Wave -eq $w.Number | ForEach-Object { [pscustomobject]@{ Wave = $w.Number; WaveName = $w.Name; Enforce = $w.Enforce; Upn = $_.Upn; Status = $_.Status; TokenProtectionGroup = ($_.TokenProtection -eq 'Ready') } } }) |
        Export-Csv (Join-Path $OutputPath 'waves.csv') -NoTypeInformation -Encoding UTF8
    $a.FixList | Select-Object Blocker, Kind, Hard, Users, SignIns, Fix, @{ n = 'Examples'; e = { $_.Examples -join '; ' } } | Export-Csv (Join-Path $OutputPath 'blockers.csv') -NoTypeInformation -Encoding UTF8
    Set-Content (Join-Path $OutputPath 'communications.ics') -Value (ConvertTo-CpIcs -Waves $a.Waves -Label $report.Scope.Label) -Encoding UTF8 -NoNewline
    Set-Content (Join-Path $OutputPath 'cutover-plan.md') -Value (ConvertTo-CpMarkdown -Report $report) -Encoding UTF8
    foreach ($w in $a.Waves) {
        $p = New-CpWavePolicies -Wave $w
        $p.PhishingResistant | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $pol "$($p.Slug)-require-phishing-resistant-mfa.json") -Encoding UTF8
        if ($p.TokenProtection) { $p.TokenProtection | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $pol "$($p.Slug)-require-token-protection.json") -Encoding UTF8 }
    }
    $tpl = Join-Path $root 'report/template.html'
    if (Test-Path $tpl) {
        $json = ($report | ConvertTo-Json -Depth 8 -Compress) -replace '</', '<\/'
        Set-Content (Join-Path $OutputPath 'index.html') -Value ((Get-Content $tpl -Raw -Encoding UTF8).Replace('/*__CP_DATA__*/null', $json)) -Encoding UTF8
    }
    $s = $a.Summary
    Write-Host ''
    Write-Host "  Ready today: $($s.Ready) of $($s.Users)  ·  would be locked out: $($s.LockedOutIfEnforcedToday)  ·  blocked by apps/devices: $($s.Blocked)"
    Write-Host "  Token Protection ready: $($s.TokenProtectionReady) of $($s.TokenProtectionInScope) in scope"
    Write-Host "  Plan: $($s.Waves) waves from $($s.Start) to $($s.FinalEnforcement)"
    Write-Host "  Output: $OutputPath"
    [pscustomobject]@{ Report = $report; Analysis = $a; OutputPath = $OutputPath }
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ''
    Write-Host "  Phishing-Resistant Cutover Planner v$script:CpVersion"
    $sd = if ($PSBoundParameters.ContainsKey('StartDate')) { $StartDate } else { $null }
    $null = Invoke-CutoverPlanner -Demo:$Demo -InputPath $InputPath -PersonaGroups $PersonaGroups -BreakGlassUpn $BreakGlassUpn -StartDate $sd `
        -HelpdeskTicketsPerWeek $HelpdeskTicketsPerWeek -WaveIntervalDays $WaveIntervalDays -PilotSize $PilotSize -Days $Days -OutputPath $OutputPath
}
