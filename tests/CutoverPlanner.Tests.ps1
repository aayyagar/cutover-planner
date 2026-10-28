#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Run: Invoke-Pester ./tests

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-CutoverPlanner.ps1')
    function New-S { param([string]$Os = 'Windows 11', [string]$Client = 'Browser', [string]$Proto = 'none', [string]$Res = '00000002-0000-0ff1-ce00-000000000000', [string]$Trust = 'Azure AD joined', [bool]$Managed = $true, $Tp = $null, [string[]]$Methods = @('Password'), [int]$Count = 1)
        $s = [pscustomobject]@{ userId = 'u1'; resourceId = $Res; resourceDisplayName = 'Exchange'; clientAppUsed = $Client; authenticationProtocol = $Proto
            deviceDetail = [pscustomobject]@{ operatingSystem = $Os; trustType = $Trust; isManaged = $Managed }; authMethods = $Methods; count = $Count }
        if ($Tp) { $s | Add-Member -NotePropertyName tokenProtectionStatusDetails -NotePropertyValue $Tp }
        $s }
    function New-Reg { param([string[]]$Methods = @(), [bool]$Admin = $false, [string]$Type = 'member', [string]$Id = 'u1')
        [pscustomobject]@{ id = $Id; userPrincipalName = "$Id@contoso.com"; userDisplayName = $Id; userType = $Type; isAdmin = $Admin; methodsRegistered = $Methods } }
}

Describe 'Platform and sign-in classification' {
    It 'parses platforms and versions' {
        (Get-CpPlatform 'Windows 8.1').Version | Should -Be 8.1
        (Get-CpPlatform 'iOS 16.7').Platform | Should -Be 'iOS'
        (Get-CpPlatform 'MacOs 14.5').Platform | Should -Be 'macOS'
        (Get-CpPlatform 'Ubuntu').Platform | Should -Be 'linux'
    }
    It 'finds hard blockers: legacy clients, ROPC and old operating systems' {
        (Get-CpSignInIssue (New-S -Client 'Exchange ActiveSync')).Kind | Should -Be 'Legacy'
        (Get-CpSignInIssue (New-S -Client 'Mobile Apps and Desktop clients' -Proto 'ropc')).Kind | Should -Be 'ROPC'
        (Get-CpSignInIssue (New-S -Os 'Android 13')).Kind | Should -Be 'OldOs'
        (Get-CpSignInIssue (New-S -Os 'iOS 16.7')).Hard | Should -BeTrue
        Get-CpSignInIssue (New-S -Os 'iOS 17.2') | Should -BeNullOrEmpty
    }
    It 'treats device code and Linux as things to plan for, not hard blocks' {
        (Get-CpSignInIssue (New-S -Proto 'deviceCode')).Hard | Should -BeFalse
        (Get-CpSignInIssue (New-S -Os 'Linux')).Kind | Should -Be 'NeedsKey'
    }
}

Describe 'Token Protection' {
    It 'uses the binding status recorded on the sign-in' {
        (Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Tp ([pscustomobject]@{ signInSessionStatus = 'bound'; signInSessionStatusCode = 0 }))).State | Should -Be 'Bound'
        $u = Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Tp ([pscustomobject]@{ signInSessionStatus = 'unbound'; signInSessionStatusCode = 1008 }))
        $u.State | Should -Be 'Unbound'
        $u.Reason | Should -Match 'WAM'
    }
    It 'ignores browsers and resources outside Exchange, SharePoint and Teams' {
        (Get-CpTokenProtection (New-S)).State | Should -Be 'OutOfScope'
        (Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Res '00000003-0000-0000-c000-000000000000')).State | Should -Be 'OutOfScope'
    }
    It 'reports Android and Linux as a coverage gap, and infers from device state when no telemetry exists' {
        (Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Os 'Android 15')).State | Should -Be 'Uncovered'
        (Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Trust '')).State | Should -Be 'Unbound'
        (Get-CpTokenProtection (New-S -Client 'Mobile Apps and Desktop clients' -Os 'iOS 18' -Managed $true)).State | Should -Be 'Bound'
    }
}

Describe 'User readiness and persona' {
    It 'is Ready with a phishing-resistant method and no blockers' {
        $r = Get-CpUserReadiness -Registration (New-Reg -Methods @('windowsHelloForBusiness', 'passKeySynced')) -SignIns @(New-S) -Persona 'InformationWorker'
        $r.Status | Should -Be 'Ready'
        $r.SingleCredential | Should -BeFalse
    }
    It 'needs registration without a phishing-resistant method' {
        (Get-CpUserReadiness -Registration (New-Reg -Methods @('microsoftAuthenticatorPush', 'mobilePhone')) -SignIns @(New-S) -Persona 'InformationWorker').Status | Should -Be 'NeedsRegistration'
    }
    It 'is Blocked by a legacy client even with a passkey' {
        $r = Get-CpUserReadiness -Registration (New-Reg -Methods @('passKeySynced')) -SignIns @((New-S), (New-S -Client 'Exchange ActiveSync')) -Persona 'InformationWorker'
        $r.Status | Should -Be 'Blocked'
        $r.Issues[0].Kind | Should -Be 'Legacy'
    }
    It 'needs a security key on Linux-only devices with Windows Hello alone' {
        (Get-CpUserReadiness -Registration (New-Reg -Methods @('windowsHelloForBusiness')) -SignIns @(New-S -Os 'Linux') -Persona 'ITPro').Status | Should -Be 'NeedsKey'
    }
    It 'assigns personas: break-glass, external, service, admin, group, IT signals' {
        Get-CpPersona -Registration (New-Reg -Id 'bg1') -SignIns @() -GroupPersona @{} -BreakGlass @('bg1') | Should -Be 'BreakGlass'
        Get-CpPersona -Registration (New-Reg -Type 'guest') -SignIns @() -GroupPersona @{} -BreakGlass @() | Should -Be 'External'
        Get-CpPersona -Registration (New-Reg) -SignIns @(New-S -Proto 'ropc') -GroupPersona @{} -BreakGlass @() | Should -Be 'Service'
        Get-CpPersona -Registration (New-Reg -Admin $true) -SignIns @(New-S) -GroupPersona @{} -BreakGlass @() | Should -Be 'Admin'
        Get-CpPersona -Registration (New-Reg) -SignIns @(New-S) -GroupPersona @{ u1 = 'Frontline' } -BreakGlass @() | Should -Be 'Frontline'
        Get-CpPersona -Registration (New-Reg) -SignIns @(New-S -Res '797f4846-ba00-4fd7-ba43-dac1f8f63013') -GroupPersona @{} -BreakGlass @() | Should -Be 'ITPro'
        Get-CpPersona -Registration (New-Reg) -SignIns @(New-S) -GroupPersona @{} -BreakGlass @() | Should -Be 'InformationWorker'
    }
}

Describe 'Scheduling' {
    It 'keeps communications off weekends and never before the programme starts' {
        $start = [datetime]'2026-11-02'
        $c = @(New-CpCommsSchedule -Enforce ([datetime]'2026-12-08') -Start $start -Type 'Users' -Audience 'x')
        $c.Count | Should -Be 7
        foreach ($e in $c) { ([datetime]$e.Date).DayOfWeek | Should -Not -BeIn @('Saturday', 'Sunday'); [datetime]$e.Date | Should -BeGreaterOrEqual $start }
        ($c | Where-Object Offset -eq 0).Date | Should -Be '2026-12-08'
    }
    It 'folds long calendar lines to 75 octets' {
        $f = Format-CpIcsLine ('DESCRIPTION:' + ('x' * 200))
        foreach ($l in ($f -split "`r`n" | Where-Object { $_ })) { [Text.Encoding]::UTF8.GetByteCount($l) | Should -BeLessOrEqual 75 }
    }
}

Describe 'Demo plan' {
    It 'produces readiness, ordered waves, a calendar and policies' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("cp-test-" + [guid]::NewGuid())
        $run = Invoke-CutoverPlanner -Demo $true -OutputPath $out -StartDate ([datetime]'2026-11-02')
        $s = $run.Report.Summary
        $s.Users | Should -Be 420
        $s.Ready | Should -Be 168
        $s.LockedOutIfEnforcedToday | Should -Be 252
        $w = @($run.Report.Waves)
        $w[0].Type | Should -Be 'Pilot'
        $w[1].Name | Should -Be 'Admins'
        for ($i = 1; $i -lt $w.Count; $i++) { [datetime]$w[$i].Enforce | Should -BeGreaterThan ([datetime]$w[$i - 1].Enforce) }
        foreach ($x in $w) { ([datetime]$x.Enforce).DayOfWeek | Should -Be 'Tuesday' }
        $users = $run.Analysis.Users
        @($users | Where-Object { $_.Persona -eq 'BreakGlass' -and $_.Wave -ne $null }).Count | Should -Be 0
        @($users | Where-Object { $_.Status -eq 'Blocked' -and $_.Wave -ne $null }).Count | Should -Be 0
        foreach ($f in 'index.html', 'cutover-plan.md', 'cutover-plan.json', 'readiness.csv', 'waves.csv', 'blockers.csv', 'communications.ics') { Join-Path $out $f | Should -Exist }
        $p = Get-Content (Join-Path $out 'policies/W01-require-phishing-resistant-mfa.json') -Raw | ConvertFrom-Json
        $p.state | Should -Be 'enabledForReportingButNotEnforced'
        $p.grantControls.authenticationStrength.id | Should -Be '00000000-0000-0000-0000-000000000004'
        $p.conditions.users.excludeGroups | Should -Contain '{{BREAK_GLASS_GROUP_ID}}'
        Remove-Item $out -Recurse -Force
    }
}
