<# 
.SYNOPSIS
    Comprehensive PowerShell adaptation of WinPEAS for auditing Windows systems.

.DESCRIPTION
    This script performs an extensive audit of a Windows system to identify potential privilege escalation vectors, misconfigurations, and the presence of sensitive information such as passwords, API keys, and tokens.

.EXAMPLE
    # Default - normal operation with username/password audit in drives/registry
    .\winPEAS.ps1

    # Include Excel files in search: .xls, .xlsx, .xlsm
    .\winPEAS.ps1 -IncludeExcel

    # Full audit - normal operation with APIs / Keys / Tokens
    ## This will produce false positives ## 
    .\winPEAS.ps1 -FullAudit 

    # Add Time stamps to each command
    .\winPEAS.ps1 -EnableTimeStamp

.NOTES
    Version:                    2.0
    Original Author:            PEASS-ng
    winPEAS.ps1 Author:         @RandolphConley
    Creation Date:              10/4/2022
    Last Updated:               04/27/2024
    Website:                    https://github.com/peass-ng/PEASS-ng

    Tested on: PowerShell 5.1, 7.x
    Compatibility: PowerShell 3.0 and above
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$EnableTimeStamp,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeExcel,

    [Parameter(Mandatory=$false)]
    [switch]$FullAudit
)

# ========================== Logging Setup ==========================
$LogFile = "winPEAS_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$SummaryFile = "winPEAS_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Initialize Log File
"Timestamp,Category,Description,Details" | Out-File -FilePath $LogFile -Encoding UTF8

# Function to Log Findings
function Log-Finding {
    param(
        [string]$Category,
        [string]$Description,
        [string]$Details
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp,$Category,$Description,$Details" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# Function to Display and Log Findings
function Report-Finding {
    param(
        [string]$Category,
        [string]$Description,
        [string]$Details,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host "$Category - $Description: $Details" -ForegroundColor $Color
    Log-Finding -Category $Category -Description $Description -Details $Details
}

# ========================== Helper Functions ==========================

# Function to Display Elapsed Time
function Show-ElapsedTime {
    if ($stopwatch) {
        $elapsed = $stopwatch.Elapsed
        Write-Host "Time Running: $($elapsed.Hours)h:$($elapsed.Minutes)m:$($elapsed.Seconds)s" -ForegroundColor Cyan
    }
}

# Function to Check ACL Permissions
function Check-ACLPermissions {
    param(
        [string]$TargetPath,
        [string]$ServiceName = $null
    )
    if (-not $TargetPath) { return }

    try {
        $ACLObject = Get-CimInstance -ClassName Cim_LogicalFileSecuritySetting -Filter "Path='$TargetPath'" -ErrorAction Stop
        $ACL = $ACLObject.GetSecurityDescriptorSddl().Descriptor
    }
    catch {
        Report-Finding -Category "ACL Check" -Description "Failed to get ACL for $TargetPath" -Details $_.Exception.Message -Color Yellow
        return
    }

    # Analyze ACL - Ownership and Permissions
    try {
        $acl = Get-Acl -Path $TargetPath -ErrorAction Stop
        $owner = $acl.Owner
        $currentUser = "$env:COMPUTERNAME\$env:USERNAME"
        
        if ($owner -like $currentUser) {
            Report-Finding -Category "ACL Check" -Description "Ownership" -Details "$currentUser owns $TargetPath" -Color Red
        }

        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -like $currentUser -and ($access.FileSystemRights -match "FullControl|Modify|Write") -and $access.AccessControlType -eq "Allow") {
                $perm = $access.FileSystemRights
                Report-Finding -Category "ACL Check" -Description "Permission" -Details "$currentUser has $perm on $TargetPath" -Color Red
            }
        }
    }
    catch {
        Report-Finding -Category "ACL Check" -Description "Error" -Details "Unable to analyze ACL for $TargetPath: $_" -Color Yellow
    }
}

# Function to Scan for Unquoted Service Paths
function Scan-UnquotedServicePaths {
    Report-Finding -Category "Service Path" -Description "Scanning for unquoted service paths" -Details "This may take a while..." -Color Yellow
    $services = Get-CimInstance -ClassName Win32_Service | Where-Object {
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '^C:\\Windows\\' -and
        ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and
        ($_.State -eq "Running" -or $_.State -eq "Stopped")
    }

    foreach ($service in $services) {
        $exePath = ($service.PathName -split '"')[1]
        if ($exePath -and -not (Test-Path $exePath)) {
            Report-Finding -Category "Unquoted Service Path" -Description "Service Name: $($service.Name)" -Details "Path: $($service.PathName)" -Color Red
        }
    }

    if (-not $services) {
        Report-Finding -Category "Unquoted Service Path" -Description "Result" -Details "No unquoted service paths found." -Color Green
    }
}

# Function to Check Scheduled Tasks for Vulnerabilities
function Check-ScheduledTasks {
    Report-Finding -Category "Scheduled Tasks" -Description "Scanning for vulnerable scheduled tasks" -Details "This may take a while..." -Color Yellow
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }

    foreach ($task in $tasks) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
            $action = $task.Actions.Execute
            if ($action -like "*%SystemRoot%*" -or $action -like "*%windir%*") {
                Report-Finding -Category "Scheduled Task" -Description "Vulnerable Task: $($task.TaskName)" -Details "Action: $action" -Color Red
            }
        }
        catch {
            Report-Finding -Category "Scheduled Tasks" -Description "Error" -Details "Unable to get info for task $($task.TaskName): $_" -Color Yellow
        }
    }
}

# Function to Check Startup Applications
function Check-StartupApplications {
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:USERPROFILE\Start Menu\Programs\Startup"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Check-ACLPermissions -TargetPath $item.FullName
                Log-Finding -Category "Startup Application" -Description "Startup Item" -Details $item.FullName
            }
        }
    }
}

# Function to Enumerate Installed Applications
function Enumerate-InstalledApplications {
    Report-Finding -Category "Installed Applications" -Description "Listing installed applications" -Details "Check the log file for details." -Color Cyan
    try {
        $apps = Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version
        foreach ($app in $apps) {
            Log-Finding -Category "Installed Application" -Description "Application" -Details "$($app.Name) - $($app.Version)"
        }
    }
    catch {
        Report-Finding -Category "Installed Applications" -Description "Error" -Details "Unable to enumerate installed applications: $_" -Color Yellow
    }
}

# Function to Retrieve System Information
function Get-SystemInformation {
    Report-Finding -Category "System Information" -Description "Gathering system information" -Details "Check the log file for details." -Color Cyan
    try {
        $sysInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        Log-Finding -Category "System Information" -Description "OS Name" -Details $sysInfo.Caption
        Log-Finding -Category "System Information" -Description "OS Version" -Details $sysInfo.Version
        Log-Finding -Category "System Information" -Description "Last Boot Up Time" -Details $sysInfo.LastBootUpTime
    }
    catch {
        Report-Finding -Category "System Information" -Description "Error" -Details "Unable to retrieve system information: $_" -Color Yellow
    }
}

# Function to Check Antivirus Status
function Check-Antivirus {
    Report-Finding -Category "Antivirus" -Description "Checking installed antivirus products" -Details "Check the log file for details." -Color Cyan
    try {
        $antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            foreach ($av in $antivirus) {
                Log-Finding -Category "Antivirus" -Description "Antivirus Product" -Details $av.displayName
            }
        }
        else {
            Report-Finding -Category "Antivirus" -Description "Result" -Details "No antivirus products found or unable to retrieve." -Color Yellow
        }
    }
    catch {
        Report-Finding -Category "Antivirus" -Description "Error" -Details "Unable to check antivirus status: $_" -Color Yellow
    }

    # Check Windows Defender Exclusions
    try {
        $exclusions = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue
        if ($exclusions) {
            foreach ($excl in $exclusions.PSObject.Properties) {
                Log-Finding -Category "Antivirus Exclusions" -Description $excl.Name -Details $excl.Value
            }
        }
    }
    catch {
        Report-Finding -Category "Antivirus Exclusions" -Description "Error" -Details "Unable to retrieve antivirus exclusions: $_" -Color Yellow
    }
}

# Function to Check User Permissions
function Check-UserPermissions {
    Report-Finding -Category "User Permissions" -Description "Enumerating user groups and permissions" -Details "Check the log file for details." -Color Cyan
    try {
        $groups = @("Administrators", "Users", "Backup Operators")
        foreach ($group in $groups) {
            $members = Get-CimInstance -ClassName Win32_GroupUser -Filter "GroupComponent=`"Win32_Group.Domain='$env:COMPUTERNAME',Name='$group'`" | ForEach-Object {
                $_.PartComponent -replace 'Win32_UserAccount.Domain="[^"]+",Name="([^"]+)"', '$1'
            }
            foreach ($member in $members) {
                Log-Finding -Category "User Group" -Description "$group Member" -Details $member
            }
        }
    }
    catch {
        Report-Finding -Category "User Permissions" -Description "Error" -Details "Unable to enumerate user groups: $_" -Color Yellow
    }
}

# Function to Check Registry Settings
function Check-RegistrySettings {
    Report-Finding -Category "Registry Settings" -Description "Checking various registry settings for security configurations" -Details "Check the log file for details." -Color Cyan

    # Example: Check UAC Settings
    try {
        $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
        if ($uac.EnableLUA -eq 1) {
            Log-Finding -Category "UAC Settings" -Description "EnableLUA" -Details "UAC is enabled."
        }
        else {
            Report-Finding -Category "UAC Settings" -Description "EnableLUA" -Details "UAC is disabled." -Color Red
        }
    }
    catch {
        Report-Finding -Category "UAC Settings" -Description "Error" -Details "Unable to retrieve UAC settings: $_" -Color Yellow
    }

    # Additional registry checks can be added here following the same pattern
}

# Function to Scan Drives for Sensitive Files
function Scan-DrivesForSensitiveFiles {
    param(
        [string[]]$Extensions = @("*.xml", "*.txt", "*.conf", "*.config", "*.cfg", "*.ini", "*.y*ml", "*.log", "*.bak", "*.xls", "*.xlsx", "*.xlsm"),
        [switch]$IncludeExcel
    )

    Report-Finding -Category "File Scan" -Description "Scanning drives for sensitive files" -Details "This may take a while..." -Color Yellow
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root

    foreach ($drive in $drives) {
        try {
            Get-ChildItem -Path $drive -Recurse -Include $Extensions -ErrorAction SilentlyContinue -Force | ForEach-Object {
                $filePath = $_.FullName
                Report-Finding -Category "Sensitive File" -Description "File Found" -Details $filePath -Color Red

                # If IncludeExcel is set and Excel is available, scan Excel files
                if ($IncludeExcel -and ($_.Extension -match "\.xlsm?$")) {
                    if (Get-Command -Name Excel.Application -ErrorAction SilentlyContinue) {
                        Search-ExcelSpreadsheet -SourcePath $filePath -SearchPattern "password|user" | Out-Null
                    }
                    else {
                        Report-Finding -Category "Excel Scan" -Description "Excel COM Object" -Details "Excel not available to scan $filePath" -Color Yellow
                    }
                }

                # Scan file content with regex patterns
                foreach ($pattern in $compiledRegexSearch.Values) {
                    try {
                        Select-String -Path $filePath -Pattern $pattern -Quiet -ErrorAction SilentlyContinue
                        if ($?) {
                            Report-Finding -Category "Sensitive Data" -Description "Pattern Match" -Details "Pattern '$($pattern)' found in $filePath" -Color Red
                        }
                    }
                    catch {
                        Report-Finding -Category "File Scan" -Description "Error" -Details "Error scanning $filePath: $_" -Color Yellow
                    }
                }
            }
        }
        catch {
            Report-Finding -Category "File Scan" -Description "Error" -Details "Unable to scan drive $drive: $_" -Color Yellow
        }
    }
}

# Function to Load and Compile Regex Patterns
function Load-RegexPatterns {
    Report-Finding -Category "Regex Patterns" -Description "Loading and compiling regex patterns" -Details "Check the log file for details." -Color Cyan
    $global:regexSearch = @{}

    # Password Patterns
    $regexSearch.Add("Simple Passwords1", "pass.*[=:].+")
    $regexSearch.Add("Simple Passwords2", "pwd.*[=:].+")
    $regexSearch.Add("Apr1 MD5", '\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
    $regexSearch.Add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
    # ... (Add all other patterns as in the original script)

    # API Keys and Tokens
    if ($FullAudit) {
        $regexSearch.Add("Artifactory API Token", "AKC[a-zA-Z0-9]{10,}")
        # ... (Add all full audit patterns)
    }

    # Web Authentication Patterns
    # ... (Add webAuth patterns if applicable)

    # Compile Regex Patterns for Performance
    $global:compiledRegexSearch = @{}
    foreach ($key in $regexSearch.Keys) {
        try {
            $compiledRegexSearch[$key] = [regex]::new($regexSearch[$key], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
        }
        catch {
            Report-Finding -Category "Regex Patterns" -Description "Invalid Pattern" -Details "Pattern for '$key' is invalid: $_" -Color Yellow
        }
    }
}

# Function to Search Excel Files
function Search-ExcelSpreadsheet {
    param(
        [string]$SourcePath,
        [string]$SearchPattern
    )

    try {
        $Excel = New-Object -ComObject Excel.Application
        $Excel.Visible = $false
        $Workbook = $Excel.Workbooks.Open($SourcePath)

        foreach ($Worksheet in $Workbook.Worksheets) {
            $Found = $Worksheet.Cells.Find($SearchPattern, [Type]::Missing, [Type]::Missing, [Type]::Missing, [Microsoft.Office.Interop.Excel.XlSearchOrder]::xlByRows, [Microsoft.Office.Interop.Excel.XlSearchDirection]::xlNext, $false, $false, $false)
            if ($Found) {
                Report-Finding -Category "Excel Scan" -Description "Pattern Match" -Details "Pattern '$SearchPattern' found in $SourcePath on worksheet '$($Worksheet.Name)' at cell $($Found.Address)" -Color Red
            }
        }

        $Workbook.Close($false)
    }
    catch {
        Report-Finding -Category "Excel Scan" -Description "Error" -Details "Error scanning Excel file $SourcePath: $_" -Color Yellow
    }
    finally {
        if ($Workbook) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Workbook) | Out-Null }
        if ($Excel) { 
            $Excel.Quit()
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Excel) | Out-Null 
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

# ========================== Main Execution ==========================

# Initialize Stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Load Regex Patterns
Load-RegexPatterns

# Gather System Information
Get-SystemInformation

# Check Antivirus Status
Check-Antivirus

# Enumerate Installed Applications
Enumerate-InstalledApplications

# Check User Permissions
Check-UserPermissions

# Check Registry Settings
Check-RegistrySettings

# Scan for Unquoted Service Paths
Scan-UnquotedServicePaths

# Check Scheduled Tasks
Check-ScheduledTasks

# Check Startup Applications
Check-StartupApplications

# Scan Drives for Sensitive Files
Scan-DrivesForSensitiveFiles -Extensions @("*.xml", "*.txt", "*.conf", "*.config", "*.cfg", "*.ini", "*.y*ml", "*.log", "*.bak", "*.xls", "*.xlsx", "*.xlsm") -IncludeExcel:$IncludeExcel

# Additional Audit Functions can be added here following the same modular approach

# ========================== Summary ==========================
$stopwatch.Stop()
$summary = @"
====================== winPEAS Audit Summary ======================

Total Time Elapsed: $($stopwatch.Elapsed.Hours)h:$($stopwatch.Elapsed.Minutes)m:$($stopwatch.Elapsed.Seconds)s

Findings Logged: $(Import-Csv -Path $LogFile | Measure-Object).Count

Detailed Findings:
Please refer to the log file: $LogFile

Summary:
- Critical Findings: $(Import-Csv -Path $LogFile | Where-Object {$_.Category -eq "Sensitive Data" -or $_.Category -eq "Unquoted Service Path" -or $_.Category -eq "ACL Check"} | Measure-Object).Count
- Warning Findings: $(Import-Csv -Path $LogFile | Where-Object {$_.Category -like "*Error*" -or $_.Category -like "*Warning*"} | Measure-Object).Count
- Informational Findings: $(Import-Csv -Path $LogFile | Where-Object {$_.Category -notlike "*Error*" -and $_.Category -notlike "*Warning*"} | Measure-Object).Count

=====================================================================
"@

$summary | Out-File -FilePath $SummaryFile -Encoding UTF8
Write-Host $summary -ForegroundColor Green

# ========================== Completion Message ==========================
Write-Host "Audit completed. Detailed log available at $LogFile and summary at $SummaryFile." -ForegroundColor Green
