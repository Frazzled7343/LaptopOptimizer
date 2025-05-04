#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OptimizeLaptop.ps1 - Performance and battery optimization for Windows laptops
.DESCRIPTION
    Optimizes Windows laptops for better performance, battery life, and reduced heat by:
    - Disabling unnecessary background apps
    - Configuring power settings for balanced performance and power savings
    - Disabling resource-intensive scheduled tasks
    - Optimizing visual effects for performance
    - Removing common bloatware applications
.NOTES
    Version:        1.1
    Author:         Frazzled7343
    Creation Date:  2023-11-03
    Last Update:    2025-05-04
    Purpose/Change: Added bloatware removal capability
#>

# Function to write color-coded status messages
function Write-StatusMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Type = "Info" # Info, Success, Warning, Error
    )
    
    switch ($Type) {
        "Success" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        default   { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
    }
}

Write-StatusMessage "Starting laptop optimization process..." -Type "Info"

# 1. Disable background apps globally (Group Policy-style)
Write-StatusMessage "Disabling background apps globally..." -Type "Info"
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    If (-Not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "LetAppsRunInBackground" -Type DWord -Value 2 -ErrorAction Stop
    Write-StatusMessage "Background apps disabled successfully" -Type "Success"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to disable background apps: $errorMessage" -Type "Error"
}

# 2. Set Power Plan to Balanced and enable CPU Power Throttling
Write-StatusMessage "Configuring power settings for optimal battery life and performance..." -Type "Info"
try {
    # Set to Balanced power plan
    powercfg /setactive SCHEME_BALANCED
    
    # Enable Modern Standby (connected standby power model)
    powercfg /setdcvalueindex SCHEME_BALANCED SUB_PROCESSOR PERFBOOSTMODE 3
    powercfg /setacvalueindex SCHEME_BALANCED SUB_PROCESSOR PERFBOOSTMODE 2
    
    # Enable CPU Power Throttling for better thermal management
    powercfg /setdcvalueindex SCHEME_BALANCED SUB_PROCESSOR PERFTHROTTLEMODE 3
    powercfg /setacvalueindex SCHEME_BALANCED SUB_PROCESSOR PERFTHROTTLEMODE 3
    
    # Reduce CPU max processor state on battery to save power
    powercfg /setdcvalueindex SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMAX 70
    
    # Apply the settings
    powercfg /setactive SCHEME_BALANCED
    Write-StatusMessage "Power settings configured successfully" -Type "Success"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to configure power settings: $errorMessage" -Type "Error"
}

# 3. Disable noisy/unnecessary scheduled tasks
Write-StatusMessage "Disabling unnecessary scheduled tasks..." -Type "Info"
$tasksToDisable = @(
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\WindowsUpdate\sih",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
)

foreach ($task in $tasksToDisable) {
    try {
        $taskPath = $task.Substring(0, $task.LastIndexOf("\") + 1)
        $taskName = $task.Split("\")[-1]
        Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
        Write-StatusMessage "Disabled task: $task" -Type "Success"
    } catch [Microsoft.Management.Infrastructure.CimException] {
        Write-StatusMessage "Could not disable $task - task may not exist on this system" -Type "Warning"
    } catch {
        $errorMessage = $_.Exception.Message
        Write-StatusMessage "Error disabling ${task}: $errorMessage" -Type "Warning"
    }
}

# 4. Set Windows to "Adjust for best performance"
Write-StatusMessage "Optimizing visual effects for performance..." -Type "Info"
try {
    $regVisualPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    If (-Not (Test-Path $regVisualPath)) {
        New-Item -Path $regVisualPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regVisualPath -Name "VisualFXSetting" -Type DWord -Value 2 -ErrorAction Stop
    
    # Additional performance tweaks
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90, 0x12, 0x01, 0x80)) -ErrorAction Stop
    
    Write-StatusMessage "Visual effects optimized successfully" -Type "Success"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to optimize visual effects: $errorMessage" -Type "Error"
}

# 5. Disable Startup Programs that aren't essential
Write-StatusMessage "Checking for non-essential startup applications..." -Type "Info"
try {
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | 
                    Select-Object Name, Command, Location, User
    
    Write-StatusMessage "Current startup applications (review these manually):" -Type "Info"
    $startupItems | Format-Table -AutoSize | Out-String | Write-Host
    
    Write-StatusMessage "To disable startup items, use Task Manager > Startup tab" -Type "Info"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Could not retrieve startup applications: $errorMessage" -Type "Warning"
}

# 6. Disable Windows Search Indexing (can be intensive on laptop resources)
Write-StatusMessage "Optimizing Windows Search for lower resource usage..." -Type "Info"
try {
    $searchService = Get-Service -Name "WSearch" -ErrorAction Stop
    if ($searchService.Status -eq "Running") {
        Stop-Service "WSearch" -Force -ErrorAction Stop
        Set-Service "WSearch" -StartupType "Manual" -ErrorAction Stop
        Write-StatusMessage "Windows Search indexing service set to manual startup" -Type "Success"
    } else {
        Write-StatusMessage "Windows Search indexing service already stopped" -Type "Info"
    }
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to modify Windows Search service: $errorMessage" -Type "Warning"
}

# 7. Set disk timeouts for power saving
Write-StatusMessage "Configuring disk timeouts for power saving..." -Type "Info"
try {
    # Set shorter disk timeout on battery (3 minutes)
    powercfg /setdcvalueindex SCHEME_BALANCED SUB_DISK DISKIDLE 180
    # Set longer disk timeout when plugged in (10 minutes)
    powercfg /setacvalueindex SCHEME_BALANCED SUB_DISK DISKIDLE 600
    Write-StatusMessage "Disk power timeouts configured successfully" -Type "Success"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to configure disk timeouts: $errorMessage" -Type "Warning"
}

# 8. Set display timeout for power saving
Write-StatusMessage "Configuring display timeouts for power saving..." -Type "Info"
try {
    # Set display timeout on battery (5 minutes)
    powercfg /setdcvalueindex SCHEME_BALANCED SUB_VIDEO VIDEOIDLE 300
    # Set display timeout when plugged in (10 minutes)
    powercfg /setacvalueindex SCHEME_BALANCED SUB_VIDEO VIDEOIDLE 600
    Write-StatusMessage "Display timeouts configured successfully" -Type "Success"
} catch {
    $errorMessage = $_.Exception.Message
    Write-StatusMessage "Failed to configure display timeouts: $errorMessage" -Type "Warning"
}

# 9. Remove common bloatware applications
Write-StatusMessage "Checking for and removing common bloatware applications..." -Type "Info"

$bloatwareApps = @(
    # Entertainment Apps
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.XboxApp",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    
    # Bing/News/Weather Apps
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingFinance",
    "Microsoft.BingSports",
    
    # Communication Apps (that most people don't use)
    "Microsoft.People",
    "Microsoft.SkypeApp",
    
    # Utility Apps (redundant or rarely used)
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Print3D",
    "Microsoft.OneConnect",
    "Microsoft.Wallet",
    
    # Games
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.WindowsMaps"
)

foreach ($app in $bloatwareApps) {
    try {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction Stop
        Write-StatusMessage "Removed: $app" -Type "Success"
    } catch {
        $errorMessage = $_.Exception.Message
        Write-StatusMessage "Failed or not found: $app" -Type "Warning"
    }
}

# Apply all power settings changes
powercfg /setactive SCHEME_BALANCED

Write-StatusMessage "Laptop optimization complete! A system restart is recommended to apply all changes." -Type "Success"
Write-StatusMessage "Note: Some settings may be overridden by your IT department if this is a managed device." -Type "Info"
