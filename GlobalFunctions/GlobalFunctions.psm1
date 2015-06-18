<#
    .Synopsis
    PowerShell module for all global functions

    .Description
    This module contains all functions used by PowerShell scripts authored by the Exchange Team

    Author: Thomas Stensitzki

    Version 1.0, 2015-06-10

    Use the following code to import the module in PowerShell scripts

        Import-Module GlobalFunctions

    Make sure that the file path to the PowerShell module has been added to the persistent list of PowerShell module paths using the Set-PersistentPSModulePath.ps1 script.

    .NOTES 
    Requirements 
    - Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2

    Revision History 
    -------------------------------------------------------------------------------- 
    1.0      Initial release
#>

<# 
    .SYNOPSIS
    Output some text to the command line for testing.

    .DESCRIPTION
    Just for testing purposes

    .PARAMETER Test
    Switch to output text to the command line

    .EXAMPLE
    # Write output to the command line
    Test-Module -Test
#>
function Test-Module {
    param(
        [switch]$Test
    )
    if($Test) {
        Write-Host "Module Test"
    }
}


<# 
    .SYNOPSIS
    Log file logger object to write and purge log files

    .DESCRIPTION
    Function that returns an object to write an purge logfiles. The object creates a new
    log folder as a child object to the script execution folder. The log file folder
    name can be set, default is "logs". If the folder does not exist it will be created.

    Severity levels supported are:
    0 : Info (default)
    1 : Error
    2 : Warning

    The default retnetion time for log files is 30 days.

    .Write
    Method to write messages with a given severity level to a log file

    .Purge
    Method to purge log files older than log file retentionin days

    .PARAMETER ScriptRoot
    The script folder the referencing script is being execting in. 
    Example: Split-Path $script:MyInvocation.MyCommand.Path

    .PARAMETER LogFolder
    Name of the log files folder 
    Default = logs

    .PARAMETER Filename
    Name pattern for the log file names. This parameter is using utilizing the datetiem format notation
    Default = \LO\G-yyyyMMdd.lo\g

    .PARAMETER TimeFormat
    DateTime format to be used as a line prefix when appending messages to the log file
    Default = yyyy-MM-dd HH:mm

    .PARAMETER LogFileRetention
    Retention period in days for expired log files
    Default = 30

    .EXAMPLE
    # Instantiate a new logger object using a log time renttion of 14 days
    $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
    $logger = New-Logger -ScriptRoot $ScriptDir -LogFileRetention 14
    
    .EXAMPLE
    # Write a new informational message to the log
    $logger.Write("My informational message")

    .EXAMPLE
    # Write a new error message to the log
    $logger.Write("My critical error", 1)

    .EXAMPLE
    # Write a new warning message to the log
    $logger.Write("My standard warning", 2)

    .EXAMPLE
    # Purge log files
    $logger.Purge()

#>
function New-Logger {
    param(
        [string]$ScriptRoot,
        [string]$LogFolder = "logs",
        [string]$FileName = "\LO\G-yyyyMMdd.lo\g",
        [string]$TimeFormat = "yyyy-MM-dd HH:mm",
        [int]$LogFileRetention = 30
    )
    # create logger object
    $logger = New-Object PSCustomObject
    # add logger properties
    $logger | Add-Member -MemberType NoteProperty -Name ScriptRoot -Value $ScriptRoot
    $logger | Add-Member -MemberType NoteProperty -Name LogFolder -Value $LogFolder
    $logger | Add-Member -MemberType NoteProperty -Name FileName -Value $FileName
    $logger | Add-Member -MemberType NoteProperty -Name TimeFormat -Value $TimeFormat
    $logger | Add-Member -MemberType NoteProperty -Name LogFileRetention -Value $LogFileRetention
    # add logger script methods
    # WRITE
    # Script method to write log messages to disk
    $logger | Add-Member -MemberType ScriptMethod -Name Write {
        param (
            [Parameter(Mandatory=$true)]
            [string]$Message,
            [int]$Severity = 0
        )
        try {
            [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
            [string]$file = (Get-Date -Format $this.FileName)
            [string]$filePath = Join-Path -Path $folderPath -ChildPath $file
            # log file line prefix
            $prefix = "$($timeStamp):"

            # map severity code to string value
            switch($Severity) {
                1 { [string]$SeverityString = "Error" }
                2 { [string]$SeverityString = "Warning" }
                default { [string]$SeverityString = "Info" } #0
            }

            # check if log directory exists
            if(!(Test-Path -Path $folderPath)) {
                # create log directory
                New-Item -Path $folderPath -ItemType Directory | Out-Null
            }

            # define log line columns
            $col1 = $($prefix)
            $col2 = ([string]$PID).PadRight(10).Substring(0,10)
            $col3 = ([string]$SeverityString).PadRight(8).Substring(0,8)
            $col4 = $($Message)

            # check, if file exists
            if(!(Test-Path -Path $filePath)) {
                $line = "$($prefix) LOG FILE CREATED ##############################`r`n"
                New-Item -Path $filePath -ItemType File -Value $line -Force | Out-Null
                $line ="TIMESTAMP       : PROCESS ID - SEVERITY - MESSAGE"
                Add-Content -Path $filePath -Value $line
            }
            # write message to file
            $line = "$($prefix) $($col2) - $($col3) - $($col4)"
            Add-Content -Path $filePath -Value $line               
        }
        catch {}
    }
    # PURGE
    # Script method to purge aged log files from disk
    $logger | Add-Member -MemberType ScriptMethod -Name Purge {
        param (
            [switch]$Detailed
        )
        [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
        [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
        try {
            # fetch list of log files
            $logFiles = Get-ChildItem -Path $folderPath | ?{$_.LastWriteTimeUtc.Date -le ([datetime]::UtcNow.AddDays(-($this.LogFileRetention))).Date}
            # write summary to log file
            $this.Write("Deleting $($logFiles.Count) log files older than $($this.LogFileRetention) days")

            foreach($file in $logFiles) {
                Remove-Item $file.FullName -Confirm:$false
            }
        }
        catch {}

    }
    # return object
    return $logger
}

# Exported functions
# --------------------------------------------------
Export-ModuleMember -Function Test-Module
Export-ModuleMember -Function New-Logger