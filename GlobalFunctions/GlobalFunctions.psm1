<#
    .Synopsis
    PowerShell module for all global functions

    .Description
    This module contains all functions used by PowerShell scripts authored by the Exchange Team

    Author: Thomas Stensitzki
    
    Version 1.2, 2015-07-17

    Use the following code to import the module in PowerShell scripts

        Import-Module GlobalFunctions

    Make sure that the file path to the PowerShell module has been added to the persistent list of PowerShell module paths using the Set-PersistentPSModulePath.ps1 script.

    .NOTES 
    Requirements 
    - Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2

    Revision History 
    -------------------------------------------------------------------------------- 
    1.0      Initial release
    1.1      Write to Event log added, send log file added
    1.2      CopyFile added
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

    .WriteEventLog
    Write an event log entry to the local computer event log

    .Purge
    Method to purge log files older than log file retentionin days

    .SendLogFile
    Send the current logger log file as an email attachment

    .PARAMETER ScriptRoot
    The script folder the referencing script is being executing in. 
    Example: $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

    .PARAMETER ScriptName
    The name of the script referencing the function. This name is used for Windows event log purposes
    Default = MyScriptName
    Example: $ScriptName = $MyInvocation.MyCommand.Name

    .PARAMETER LogFolder
    Name of the log files folder 
    Default = logs

    .PARAMETER FileName
    Name pattern for the log file names. This parameter is using utilizing the datetiem format notation
    Default = \LO\G-yyyyMMdd.lo\g

    .PARAMETER TimeFormat
    DateTime format to be used as a line prefix when appending messages to the log file
    Default = yyyy-MM-dd HH:mm

    .PARAMETER LogFileRetention
    Retention period in days for expired log files
    Default = 30

    .PARAMETER EventLogName
    Name of the Windows Event Log events are written to.
    Default = Application

    .EXAMPLE
    # Instantiate a new logger object using a log time renttion of 14 days
    $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
    $logger = New-Logger -ScriptRoot $ScriptDir -ScriptName $ScriptName -LogFileRetention 14
    
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
    $logger.SendLogFile("sender@mcsmemail.de", "recipient@mcsmemail.de", "smtpserver.mcsmemail.de")

    .EXAMPLE
    # Purge log files
    $logger.Purge()

#>
function New-Logger {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptRoot,
        [string]$ScriptName = "MyScriptName",
        [string]$LogFolder = "logs",
        [string]$FileName = "\LO\G-yyyyMMdd.lo\g",
        [string]$TimeFormat = "yyyy-MM-dd HH:mm",
        [int]$LogFileRetention = 30,
        [string]$EventLogName = "Application"
    )
    # create logger object
    $logger = New-Object PSCustomObject
    # add logger properties
    $logger | Add-Member -MemberType NoteProperty -Name ScriptRoot -Value $ScriptRoot
    $logger | Add-Member -MemberType NoteProperty -Name ScriptName -Value $ScriptName
    $logger | Add-Member -MemberType NoteProperty -Name LogFolder -Value $LogFolder
    $logger | Add-Member -MemberType NoteProperty -Name FileName -Value $FileName
    $logger | Add-Member -MemberType NoteProperty -Name TimeFormat -Value $TimeFormat
    $logger | Add-Member -MemberType NoteProperty -Name LogFileRetention -Value $LogFileRetention
    $logger | Add-Member -MemberType NoteProperty -Name EventLogName -Value $EventLogName
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
    # WRITEEVENTLOG
    # Script method to write messages to event log
    $logger | Add-Member -MemberType ScriptMethod -Name WriteEventLog {
        param (
            [Parameter(Mandatory=$true)]
            [string]$Message,
            [int]$Severity = 0 
        )
        try {
            # Create new event log source first. Without event log source we cannot write to event log
            New-EventLog -LogName $this.EventLogName -Source $this.ScriptName

             # map severity code to string value
            switch($Severity) {
                1 { [string]$SeverityString = "Error" }
                2 { [string]$SeverityString = "Warning" }
                default { [string]$SeverityString = "Information" } #0
            }

            Write-EventLog -LogName $this.EventLogName -Source $this.ScriptName -EntryType $SeverityString  -EventId $Severity -Message $Message             
        }
        catch {
            $this.Write("Error writing to event log. Error: $($Error)")           
        }
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
    # COPYFILE
    # Script method to copy a file to sub folder
    $logger | Add-Member -MemberType ScriptMethod -Name CopyFile {
        param (
            [Parameter(Mandatory=$true)]
            [string]$SourceFilePath,
            [Parameter(Mandatory=$true)]
            [string]$RepositoryFolderName
        )
        try {
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $RepositoryFolderName
            [string]$sourceFileName = Split-Path -Path $SourceFilePath -Leaf

            # check if repository directory exists
            if(!(Test-Path -Path $folderPath)) {
                # create log directory
                New-Item -Path $folderPath -ItemType Directory | Out-Null
                $this.Write("$($folderPath) folder created")
            }            

            if(Test-Path -Path $SourceFilePath) {
                $this.Write("Moving $($SourceFilePath) to $(Join-Path -Path $folderPath -ChildPath $sourceFileName)")
                Move-Item -Path $SourceFilePath -Destination (Join-Path -Path $folderPath -ChildPath $sourceFileName)
            }
            else {
                $this.Write("$($folderPath) does not exist and cannot be copied",2)
            }
        }
        catch {}
    }
    # SENDLOGFILE
    # Script method to send log file via email
    $logger | Add-Member -MemberType ScriptMethod -Name SendLogFile {
        param (
            [Parameter(Mandatory=$true)]
            [string]$From,
            [Parameter(Mandatory=$true)]
            [string]$To,
            [Parameter(Mandatory=$true)]
            [string]$SmtpServer
        )
        try {
            [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
            [string]$file = (Get-Date -Format $this.FileName)
            [string]$filePath = Join-Path -Path $folderPath -ChildPath $file

            [string]$subject = "Requested Log File ($($this.ScriptName))"
            [string]$body = "<html>
                <body>
                    <font size=""1"" face=""Arial,sans-serif"">
                    <p2>Please find the requested log file $($filePath) attached to this email.</p>
                    </font>
                </body>"

            # Write mail action to log file first
            $this.Write("Sending log file from $($From) to $($To) via $($SmtpServer)")

            # Send mail message
            Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $subject -Body $body -BodyAsHtml -Attachments $filePath
        }
        catch {}
    }
    # return object
    return $logger
}

<# 
    .SYNOPSIS
    Sends an email to given recipient

    .DESCRIPTION
    This function is an encapsulation for the Send-MailMessage cmdlet to utilize a common parameter set

    .PARAMETER From
    Email address of the sender

    .PARAMETER To
    Email address of the recipient

    .PARAMETER Subject
    Email subject
   
    .PARAMETER MessageBody
    HTML message body

    .PARAMETER SMTPServer
    SMTP Server for relaying the message

    .EXAMPLE
    # Send an email
    Send-Mail -From sender@mcsmemail.de -To recipient@mcsmemail.de -Subject "My message subject" -MessageBody $SomeBodyVariable -SMTPServer myserver.mcsmemail.de
#>
function Send-Mail {
    param (
        [Parameter(Mandatory=$true)]
        [string]$From,
        [Parameter(Mandatory=$true)]
        [string]$To,
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        [Parameter(Mandatory=$true)]
        [string]$MessageBody,
        [Parameter(Mandatory=$true)]
        [string]$SMTPServer
    )
    try {
        Send-MailMessage -From $From -To $To -SmtpServer $SMTPServer -BodyAsHtml $MessageBody -Subject $Subject 
    }
    catch {}
}

# Exported functions
# --------------------------------------------------
Export-ModuleMember -Function Test-Module
Export-ModuleMember -Function Write-Log
Export-ModuleMember -Function New-Logger
Export-ModuleMember -Function Send-Mail