# This script needs to be run as administrator


# enable advanced auditing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "SCENoApplyLegacyAuditPolicy" -Value 1


#region auditLogs

# Account Logon
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
# Account Management
Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
# Detailed Tracking
Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
Auditpol /set /subcategory:"Plug and Play Events" /success:enable 
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enabley
Auditpol /set /subcategory:"Process Termination" /success:disable /failure:disable
Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable
# DS Access
Auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable
# Logon/Logoff
Auditpol /set /subcategory:"Account Lockout" /success:enable
Auditpol /set /subcategory:"Group Membership" /success:enable 
Auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"Logoff" /success:enable 
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"User / Device Claims" /success:disable /failure:disable
# Object Access
Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
Auditpol /set /subcategory:"Central Policy Staging" /success:disable /failure:disable
Auditpol /set /subcategory:"Detailed File Share" /success:enable 
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"File System" /success:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
Auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
Auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"Registry" /success:enable
Auditpol /set /subcategory:"SAM" /success:enable
# Policy Change
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable
Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:disable
# Privilege Use
Auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
# System
Auditpol /set /subcategory:"IPsec Driver" /success:enable
Auditpol /set /subcategory:"Other System Events" /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

#endregion

#region EventLogSizes
wevtutil sl Application /ms:67108864 /rt:false /ab:false
wevtutil sl System /ms:67108864 /rt:false /ab:false
wevtutil sl Security /ms:134217728 /rt:false /ab:false
wevtutil sl 'Windows PowerShell' /ms:67108864 /rt:false /ab:false
wevtutil sl PowerShellCore/Operational /ms:67108864 /rt:false /ab:false


<#
wevtutil gl Application
wevtutil gl System
wevtutil gl Security
wevtutil gl 'Windows PowerShell'
#>
#endregion


#region WindowsPowershellLogging
# Module Logging
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging").EnableModuleLogging -eq 1){
    Write-Host "EnableModuleLogging already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"){
        Write-Host "Powershell Module Logging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames").'*' -eq '*'){
    Write-Host "Module Names logging already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"){
        Write-Host "Powershell Module Logging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"){
        Write-Host "Powershell Module Names registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name '*' -Value '*'
}


# Script Block Logging
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging").EnableScriptBlockLogging -eq 1){
    Write-Host "EnableScriptBlockLogging already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"){
        Write-Host "Powershell Script Block Logging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
}


# Transcription

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription").EnableTranscripting -eq 1){
    Write-Host "EnableTranscripting already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription").EnableInvocationHeader -eq 1){
    Write-Host "EnableInvocationHeader already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription").OutputDirectory -eq 1){
    Write-Host "OutputDirectory already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value 'c:\Logs'
}

#endregion

#region PowershellCoreLogging

# Module Logging
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging").EnableModuleLogging -eq 1){
    Write-Host "EnableModuleLogging already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging"){
        Write-Host "Powershell Module Logging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging" -Name "EnableModuleLogging" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging\ModuleNames").'*' -eq '*'){
    Write-Host "Module Names logging already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging"){
        Write-Host "Powershell Module Logging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging\ModuleNames"){
        Write-Host "Powershell Module Names registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging\ModuleNames"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ModuleLogging\ModuleNames" -Name '*' -Value '*'
}

# Script Block Logging
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ScriptBlockLogging").EnableScriptBlockLogging -eq 1){
    Write-Host "EnableScriptBlockLogging already is on for PowerShell Core"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "PowershellCore registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ScriptBlockLogging"){
        Write-Host "PowershellCore ScriptBlockLogging registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ScriptBlockLogging"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
}

# Transcription

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription").EnableTranscripting -eq 1){
    Write-Host "EnableTranscripting already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription" -Name "EnableTranscripting" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription").EnableInvocationHeader -eq 1){
    Write-Host "EnableInvocationHeader already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription" -Name "EnableInvocationHeader" -Value 1
}

if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription").OutputDirectory -eq 1){
    Write-Host "OutputDirectory already is on"
} else {
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"){
        Write-Host "Powershell registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore"
    }
    if(Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"){
        Write-Host "Powershell Transcription registry key exists"
    } else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\PowerShellCore\Transcription" -Name "OutputDirectory" -Value 'c:\Logs'
}

#endregion







