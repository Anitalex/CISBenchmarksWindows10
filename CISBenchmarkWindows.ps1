   
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


wevtutil sl Application /ms:67108864 /rt:false /ab:false
wevtutil sl System /ms:67108864 /rt:false /ab:false
wevtutil sl Security /ms:134217728 /rt:false /ab:false
wevtutil sl 'Windows PowerShell' /ms:67108864 /rt:false /ab:false

<#
wevtutil gl Application
wevtutil gl System
wevtutil gl Security
wevtutil gl 'Windows PowerShell'
#>