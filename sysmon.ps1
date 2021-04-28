# This script needs to be run as administrator


# download sysmon

# download sysmon config file
Set-Location c:\temp
git clone https://github.com/olafhartong/sysmon-modular.git
Set-Location .\sysmon-modular
. .\Merge-SysmonXml.ps1
Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml

# run sysmon with config file
sysmon.exe -accepteula -i sysmonconfig.xml





