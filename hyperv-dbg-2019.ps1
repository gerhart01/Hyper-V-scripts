#
# Argument initialization
#

# Script for configuring debugging Windows Server 2012 R2/ Windows 8.1 using kdvm.dll transport (was ported to virtualization\v2 WMI namespace)
# You need kdvm.dll from Windows Server 2012 R2 Preview build. Copy it to %Systemroot%\system32 dir
# original script was published on osronline.com http://www.osronline.com/showthread.cfm?link=234398 by Jake Oshins
#
# Modified version can be used for 
# Script for synthethic Windows 10/ Windows Server 2019 debugging was updated with information from 
# https://withinrafael.com/2015/02/01/how-to-set-up-synthetic-kernel-debugging-for-hyper-v-virtual-machines/
#
# Script can config guest VM bcdedit settings using powershell direct, and make debug_guest_<VMName>.bat file with WinDBG launching parameters

$nextarg = "none"
$DebugPort = "unassigned" #port number (use in windbg connection string)
$targetcomputer = $env:COMPUTERNAME #name of host OS
$VMName = "" #virtual machine name
$AutoAssign = "false"
$DebugOff = "false"
$ConfigVM = "true"
$RebootVM = "false"
$VMGuid = ""
$NotRewrite = $False # rewrite output file with windbg launching params

function funHelp()
{
$helpText=@"

DESCRIPTION:
NAME: hyperv-dbg-2019.ps1
Displays (and optionally sets) the debugport for synthetic debugging.

PARAMETERS:
-computerName Specifies the name of the computer upon which to run the script
-help         prints help file
-vmname       name of the VM of interest
-port         (optional) ID of the channel to use for debugging
-debugoff     disable guest debugging
-autoassign
-configvm     configure VM using powershell direct
-rebootvm     reboot vm after configuring

SYNTAX:

hyperv-dbg-2019.ps1 [-computerName targetcomputer] [-vmname NameOfVM] [-vmguid GuidOfVM] [-port PortNumber] [-ConfigVM $True|$False] [-RebootVM $True|$False]

.\hyperv-dbg-2019.ps1 -vmname Win10x64_Gen2 -port 50010 -ConfigVm $True -RebootVM $True

"@
$helpText
exit
}


foreach ($argument in $args)
{
    # parse commands with no following arguments
    switch ($argument)
    {
        "?"     {funHelp}
        "help"  {funHelp}
        "-help" {funHelp}
        "/?"    {funHelp}
        "-?"    {funHelp}
        "autoassign"    {$AutoAssign = "true"}
        "-autoassign"   {$AutoAssign = "true"}
        "/autoassign"   {$AutoAssign = "true"}
        "debugoff"        {$DebugOff = "true"}
        "-debugoff"       {$DebugOff = "true"}
        "/debugoff"       {$DebugOff = "true"}
        "ConfigVM"        {$ConfigVM = "true"}
        "-ConfigVM"       {$ConfigVM = "true"}
        "/ConfigVM"       {$ConfigVM = "true"}
        "RebootVM"        {$RebootVM = "true"}
        "-RebootVM"       {$RebootVM = "true"}
        "/RebootVM"       {$RebootVM = "true"}
        default {}
    }

    # parse values that followed a switch

    switch ($nextarg)
    {
        "vmname"        {$VMName = $argument}
        "-vmname"       {$VMName = $argument}
        "/vmname"       {$VMName = $argument}
        "port"          {$DebugPort = $argument}
        "-port"         {$DebugPort = $argument}
        "/port"         {$DebugPort = $argument}
        "vmguid"        {$VMGuid = $argument}
        "-vmguid"       {$VMGuid = $argument}
        "/vmguid"       {$VMGuid = $argument}
        default         {}
    }

    $nextarg = $argument
}

if (($VMName -eq "") -and ($VMGuid -eq ""))
{
    funHelp
}

if (($VMName -ne "") -and ($VMGuid -ne ""))
{
    Write-Warning "Set VMname or VMGuid only"
    funHelp
}

if ($ConfigVM -eq $True)
{
    if ($DebugPort -eq "unassigned")
    {
        Write-Warning "Please, specify debug port"
        funHelp
    }
}

#Get the VM object that we want to modify
if ($VMName -ne "")
{
    $VM = Get-VM -computername $targetcomputer -VMName $VMName
}

if ($VMGuid -ne "")
{
    $VM = Get-VM -computername $targetcomputer -Id $VMGuid
}

#Get a VMManagementService object
$VMManagementService = gwmi -class "Msvm_VirtualSystemManagementService" -namespace "root\virtualization\v2" -computername $targetcomputer

#Get the VM object that we want to modify
$query = "SELECT * FROM Msvm_ComputerSystem WHERE ElementName='" + $VMName + "'"
$VM1 = gwmi -query $query -namespace "root\virtualization\v2" -computername $targetcomputer

#Get the VirtualSystemGlobalSettingData of the VM we want to modify
$query = "Associators of {$VM1} WHERE ResultClass=Msvm_VirtualSystemSettingData"
$VMSystemGlobalSettingData = gwmi -query $query -namespace "root\virtualization\v2" -computername $targetcomputer |  ? { $_.ElementName -eq $VM1.ElementName }

# Set a new debugport
if ($DebugPort -ne "unassigned")
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPort = $DebugPort
    $VMSystemGlobalSettingData.DebugPortEnabled = 1

    #Update the VM with ModifyVirtualSystem
    $Result = $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
}

# Enable auto assigned debug ports
if ($AutoAssign -eq $True)
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 2

    #Update the VM with ModifyVirtualSystem
    $Result = $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
}

# Turn off debugging
if ($DebugOff -eq $True)
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 0

    #Update the VM with ModifyVirtualSystem
    $Result = $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
}

if ([string]::IsNullOrEmpty($VMName))
{
    Write-Warning "Please, specify VM name for executing Powershell direct commands" 
}

if ($ConfigVm -eq $True)
{
    
    if ($VM.Generation -eq 2)
    {
        $FirmwareCfg = Get-VMFirmware Win10x64_Gen2
        if ($FirmwareCfg.SecureBoot -eq "On")
        {
            Write-Warning "You can't debug VM, until secureboot is enabled"
            exit
        }
    }


    $s = New-PSSession -VMName $VMName

    Invoke-Command -Session $s {bcdedit /debug yes}

    Invoke-Command -Session $s {param($Dbgport) bcdedit.exe /dbgsettings NET HOSTIP:1.2.3.4 PORT:$Dbgport KEY:1.2.3.4} -ArgumentList $DebugPort 

    if ($RebootVM -eq $True)
    {
        Restart-VM -Name $VMName
    }
}

$bat_file_name = "debug_guest_$VMName.bat"
$bat_file_content = "windbg.exe -k net:target=$env:computername,port=$DebugPort,key=1.2.3.4"

if ($NotRewrite -eq $True)
{
    if (-not (Test-Path $bat_file_name))
    {
       $bat_file_content | Out-File -FilePath $bat_file_name -Encoding ascii
    }
} 
else
{
    $bat_file_content | Out-File -FilePath $bat_file_name -Encoding ascii
}

exit