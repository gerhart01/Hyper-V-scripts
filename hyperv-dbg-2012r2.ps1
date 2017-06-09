#
# Argument initialization
#

#script for configuring debugging Windows Server 2012 R2/ Windows 8.1 using kdvm.dll transport (was ported to virtualization\v2 WMI namespace)
#You need kdvm.dll from Windows Server 2012 R2 Preview build. Copy it to %Systemroot%\system32 dir
#original script was published on osronline.com http://www.osronline.com/showthread.cfm?link=234398

$nextarg = "none"
$DebugPort = "50005" #port number (use in windbg connection string)
$targetcomputer = $env:COMPUTERNAME #name of host OS
$VMName = "Windows Server 2012 R2" #virtual machine name
$AutoAssign = "false"
$DebugOff = "false"

function funHelp()
{
$helpText=@"

DESCRIPTION:
NAME: synthdebug.ps1
Displays (and optionally sets) the debugport for synthetic debugging.

PARAMETERS:
-computerName Specifies the name of the computer upon which to run the script
-help         prints help file
-vmname       name of the VM of interest
-port        (optional) ID of the channel to use for debugging
-debugoff
-autoassign

SYNTAX:
synthdebug.ps1 [-computerName targetcomputer] -vmname NameOfVM [-port 
PortNumber]

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
        "-computername" {$targetcomputer = $argument}
        default         {}
    }

    $nextarg = $argument
}

if ($VMName -eq "")
{
    funHelp
}

#Get a VMManagementService object
$VMManagementService = gwmi -class "Msvm_VirtualSystemManagementService" -namespace "root\virtualization\v2" -computername $targetcomputer

#Get the VM object that we want to modify
$query = "SELECT * FROM Msvm_ComputerSystem WHERE ElementName='" + $VMName + "'"
$VM = gwmi -query $query -namespace "root\virtualization\v2" -computername $targetcomputer

#Get the VirtualSystemGlobalSettingData of the VM we want to modify
$query = "Associators of {$VM} WHERE ResultClass=Msvm_VirtualSystemSettingData"
$VMSystemGlobalSettingData = gwmi -query $query -namespace "root\virtualization\v2" -computername $targetcomputer


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
if ($AutoAssign -ne "false")
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 2

    #Update the VM with ModifyVirtualSystem
    $Result = $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
}

# Turn off debugging
if ($DebugOff -ne "false")
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 0

    #Update the VM with ModifyVirtualSystem
    $Result = $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
}

$VMSystemGlobalSettingData

exit
