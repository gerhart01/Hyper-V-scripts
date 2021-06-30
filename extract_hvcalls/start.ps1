
#
# Set paths to Windows binaries with direct hvcalls and IDA PRO
# current binaries:
#
#    winhvr.sys, 
#    winhv.sys, 
#    securekernel.exe, 
#    ntoskrnl.exe
#    ntkrla57.exe
#    securekernella57.exe
#
# Tested on IDA PRO 7.5
#
# good example of IDA PRO batch analysis can be found in 
# https://irq5.io/2020/05/25/batch-binary-analysis-with-ida-pro-7-4-automation/
#


$dir_with_hvcalls_bin = "F:\bin"
$path_to_ida = "F:\IDA\ida64.exe"
$path_to_script = (Get-Location).Path + "\extract_hvcalls.py"


$bin_array = @(
    "winhvr.sys", 
    "winhv.sys", 
    "securekernel.exe", 
    "ntoskrnl.exe",
    "ntkrla57.exe"
    "securekernella57.exe"
)

function GetHvcallBinaries()
{
    $sys_dir = [System.Environment]::SystemDirectory + "\"

    $script:bin_array | ForEach-Object {       
           $file = $_

           if ($file.Contains(".sys"))
           {
                $file = $sys_dir + "drivers\" + $_
           } else
           {
                $file = $sys_dir + $_
           }


           If ((Test-Path $file) -eq $True)
           {
                Copy-Item $file $dir_with_hvcalls_bin
           } 
        
    }    
}

# Uncomment if you working with current Windows distr
# GetHvcallBinaries

Get-ChildItem $dir_with_hvcalls_bin  | where {$_.extension -in ".sys",".exe"} | ForEach-Object {
    $fn = $_.FullName
    $ida_params = '-c -A -S'+$path_to_script+' '+$fn
    $expr = '& '+$path_to_ida+" "+$ida_params
    Write-Host "processing "$_.Name"..."
    Invoke-Expression $expr
}