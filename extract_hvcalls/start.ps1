# __author__ = "Gerhart"
# __license__ = "GPL3"
# __version__ = "1.0.0"
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


$dir_with_hvcalls_bin = "F:\test"
$path_to_ida = "F:\IDA\ida64.exe"
$path_to_script = (Get-Location).Path + "\extract_hvcalls.py"
$ida_extension = ".i64"


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
    $short_idb = $_.Name.Replace($_.extension, $ida_extension)

    $idb_path =  $fn + $ida_extension

    if ((Test-Path $idb_path) -eq $True)
    {
         $ida_params = '-A -S'+$path_to_script+' '+ $idb_path
         Write-Host "processing "$short_idb"..."
    } 
    else
    {
         $ida_params = '-c -A -S'+$path_to_script+' '+$fn
         Write-Host "processing "$_.Name"..."
    }

    $expr = '& '+$path_to_ida+" "+$ida_params
    
    Invoke-Expression $expr
}