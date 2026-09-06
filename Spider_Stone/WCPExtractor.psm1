#
# WCPExtractor.psm1
# PowerShell module for extracting WCP (Windows Componentization Platform) compressed files
# Based on wcpex.c by Smx (https://github.com/smx-smx/wcpex/)
#
#
# Copyright (C) 2023 Stefano Moioli
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
# 1. The origin of this software must not be misrepresented; you must not
# claim that you wrote the original software. If you use this software
# in a product, an acknowledgment in the product documentation would be
# appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
# misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace WCP {
    [StructLayout(LayoutKind.Sequential)]
    public struct BlobData {
        public IntPtr length;
        public IntPtr fill;
        public IntPtr pData;
    }

    public static class NativeMethods {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);
    }

    // Delegate types for WCP functions - no calling convention specified
    public delegate uint GetCompressedFileTypeDelegate(ref BlobData arg);

    public delegate int InitializeDeltaCompressorDelegate(IntPtr arg);

    public delegate int DeltaDecompressBufferDelegate(
        uint DeltaFlagType,
        IntPtr pDictionary,
        uint headerSize,
        ref BlobData inData,
        ref BlobData outData
    );

    public delegate int LoadFirstResourceLanguageAgnosticDelegate(
        uint unused,
        IntPtr hModule,
        ushort lpType,
        ushort lpName,
        IntPtr pOutDict
    );

    // Optional (build-dependent) export. Confirmed present in wcp.dll 10.0.26100.33288 as
    // ?IsManifestCompressed@Rtl@Implementation@WCP@Windows@@YAJPEBU_LBLOB@@PEA_N@Z
    //   long IsManifestCompressed(const _LBLOB* in, bool* isCompressed)
    public delegate int IsManifestCompressedDelegate(
        ref BlobData inData,
        [MarshalAs(UnmanagedType.U1)] ref bool isCompressed
    );
}
'@

function Get-ProcessorArchitecture {
    <#
    .SYNOPSIS
    Gets the current processor architecture
    
    .DESCRIPTION
    Determines if the system is x86, x64, or ARM64
    
    .OUTPUTS
    String representing the architecture: "x86", "x64", or "arm64"
    #>
    [CmdletBinding()]
    param()
    
    $arch = $env:PROCESSOR_ARCHITECTURE
    $archW6432 = $env:PROCESSOR_ARCHITEW6432
    
    # Check for ARM64
    if ($arch -eq "ARM64" -or $archW6432 -eq "ARM64") {
        return "arm64"
    }
    # Check for x64
    elseif ($arch -eq "AMD64" -or $archW6432 -eq "AMD64") {
        return "x64"
    }
    # Default to x86
    else {
        return "x86"
    }
}

function Find-LatestWCPDll {
    <#
    .SYNOPSIS
    Finds the latest version of wcp.dll matching the current Windows bitness
    
    .DESCRIPTION
    Searches for wcp.dll in Windows directories based on system architecture (x86, x64, or ARM64)
    
    .OUTPUTS
    String path to the latest wcp.dll matching system bitness
    #>
    [CmdletBinding()]
    param()
    
    # Determine system architecture
    $architecture = Get-ProcessorArchitecture
    $bitnessText = switch ($architecture) {
        "x64" { "64-bit (x64)" }
        "arm64" { "64-bit (ARM64)" }
        "x86" { "32-bit (x86)" }
    }
    
    Write-Host "Searching for $bitnessText wcp.dll in Windows directories..." -ForegroundColor Cyan
    Write-Host "System architecture: $bitnessText" -ForegroundColor Gray
    
    # Build search paths based on system architecture
    $searchPaths = @()
    
    # System32 always contains the native bitness version
    $searchPaths += Join-Path $env:WINDIR "System32\wcp.dll"
    
    # Add WinSxS patterns based on architecture
    switch ($architecture) {
        "x64" {
            $searchPaths += Join-Path $env:WINDIR "WinSxS\amd64_microsoft-windows-servicingstack*\wcp.dll"
        }
        "arm64" {
            $searchPaths += Join-Path $env:WINDIR "WinSxS\arm64_microsoft-windows-servicingstack*\wcp.dll"
        }
        "x86" {
            $searchPaths += Join-Path $env:WINDIR "WinSxS\x86_microsoft-windows-servicingstack*\wcp.dll"
        }
    }
    
    Write-Host "`nSearching in the following patterns:" -ForegroundColor Gray
    foreach ($pattern in $searchPaths) {
        Write-Host "  - $pattern" -ForegroundColor Gray
    }
    
    $wcpFiles = @()
    
    foreach ($path in $searchPaths) {
        Write-Verbose "Searching: $path"
        $found = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($found) {
            foreach ($file in $found) {
                # Verify architecture matches what we expect
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    if ($bytes.Length -gt 0x3C) {
                        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
                        if ($bytes.Length -gt $peOffset + 4 + 20) {
                            $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
                            
                            # Check if architecture matches what we're looking for
                            $isCorrectArch = $false
                            switch ($architecture) {
                                "x64" {
                                    # 0x8664 = AMD64, 0x0200 = IA64
                                    if ($machine -eq 0x8664 -or $machine -eq 0x0200) {
                                        $isCorrectArch = $true
                                    }
                                }
                                "arm64" {
                                    # 0xAA64 = ARM64
                                    if ($machine -eq 0xAA64) {
                                        $isCorrectArch = $true
                                    }
                                }
                                "x86" {
                                    # 0x014c = i386
                                    if ($machine -eq 0x014c) {
                                        $isCorrectArch = $true
                                    }
                                }
                            }
                            
                            if ($isCorrectArch) {
                                $wcpFiles += $file
                                Write-Verbose "Found $bitnessText wcp.dll: $($file.FullName)"
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Could not verify architecture for: $($file.FullName)"
                    # If we can't verify, include it anyway if it's from System32
                    if ($file.DirectoryName -eq (Join-Path $env:WINDIR "System32")) {
                        $wcpFiles += $file
                    }
                }
            }
        }
    }
    
    if ($wcpFiles.Count -eq 0) {
        throw "$bitnessText wcp.dll not found in Windows directories"
    }
    
    Write-Host "`nFound $($wcpFiles.Count) $bitnessText wcp.dll file(s)" -ForegroundColor Green
    
    # Sort by version and last write time to get the newest
    $latestWcp = $wcpFiles | ForEach-Object {
        $fileInfo = $_
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fileInfo.FullName)
        
        [PSCustomObject]@{
            Path = $fileInfo.FullName
            FileVersion = $versionInfo.FileVersion
            ProductVersion = $versionInfo.ProductVersion
            LastWriteTime = $fileInfo.LastWriteTime
            Directory = $fileInfo.DirectoryName
            VersionObject = [Version]::new($versionInfo.FileMajorPart, $versionInfo.FileMinorPart, 
                                          $versionInfo.FileBuildPart, $versionInfo.FilePrivatePart)
        }
    } | Sort-Object -Property VersionObject, LastWriteTime -Descending | Select-Object -First 1
    
    # Display found path
    Write-Host "`nFound latest $bitnessText wcp.dll:" -ForegroundColor Yellow
    Write-Host "  Path: $($latestWcp.Path)" -ForegroundColor White
    Write-Host "  Directory: $($latestWcp.Directory)" -ForegroundColor White
    Write-Host "  Version: $($latestWcp.FileVersion)" -ForegroundColor White
    Write-Host "  Product Version: $($latestWcp.ProductVersion)" -ForegroundColor White
    Write-Host "  Last Modified: $($latestWcp.LastWriteTime)" -ForegroundColor White
    Write-Host ""
    
    return $latestWcp.Path
}

function Initialize-WCPModule {
    <#
    .SYNOPSIS
    Initializes the WCP module by loading wcp.dll and resolving function pointers
    
    .DESCRIPTION
    Loads the Windows Componentization Platform DLL using LoadLibrary and prepares function delegates
    
    .PARAMETER WCPPath
    Path to the wcp.dll file to load
    
    .OUTPUTS
    Hashtable containing the module handle and function delegates
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WCPPath
    )
    
    Write-Verbose "Initializing WCP module from: $WCPPath"
    
    # Use LoadLibrary to load the DLL (matching C code's init() function)
    $wcpModule = [WCP.NativeMethods]::LoadLibrary($WCPPath)
    
    if ($wcpModule -eq [IntPtr]::Zero) {
        $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to load wcp.dll from '$WCPPath'. Error code: $lastError"
    }
    
    Write-Verbose "Successfully loaded wcp.dll, handle: 0x$($wcpModule.ToString('X'))"
    
    $functions = @{
        Module = $wcpModule
        DllPath = $WCPPath
    }
    
    # Get function pointers - these are the mangled C++ names from the DLL
    $procAddresses = @{
        GetCompressedFileType = "?GetCompressedFileType@Rtl@WCP@Windows@@YAKPEBU_LBLOB@@@Z"
        InitializeDeltaCompressor = "?InitializeDeltaCompressor@Rtl@Windows@@YAJPEAX@Z"
        DeltaDecompressBuffer = "?DeltaDecompressBuffer@Rtl@Windows@@YAJKPEAU_LBLOB@@_K0PEAVAutoDeltaBlob@12@@Z"
        LoadFirstResourceLanguageAgnostic = "?LoadFirstResourceLanguageAgnostic@Rtl@Windows@@YAJKPEAUHINSTANCE__@@PEBG1PEAU_LBLOB@@@Z"
    }
    
    foreach ($func in $procAddresses.GetEnumerator()) {
        Write-Verbose "Getting procedure address for: $($func.Key)"
        $ptr = [WCP.NativeMethods]::GetProcAddress($wcpModule, $func.Value)
        
        if ($ptr -eq [IntPtr]::Zero) {
            [WCP.NativeMethods]::FreeLibrary($wcpModule) | Out-Null
            throw "Failed to get procedure address for $($func.Key) in wcp.dll"
        }
        
        Write-Verbose "Got procedure address for $($func.Key): 0x$($ptr.ToString('X'))"
        
        switch ($func.Key) {
            "GetCompressedFileType" {
                $functions[$func.Key] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $ptr, [WCP.GetCompressedFileTypeDelegate])
            }
            "InitializeDeltaCompressor" {
                $functions[$func.Key] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $ptr, [WCP.InitializeDeltaCompressorDelegate])
            }
            "DeltaDecompressBuffer" {
                $functions[$func.Key] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $ptr, [WCP.DeltaDecompressBufferDelegate])
            }
            "LoadFirstResourceLanguageAgnostic" {
                $functions[$func.Key] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $ptr, [WCP.LoadFirstResourceLanguageAgnosticDelegate])
            }
        }
    }
    
    # Optional exports: resolve if present, do not fail the module when a given
    # wcp.dll build does not export them. Name verified against 10.0.26100.33288.
    $optionalProcAddresses = @{
        IsManifestCompressed = "?IsManifestCompressed@Rtl@Implementation@WCP@Windows@@YAJPEBU_LBLOB@@PEA_N@Z"
    }

    foreach ($func in $optionalProcAddresses.GetEnumerator()) {
        $ptr = [WCP.NativeMethods]::GetProcAddress($wcpModule, $func.Value)
        if ($ptr -eq [IntPtr]::Zero) {
            Write-Verbose "Optional export not found in this wcp.dll build: $($func.Key)"
            continue
        }
        Write-Verbose "Got optional procedure address for $($func.Key): 0x$($ptr.ToString('X'))"
        switch ($func.Key) {
            "IsManifestCompressed" {
                $functions[$func.Key] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    $ptr, [WCP.IsManifestCompressedDelegate])
            }
        }
    }

    Write-Verbose "WCP module initialization complete"
    return $functions
}

function Test-WCPManifestCompressed {
    <#
    .SYNOPSIS
    Reports whether a manifest blob is WCP-compressed, using wcp.dll's own IsManifestCompressed.

    .DESCRIPTION
    Some WinSxS manifests are stored uncompressed (plain UTF-8/UTF-16 XML). Feeding those to the
    delta-decompress path fails. This wraps the native ?IsManifestCompressed@Rtl@Implementation@WCP@Windows@@
    export so callers can decide whether to decompress or read the file as-is. Returns $null when the
    loaded wcp.dll build does not export the function (older servicing stacks).

    .PARAMETER InputFile
    Path to the manifest file to test.

    .PARAMETER WCPDllPath
    Path to wcp.dll. If omitted, the latest matching-bitness version is located automatically.

    .OUTPUTS
    [bool] $true / $false, or $null if the export is unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$InputFile,

        [Parameter(Mandatory = $false)]
        [string]$WCPDllPath
    )

    $InputFile = [System.IO.Path]::GetFullPath($InputFile)
    $wcp = $null
    $inputDataPtr = [IntPtr]::Zero

    try {
        if ([string]::IsNullOrEmpty($WCPDllPath)) { $WCPDllPath = Find-LatestWCPDll }
        $wcp = Initialize-WCPModule -WCPPath $WCPDllPath

        if (-not $wcp.ContainsKey("IsManifestCompressed")) {
            Write-Verbose "IsManifestCompressed not exported by this wcp.dll build"
            return $null
        }

        $fileBytes = [System.IO.File]::ReadAllBytes($InputFile)
        if ($fileBytes.Length -eq 0) { throw "Input file is empty" }

        $inputDataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($fileBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($fileBytes, 0, $inputDataPtr, $fileBytes.Length)

        $inData = New-Object WCP.BlobData
        $inData.length = [IntPtr]$fileBytes.Length
        $inData.fill   = [IntPtr]$fileBytes.Length
        $inData.pData  = $inputDataPtr

        $isCompressed = $false
        $hr = $wcp.IsManifestCompressed.Invoke([ref]$inData, [ref]$isCompressed)
        if ($hr -lt 0) { throw "IsManifestCompressed failed: 0x$($hr.ToString('X8'))" }

        return [bool]$isCompressed
    } catch {
        Write-Error "Test-WCPManifestCompressed failed: $_"
        return $null
    } finally {
        if ($inputDataPtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputDataPtr)
        }
        if ($wcp -and $wcp.Module -ne [IntPtr]::Zero) {
            [WCP.NativeMethods]::FreeLibrary($wcp.Module) | Out-Null
        }
    }
}

function Get-WCPCompressionTypeName {
    <#
    .SYNOPSIS
    Maps a wcp.dll GetCompressedFileType numeric result to a human-readable name.

    .DESCRIPTION
    The numeric code returned by the live wcp.dll is authoritative. These labels are the
    decoded enum snapshot from ServicingCommon.dll (Windows Server 2025, build 26100.x):
    the compressed-file header is 'D' 'C' <T> 0x01 with <T> selecting the type -
    D=1, N=2, H=3, M=4 (DCM delta manifest), S=5 (DCS/LZMS), X=6. If Microsoft changes the
    enum in a newer wcp.dll, an unmapped code is labelled from the on-disk magic byte instead,
    so detection never depends on a frozen table.

    .PARAMETER Code
    The value returned by GetCompressedFileType.

    .PARAMETER Bytes
    Optional first bytes of the file, used to label codes not in the known map.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Code,

        [Parameter(Mandatory = $false)]
        [byte[]]$Bytes
    )

    $map = @{
        0 = 'uncompressed/none'
        1 = 'DCD'
        2 = 'DCN'
        3 = 'DCH'
        4 = 'DCM (delta manifest)'
        5 = 'DCS (LZMS)'
        6 = 'DCX'
    }

    if ($map.ContainsKey([int]$Code)) {
        return $map[[int]$Code]
    }

    if ($Bytes -and $Bytes.Length -ge 4 -and $Bytes[0] -eq 0x44 -and $Bytes[1] -eq 0x43 -and $Bytes[3] -eq 0x01) {
        return ("DC{0}\x01 (code {1}, unmapped)" -f [char]$Bytes[2], $Code)
    }

    return "unknown (code $Code)"
}

function Expand-WCPFile {
    <#
    .SYNOPSIS
    Extracts a WCP-compressed file (typically Windows manifest files)
    
    .DESCRIPTION
    Decompresses files handled by Windows Componentization Platform, such as manifest files
    found in %windir%\WinSxS\Manifests
    
    .PARAMETER InputFile
    Path to the compressed input file
    
    .PARAMETER OutputFile
    Path where the decompressed output will be saved. If not specified, outputs to console.
    
    .PARAMETER WCPDllPath
    Path to wcp.dll. If not specified, automatically finds the latest version matching system bitness.
    
    .EXAMPLE
    Expand-WCPFile -InputFile "C:\Windows\WinSxS\Manifests\example.manifest" -OutputFile "C:\Temp\example.xml"
    
    .EXAMPLE
    Expand-WCPFile -InputFile "compressed.manifest" -OutputFile "decompressed.xml" -WCPDllPath "C:\Windows\System32\wcp.dll"
    
    .EXAMPLE
    Expand-WCPFile -InputFile "compressed.manifest" | Out-File "decompressed.xml" -Encoding UTF8
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$InputFile,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$OutputFile,
        
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$WCPDllPath
    )
    
    # Get full path to input file
    $InputFile = [System.IO.Path]::GetFullPath($InputFile)
    
    # Initialize variables for cleanup
    $wcp = $null
    $inputDataPtr = [IntPtr]::Zero
    $dictDataPtr = [IntPtr]::Zero
    
    try {
        # Find or validate WCP DLL path
        if ([string]::IsNullOrEmpty($WCPDllPath)) {
            Write-Verbose "No WCP DLL path specified, searching for latest version..."
            $WCPDllPath = Find-LatestWCPDll
        } else {
            Write-Host "Using specified WCP DLL path: $WCPDllPath" -ForegroundColor Cyan
            
            # Verify the DLL exists and is accessible
            if (-not (Test-Path $WCPDllPath)) {
                throw "WCP DLL not found at: $WCPDllPath"
            }
            
            # Display version info for specified DLL
            $dllInfo = Get-Item $WCPDllPath
            $dllVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllInfo.FullName)
            Write-Host "WCP DLL Version: $($dllVersion.FileVersion)" -ForegroundColor Green
        }
        
        # Initialize WCP module (mimics C code's init() function)
        Write-Host "`nInitializing WCP module..." -ForegroundColor Yellow
        $wcp = Initialize-WCPModule -WCPPath $WCPDllPath
        
        # Read input file
        Write-Host "Reading input file: $InputFile" -ForegroundColor Yellow
        $fileInfo = Get-Item $InputFile
        Write-Host "Input file size: $($fileInfo.Length) bytes" -ForegroundColor Gray
        
        $fileBytes = [System.IO.File]::ReadAllBytes($InputFile)
        $fileSize = $fileBytes.Length
        
        if ($fileSize -eq 0) {
            throw "Input file is empty"
        }
        
        # Allocate unmanaged memory for input data
        $inputDataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($fileSize)
        [System.Runtime.InteropServices.Marshal]::Copy($fileBytes, 0, $inputDataPtr, $fileSize)
        
        # Create input blob structure
        $inData = New-Object WCP.BlobData
        $inData.length = [IntPtr]$fileSize
        $inData.fill = [IntPtr]$fileSize
        $inData.pData = $inputDataPtr
        
        # --- Version-resilient compression-type detection & dispatch ---
        # The numeric type is taken from the LIVE wcp.dll (authoritative across versions).
        # Names + magic layout are the decoded enum from ServicingCommon.dll (Server 2025
        # 26100.x, onecore\base\wcp\rtllib\win32lib\delta_library.cpp):
        #   header = 'D' 'C' <T> 0x01 (len >= 4);  <T>: D=1 N=2 H=3 M=4 S=5 X=6
        #   Only type 4 (DCM) counts as "compressed" per IsManifestCompressed; type 5 (DCS) is LZMS.
        Write-Verbose "Getting compressed file type..."
        $fileType = $wcp.GetCompressedFileType.Invoke([ref]$inData)
        $typeName = Get-WCPCompressionTypeName -Code $fileType -Bytes $fileBytes
        Write-Host "Compressed file type: $fileType ($typeName)" -ForegroundColor Gray

        # No DC?\x01 magic => not WCP-compressed; the bytes are already the plain manifest.
        $hasWcpMagic = ($fileSize -ge 4 -and $fileBytes[0] -eq 0x44 -and $fileBytes[1] -eq 0x43 -and $fileBytes[3] -eq 0x01)
        if (-not $hasWcpMagic) {
            Write-Host "Input is not WCP-compressed - passing through unchanged." -ForegroundColor Gray
            $passText = [System.Text.Encoding]::UTF8.GetString($fileBytes)
            if ($OutputFile) {
                $OutputFile = [System.IO.Path]::GetFullPath($OutputFile)
                $passDir = Split-Path -Parent $OutputFile
                if ($passDir -and -not (Test-Path $passDir)) { New-Item -ItemType Directory -Path $passDir -Force | Out-Null }
                [System.IO.File]::WriteAllText($OutputFile, $passText, [System.Text.Encoding]::UTF8)
                Write-Host "`nWrote pass-through output to: $OutputFile" -ForegroundColor Green
            } else {
                Write-Output $passText
            }
            return
        }

        # Compressed, but not the delta manifest type: do not guess. Type 5 (DCS/LZMS) needs the
        # ?LZMSDecompressBuffer@Rtl@WCP@Windows@@ branch wired against a validated Auto<_LBLOB>
        # layout - deliberately a typed extension point, not a blind native call.
        if ($fileType -ne 4) {
            throw ("WCP compression type $fileType ($typeName) is not supported by the delta path. " +
                   "Type 5 (DCS/LZMS) requires an LZMSDecompressBuffer branch; types 1/2/3/6 are not implemented.")
        }

        # Initialize delta compressor
        Write-Verbose "Initializing delta compressor..."
        $result = $wcp.InitializeDeltaCompressor.Invoke([IntPtr]::Zero)
        Write-Host "InitializeDeltaCompressor: 0x$($result.ToString('X8'))" -ForegroundColor Gray
        
        if ($result -lt 0) {
            throw "InitializeDeltaCompressor failed"
        }
        
        # Allocate dictionary data (3 x uint64 = 24 bytes)
        $dictDataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(24)
        
        # Load resource dictionary
        Write-Verbose "Loading resource dictionary..."
        $result = $wcp.LoadFirstResourceLanguageAgnostic.Invoke(
            0,                  # unused
            $wcp.Module,        # HMODULE
            0x266,             # lpType (special meaning - matches C code)
            1,                 # lpName (special meaning - matches C code)
            $dictDataPtr
        )
        
        Write-Host "LoadFirstResourceLanguageAgnostic: 0x$($result.ToString('X8'))" -ForegroundColor Gray
        
        if ($result -lt 0) {
            throw "LoadFirstResourceLanguageAgnostic failed"
        }
        
        # Prepare output blob
        $outData = New-Object WCP.BlobData
        
        # Decompress buffer
        Write-Verbose "Decompressing buffer..."
        $result = $wcp.DeltaDecompressBuffer.Invoke(
            2,                  # type (matches C code)
            $dictDataPtr,       # dictionary
            4,                  # headerSize (matches C code)
            [ref]$inData,
            [ref]$outData
        )
        
        Write-Host "DeltaDecompressBuffer: 0x$($result.ToString('X8'))" -ForegroundColor Gray
        
        if ($result -lt 0) {
            throw "DeltaDecompressBuffer failed"
        }
        
        # Extract decompressed data
        Write-Verbose "Extracting decompressed data..."
        $outputSize = [int]$outData.length
        Write-Host "`nDecompressed size: $outputSize bytes" -ForegroundColor Green
        
        if ($outputSize -eq 0) {
            throw "Decompression resulted in empty output"
        }
        
        $outputBytes = New-Object byte[] $outputSize
        [System.Runtime.InteropServices.Marshal]::Copy($outData.pData, $outputBytes, 0, $outputSize)
        
        # Convert to string (assuming UTF-8 encoding for manifest files)
        $outputText = [System.Text.Encoding]::UTF8.GetString($outputBytes)
        
        # Write output
        if ($OutputFile) {
            # Get full path for output file
            $OutputFile = [System.IO.Path]::GetFullPath($OutputFile)
            Write-Verbose "Writing output to: $OutputFile"
            $outputDir = Split-Path -Parent $OutputFile
            if ($outputDir -and -not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }
            [System.IO.File]::WriteAllText($OutputFile, $outputText, [System.Text.Encoding]::UTF8)
            Write-Host "`nSuccessfully decompressed to: $OutputFile" -ForegroundColor Green
        } else {
            # Output to pipeline
            Write-Output $outputText
        }
        
    } catch {
        Write-Error "Failed to decompress file: $_"
        throw
    } finally {
        # Cleanup unmanaged resources
        Write-Verbose "Cleaning up resources..."
        
        if ($inputDataPtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputDataPtr)
        }
        if ($dictDataPtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($dictDataPtr)
        }
        if ($wcp -and $wcp.Module -ne [IntPtr]::Zero) {
            [WCP.NativeMethods]::FreeLibrary($wcp.Module) | Out-Null
        }
    }
}

function Test-WCPManifest {
    <#
    .SYNOPSIS
    Tests decompression of a manifest file from Windows WinSxS
    
    .DESCRIPTION
    Finds a manifest file in C:\Windows\WinSxS\Manifests\ and attempts to decompress it
    
    .PARAMETER ManifestName
    Optional specific manifest name to test. If not provided, tests the first manifest found.
    
    .PARAMETER OutputPath
    Optional output directory for the decompressed file. Defaults to user's temp directory.
    
    .EXAMPLE
    Test-WCPManifest
    
    .EXAMPLE
    Test-WCPManifest -ManifestName "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60b5254171f9507e.manifest"
    
    .EXAMPLE
    Test-WCPManifest -OutputPath "C:\Temp"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ManifestName,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $env:TEMP
    )
    
    try {
        $manifestsPath = Join-Path $env:WINDIR "WinSxS\Manifests"
        
        if (-not (Test-Path $manifestsPath)) {
            throw "Manifests directory not found: $manifestsPath"
        }
        
        Write-Host "Testing WCP manifest decompression..." -ForegroundColor Cyan
        Write-Host "Manifests directory: $manifestsPath" -ForegroundColor Gray
        
        # Find a manifest to test
        if ($ManifestName) {
            $manifestFile = Get-ChildItem -Path $manifestsPath -Filter $ManifestName -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $manifestFile) {
                throw "Specified manifest not found: $ManifestName"
            }
        } else {
            # Get first manifest file
            $manifestFile = Get-ChildItem -Path $manifestsPath -Filter "*.manifest" | Select-Object -First 1
            if (-not $manifestFile) {
                throw "No manifest files found in $manifestsPath"
            }
        }
        
        Write-Host "`nSelected manifest for testing:" -ForegroundColor Yellow
        Write-Host "  Name: $($manifestFile.Name)" -ForegroundColor White
        Write-Host "  Size: $($manifestFile.Length) bytes" -ForegroundColor White
        Write-Host "  Last Modified: $($manifestFile.LastWriteTime)" -ForegroundColor White
        
        # Create output filename
        $outputFileName = [System.IO.Path]::GetFileNameWithoutExtension($manifestFile.Name) + "_decompressed.xml"
        $outputFilePath = Join-Path $OutputPath $outputFileName
        
        Write-Host "`nDecompressing manifest..." -ForegroundColor Yellow
        
        # Perform decompression
        Expand-WCPFile -InputFile $manifestFile.FullName -OutputFile $outputFilePath
        
        # Verify output
        if (Test-Path $outputFilePath) {
            $outputInfo = Get-Item $outputFilePath
            Write-Host "`nDecompression successful!" -ForegroundColor Green
            Write-Host "Output file: $outputFilePath" -ForegroundColor White
            Write-Host "Output size: $($outputInfo.Length) bytes" -ForegroundColor White
            
            # Show first few lines of decompressed content
            $content = Get-Content $outputFilePath -TotalCount 5
            Write-Host "`nFirst few lines of decompressed content:" -ForegroundColor Cyan
            $content | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            
            # Validate XML
            try {
                [xml]$xmlContent = Get-Content $outputFilePath
                Write-Host "`nXML validation: PASSED" -ForegroundColor Green
                Write-Host "Root element: $($xmlContent.DocumentElement.Name)" -ForegroundColor Gray
            } catch {
                Write-Host "`nXML validation: FAILED" -ForegroundColor Red
                Write-Host "Error: $_" -ForegroundColor Red
            }
        } else {
            throw "Output file was not created"
        }
        
    } catch {
        Write-Error "Test failed: $_"
    }
}

# Export module functions
Export-ModuleMember -Function Expand-WCPFile, Find-LatestWCPDll, Test-WCPManifest, Get-ProcessorArchitecture, Test-WCPManifestCompressed, Get-WCPCompressionTypeName