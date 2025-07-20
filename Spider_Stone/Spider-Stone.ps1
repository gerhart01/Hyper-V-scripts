#Requires -Version 7.0

<#
.SYNOPSIS
    Extracts and displays file information from Windows Optional Features
.DESCRIPTION
    This script searches for manifest files associated with a Windows Optional Feature,
    extracts them using WCPExtractor, and displays the file information in a grid view
.PARAMETER FeatureName
    The name of the Windows Optional Feature to analyze
.PARAMETER OutputDirectory
    The directory where manifest files will be copied and extracted
.PARAMETER VerboseOutput
    Enable verbose output
.PARAMETER ParsingMum
    Enable parsing of MUM files from servicing packages
.PARAMETER NotShowGridView
    Do not display results in GridView
.PARAMETER PathToWcp
    Full path to the wcp.dll file to use for extraction
.PARAMETER SearchWcpDll
    Search for the latest version of wcp.dll using WCPExtractor module
.PARAMETER Help
    Show help information
.VERSION
    0.0.3
.AUTHOR
    Spider Stone
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FeatureName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ".\OptionalFeatureFiles",
    
    [switch]$VerboseOutput,
    
    [switch]$ParsingMum,
    
    [switch]$NotShowGridView,
    
    [Parameter(Mandatory = $false)]
    [string]$PathToWcp,
    
    [switch]$SearchWcpDll,
    
    [Parameter(Mandatory = $false)]
    [Alias("?")]
    [switch]$Help
)

#region Script Configuration
$script:Config = @{
    Version = "0.0.2"
    ScriptName = "Spider Stone"
    AllFiles = @()
    WcpModuleLoaded = $false
    WcpDllPath = $null
    ProcessedMumFiles = @()
    RegistryPaths = @{
        OptionalFeatures = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures"
        Packages = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        UpdateDetect = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\UpdateDetect"
    }
    ManifestsPath = "C:\Windows\WinSxS\Manifests"
    ServicingPath = "C:\Windows\servicing\Packages"
    SuffixesToRemove = @("-fod-package", "-opt-package", "-package")
}
#endregion

#region Help Function
function Show-Help {
    <#
    .SYNOPSIS
        Displays help information for the script
    #>
    
    $helpText = @"

$($script:Config.ScriptName) v$($script:Config.Version) - Optional Feature File Finder and Extractor

USAGE:
    .\spider_stone.ps1 [-FeatureName <string>] [-OutputDirectory <string>] [-VerboseOutput] [-ParsingMum] 
                       [-NotShowGridView] [-PathToWcp <string>] [-SearchWcpDll] [-Help]

PARAMETERS:
    -FeatureName <string>
        The name of the Windows Optional Feature to analyze.
        If not specified, shows list of installed features.
        
    -OutputDirectory <string>
        The directory where manifest files will be copied and extracted.
        Default: .\OptionalFeatureFiles
        
    -VerboseOutput
        Enable verbose output for detailed logging.
        
    -ParsingMum
        Enable parsing of MUM files from Windows servicing packages.
        This will recursively process related MUM files.
        
    -NotShowGridView
        Do not display results in GridView.
        
    -PathToWcp <string>
        Full path to the wcp.dll file to use for extraction.
        
    -SearchWcpDll
        Search for the latest version of wcp.dll using WCPExtractor module's Find-LatestWCPDll function.
        
    -Help, -?
        Show this help message.

EXAMPLES:
    # Show installed features
    .\spider_stone.ps1
    
    # Analyze specific feature
    .\spider_stone.ps1 -FeatureName "Windows-Defender-Default-Definitions"
    
    # Analyze with MUM parsing
    .\spider_stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput
    
    # Custom output directory without GridView
    .\spider_stone.ps1 -FeatureName "RSAT" -OutputDirectory "C:\Temp\Features" -NotShowGridView
    
    # Use specific wcp.dll
    .\spider_stone.ps1 -FeatureName "RSAT" -PathToWcp "C:\Windows\System32\wcp.dll"
    
    # Search for wcp.dll
    .\spider_stone.ps1 -SearchWcpDll

NOTES:
    - Requires PowerShell 7.0 or higher
    - Requires WCPExtractor.psm1 module in the same directory
    - Administrator privileges may be required for some operations

"@
    
    Write-Host $helpText -ForegroundColor Cyan
}
#endregion

#region Utility Functions
function Write-VerboseMessage {
    <#
    .SYNOPSIS
        Writes verbose messages if VerboseOutput is enabled
    #>
    param([string]$Message)
    
    if ($VerboseOutput) {
        Write-Host "[VERBOSE] $Message" -ForegroundColor Gray
    }
}

function Write-Header {
    <#
    .SYNOPSIS
        Writes a formatted header section
    #>
    param(
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )
    
    Write-Host "`n$Title" -ForegroundColor $Color
    Write-Host ("=" * $Title.Length) -ForegroundColor $Color
}

function Test-RegistryPath {
    <#
    .SYNOPSIS
        Safely checks if a registry path exists
    #>
    param([string]$Path)
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    
    return Test-Path -Path $Path -ErrorAction SilentlyContinue
}

function Get-RegistryProperties {
    <#
    .SYNOPSIS
        Safely gets registry properties
    #>
    param([string]$Path)
    
    if (-not (Test-RegistryPath -Path $Path)) {
        return $null
    }
    
    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    return $properties
}

function Get-SystemArchitecturePrefix {
    <#
    .SYNOPSIS
        Determines the system architecture prefix for manifest files
    #>
    
    if ([Environment]::Is64BitOperatingSystem) {
        if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 
            [System.Runtime.InteropServices.Architecture]::Arm64) {
            return "arm64_"
        }
        return "amd64_"
    }
    
    return "x86_"
}

function Get-FeatureOutputDirectory {
    <#
    .SYNOPSIS
        Creates and returns the feature-specific output directory
    #>
    param([string]$Feature)
    
    $safeFeatureName = if ([string]::IsNullOrWhiteSpace($Feature)) { 
        "AllFeatures" 
    } else { 
        $Feature -replace '[^\w\-]', '_' 
    }
    
    $featureDir = Join-Path ([System.IO.Path]::GetFullPath($OutputDirectory)) $safeFeatureName
    
    if (-not (Test-Path $featureDir)) {
        New-Item -ItemType Directory -Path $featureDir -Force | Out-Null
    }
    
    return $featureDir
}
#endregion

#region Feature Discovery Functions
function Get-SubkeysFromRegistry {
    <#
    .SYNOPSIS
        Gets subkey names from a specific registry path
    #>
    param([string]$RegistryPath)
    
    $subkeys = @()
    
    if (Test-RegistryPath -Path $RegistryPath) {
        $keys = Get-ChildItem -Path $RegistryPath -ErrorAction SilentlyContinue
        if ($null -ne $keys) {
            foreach ($key in $keys) {
                $subkeys += $key.PSChildName
            }
        }
    }
    
    return $subkeys
}

function Get-InstalledOptionalFeatures {
    <#
    .SYNOPSIS
        Retrieves combined list of installed features from OptionalFeatures and UpdateDetect
    #>
    
    Write-VerboseMessage "Getting list of installed optional features..."
    
    # Get subkeys from OptionalFeatures
    $optionalFeatures = Get-SubkeysFromRegistry -RegistryPath $script:Config.RegistryPaths.OptionalFeatures
    Write-VerboseMessage "Found $($optionalFeatures.Count) features in OptionalFeatures"
    
    # Get subkeys from UpdateDetect
    $updateDetectFeatures = Get-SubkeysFromRegistry -RegistryPath $script:Config.RegistryPaths.UpdateDetect
    Write-VerboseMessage "Found $($updateDetectFeatures.Count) features in UpdateDetect"
    
    # Find features unique to UpdateDetect
    $uniqueToUpdateDetect = $updateDetectFeatures | Where-Object { $_ -notin $optionalFeatures }
    
    # Combine and remove duplicates
    $allFeatures = $optionalFeatures + $updateDetectFeatures | Select-Object -Unique | Sort-Object
    
    # Display source information
    Write-Host "`nFeatures from OptionalFeatures: $($optionalFeatures.Count)" -ForegroundColor Gray
    Write-Host "Features from UpdateDetect: $($updateDetectFeatures.Count)" -ForegroundColor Gray
    Write-Host "Total unique features: $($allFeatures.Count)" -ForegroundColor Green
    
    # Display features unique to UpdateDetect
    if ($uniqueToUpdateDetect.Count -gt 0) {
        Write-Host "`nFeatures found only in UpdateDetect:" -ForegroundColor Yellow
        foreach ($feature in $uniqueToUpdateDetect) {
            Write-Host "  - $feature" -ForegroundColor Gray
        }
    }
    
    return $allFeatures
}

function Show-InstalledFeatures {
    <#
    .SYNOPSIS
        Displays installed optional features in a formatted list
    #>
    
    # First get subkeys from both locations to track sources
    $optionalFeatures = Get-SubkeysFromRegistry -RegistryPath $script:Config.RegistryPaths.OptionalFeatures
    $updateDetectFeatures = Get-SubkeysFromRegistry -RegistryPath $script:Config.RegistryPaths.UpdateDetect
    
    # Combine all features
    $allFeatures = $optionalFeatures + $updateDetectFeatures | Select-Object -Unique | Sort-Object
    
    if ($allFeatures.Count -eq 0) {
        Write-Host "`nNo optional features found in registry" -ForegroundColor Yellow
        return $allFeatures
    }
    
    Write-Header -Title "Installed Optional Features"
    
    # Display statistics
    Write-Host "`nFeatures from OptionalFeatures: $($optionalFeatures.Count)" -ForegroundColor Gray
    Write-Host "Features from UpdateDetect: $($updateDetectFeatures.Count)" -ForegroundColor Gray
    Write-Host "Total unique features: $($allFeatures.Count)" -ForegroundColor Green
    
    # Find features unique to UpdateDetect
    $uniqueToUpdateDetect = $updateDetectFeatures | Where-Object { $_ -notin $optionalFeatures }
    
    # Display features unique to UpdateDetect
    if ($uniqueToUpdateDetect.Count -gt 0) {
        Write-Host "`nFeatures found only in UpdateDetect:" -ForegroundColor Yellow
        foreach ($feature in $uniqueToUpdateDetect) {
            Write-Host "  - $feature" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nAll features:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $allFeatures.Count; $i++) {
        $feature = $allFeatures[$i]
        $source = ""
        
        # Mark features that are only in UpdateDetect
        if ($feature -in $uniqueToUpdateDetect) {
            $source = " [UpdateDetect only]"
        }
        
        Write-Host ("{0,3}. {1}{2}" -f ($i + 1), $feature, $source) -ForegroundColor White
    }
    
    Write-Host "`nTotal: $($allFeatures.Count) feature(s)" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Cyan
    
    return $allFeatures
}

function Test-FeatureExists {
    <#
    .SYNOPSIS
        Verifies if a feature exists as a subkey in either registry location
    #>
    param([string]$Feature)
    
    if ([string]::IsNullOrWhiteSpace($Feature)) {
        return $false
    }
    
    # Check in OptionalFeatures
    $optionalFeaturePath = Join-Path $script:Config.RegistryPaths.OptionalFeatures $Feature
    if (Test-RegistryPath -Path $optionalFeaturePath) {
        Write-Host "Feature '$Feature' found in OptionalFeatures registry" -ForegroundColor Green
        return $true
    }
    
    # Check in UpdateDetect
    $updateDetectPath = Join-Path $script:Config.RegistryPaths.UpdateDetect $Feature
    if (Test-RegistryPath -Path $updateDetectPath) {
        Write-Host "Feature '$Feature' found in UpdateDetect registry" -ForegroundColor Green
        return $true
    }
    
    Write-Warning "Feature '$Feature' not found in registry"
    return $false
}
#endregion

#region Package Discovery Functions
function Get-PackagesWithFeature {
    <#
    .SYNOPSIS
        Finds packages containing the specified feature in Updates subkey
    #>
    param([string]$Feature)
    
    Write-VerboseMessage "Searching for feature in Packages registry..."
    
    $foundPackages = @()
    $packagesPath = $script:Config.RegistryPaths.Packages
    
    if (-not (Test-RegistryPath -Path $packagesPath)) {
        Write-Error "Packages registry path not found"
        return $foundPackages
    }
    
    $packages = Get-ChildItem -Path $packagesPath -ErrorAction SilentlyContinue
    
    if ($null -eq $packages) {
        return $foundPackages
    }
    
    foreach ($package in $packages) {
        $updatesPath = Join-Path $package.PSPath "Updates"
        
        if (-not (Test-RegistryPath -Path $updatesPath)) {
            continue
        }
        
        $properties = Get-RegistryProperties -Path $updatesPath
        
        if ($null -eq $properties) {
            continue
        }
        
        foreach ($prop in $properties.PSObject.Properties) {
            if ($prop.Name -eq $Feature) {
                Write-VerboseMessage "Found feature in package: $($package.PSChildName)"
                $foundPackages += [PSCustomObject]@{
                    PackageName = $package.PSChildName
                    Source = "Packages"
                }
                break
            }
        }
    }
    
    return $foundPackages
}

function Get-OwnerPackages {
    <#
    .SYNOPSIS
        Finds packages that own the specified package and retrieves additional info
    #>
    param([string]$PackageName)
    
    Write-VerboseMessage "Searching for owner packages of: $PackageName"
    
    $ownerPackages = @()
    $packagesPath = $script:Config.RegistryPaths.Packages
    
    $packages = Get-ChildItem -Path $packagesPath -ErrorAction SilentlyContinue
    
    if ($null -eq $packages) {
        return $ownerPackages
    }
    
    foreach ($package in $packages) {
        $ownersPath = Join-Path $package.PSPath "Owners"
        
        if (-not (Test-RegistryPath -Path $ownersPath)) {
            continue
        }
        
        $properties = Get-RegistryProperties -Path $ownersPath
        
        if ($null -eq $properties) {
            continue
        }
        
        foreach ($prop in $properties.PSObject.Properties) {
            if ($prop.Name -eq $PackageName) {
                Write-VerboseMessage "Found owner package: $($package.PSChildName)"
                
                # Get additional package information
                $packageInfo = Get-RegistryProperties -Path $package.PSPath
                
                $ownerInfo = [PSCustomObject]@{
                    PackageName = $package.PSChildName
                    InstallClient = if ($packageInfo.InstallClient) { $packageInfo.InstallClient } else { "N/A" }
                    InstallName = if ($packageInfo.InstallName) { $packageInfo.InstallName } else { "N/A" }
                }
                
                # Display additional information
                Write-Host "  Owner Package: $($ownerInfo.PackageName)" -ForegroundColor Yellow
                Write-Host "  InstallClient: $($ownerInfo.InstallClient)" -ForegroundColor Gray
                Write-Host "  InstallName: $($ownerInfo.InstallName)" -ForegroundColor Gray
                
                $ownerPackages += $ownerInfo
                break
            }
        }
    }
    
    return $ownerPackages
}
#endregion

#region MUM File Processing Functions
function Parse-MumFile {
    <#
    .SYNOPSIS
        Parses a MUM file and extracts component information
    #>
    param([string]$MumFilePath)
    
    if (-not (Test-Path $MumFilePath)) {
        Write-VerboseMessage "MUM file not found: $MumFilePath"
        return @()
    }
    
    Write-VerboseMessage "Parsing MUM file: $MumFilePath"
    
    $components = @()
    $xmlContent = Get-Content -Path $MumFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
    
    if ($null -eq $xmlContent) {
        return $components
    }
    
    [xml]$xml = $xmlContent
    
    # Find all assemblyIdentity elements with name attributes
    $assemblyIdentities = $xml.SelectNodes("//assemblyIdentity[@name]")
    
    if ($null -ne $assemblyIdentities) {
        foreach ($identity in $assemblyIdentities) {
            $name = $identity.GetAttribute("name")
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $components += $name
                Write-VerboseMessage "Found component: $name"
            }
        }
    }
    
    return $components | Select-Object -Unique
}

function Process-MumFiles {
    <#
    .SYNOPSIS
        Recursively processes MUM files
    #>
    param([array]$MumFileNames)
    
    $allComponents = @()
    $mumPath = $script:Config.ServicingPath
    
    foreach ($mumName in $MumFileNames) {
        # Skip if already processed
        if ($mumName -in $script:Config.ProcessedMumFiles) {
            continue
        }
        
        $script:Config.ProcessedMumFiles += $mumName
        
        # Search for MUM file
        $mumFiles = Get-ChildItem -Path $mumPath -Filter "*$mumName*" -ErrorAction SilentlyContinue
        
        foreach ($mumFile in $mumFiles) {
            Write-Host "  Processing MUM: $($mumFile.Name)" -ForegroundColor Cyan
            
            $components = Parse-MumFile -MumFilePath $mumFile.FullName
            $allComponents += $components
            
            # Recursively process found components as potential MUM files
            if ($components.Count -gt 0) {
                $childComponents = Process-MumFiles -MumFileNames $components
                $allComponents += $childComponents
            }
        }
    }
    
    return $allComponents | Select-Object -Unique
}
#endregion

#region Manifest File Functions
function Get-ManifestFileName {
    <#
    .SYNOPSIS
        Generates manifest file name prefix from package name
    #>
    param([string]$PackageName)
    
    $arch = Get-SystemArchitecturePrefix
    $manifestName = $arch + $PackageName.ToLower()
    
    # Remove suffixes
    foreach ($suffix in $script:Config.SuffixesToRemove) {
        if ($manifestName.Contains($suffix)) {
            $index = $manifestName.IndexOf($suffix)
            $manifestName = $manifestName.Substring(0, $index)
            break
        }
    }
    
    Write-VerboseMessage "Generated manifest name prefix: $manifestName"
    return $manifestName
}

function Find-ManifestFiles {
    <#
    .SYNOPSIS
        Searches for manifest files matching the specified prefix
    #>
    param([string]$ManifestPrefix)
    
    $foundFiles = @()
    
    if (-not (Test-Path $script:Config.ManifestsPath)) {
        Write-Warning "Manifests directory not found: $($script:Config.ManifestsPath)"
        return $foundFiles
    }
    
    $searchPattern = "$ManifestPrefix*.manifest"
    Write-VerboseMessage "Searching for: $searchPattern in $($script:Config.ManifestsPath)"
    
    $files = Get-ChildItem -Path $script:Config.ManifestsPath `
                          -Filter $searchPattern `
                          -ErrorAction SilentlyContinue
    
    if ($null -ne $files) {
        foreach ($file in $files) {
            Write-VerboseMessage "Found manifest: $($file.Name)"
            $foundFiles += $file
        }
    }
    
    return $foundFiles
}

function Copy-ManifestFiles {
    <#
    .SYNOPSIS
        Copies manifest files to the output directory
    #>
    param(
        [array]$ManifestFiles,
        [string]$Destination
    )
    
    $fullDestination = [System.IO.Path]::GetFullPath($Destination)
    
    if (-not (Test-Path $fullDestination)) {
        New-Item -ItemType Directory -Path $fullDestination -Force | Out-Null
    }
    
    $copiedFiles = @()
    
    foreach ($file in $ManifestFiles) {
        $destPath = Join-Path $fullDestination $file.Name
        
        if (Copy-Item -Path $file.FullName -Destination $destPath -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-VerboseMessage "Copied: $($file.Name)"
            $copiedFiles += $destPath
        } else {
            Write-Warning "Failed to copy $($file.Name)"
        }
    }
    
    return $copiedFiles
}
#endregion

#region WCPExtractor Functions
function Initialize-WCPExtractor {
    <#
    .SYNOPSIS
        Loads the WCPExtractor module and finds the WCP DLL
    #>
    
    if ($script:Config.WcpModuleLoaded -and $null -ne $script:Config.WcpDllPath) {
        return $true
    }
    
    $currentPath = Get-Location
    $modulePath = Join-Path $currentPath "WCPExtractor.psm1"
    
    if (-not (Test-Path $modulePath)) {
        Write-Error "WCPExtractor.psm1 not found in current directory: $currentPath"
        return $false
    }
    
    Import-Module $modulePath -Force -ErrorAction SilentlyContinue
    
    if (-not (Get-Module -Name WCPExtractor)) {
        Write-Error "Failed to load WCPExtractor module"
        return $false
    }
    
    $script:Config.WcpModuleLoaded = $true
    Write-VerboseMessage "WCPExtractor module loaded from: $modulePath"
    
    # Use PathToWcp if provided
    if (-not [string]::IsNullOrWhiteSpace($PathToWcp)) {
        if (Test-Path $PathToWcp) {
            $script:Config.WcpDllPath = $PathToWcp
            Write-VerboseMessage "Using specified WCP DLL: $PathToWcp"
        } else {
            Write-Error "Specified WCP DLL not found: $PathToWcp"
            return $false
        }
    }
    # Otherwise, find the WCP DLL using the module function
    elseif (Get-Command -Name Find-LatestWCPDll -ErrorAction SilentlyContinue) {
        $script:Config.WcpDllPath = Find-LatestWCPDll -ErrorAction SilentlyContinue
        if ($null -eq $script:Config.WcpDllPath) {
            Write-Error "Failed to find WCP DLL"
            return $false
        }
        Write-VerboseMessage "Found WCP DLL: $($script:Config.WcpDllPath)"
    } else {
        Write-Warning "Find-LatestWCPDll function not found in WCPExtractor module"
    }
    
    return $true
}

function Extract-ManifestFiles {
    <#
    .SYNOPSIS
        Extracts manifest files using WCPExtractor
    #>
    param([array]$ManifestFiles)
    
    if (-not (Initialize-WCPExtractor)) {
        return
    }
    
    foreach ($file in $ManifestFiles) {
        $fullInputPath = [System.IO.Path]::GetFullPath($file)
        $fullOutputPath = [System.IO.Path]::GetFullPath("$file.extracted")
        
        Write-VerboseMessage "Extracting: $fullInputPath"
        Write-VerboseMessage "Output to: $fullOutputPath"
        
        # Check if Expand-WCPFile function is available
        if (Get-Command -Name Expand-WCPFile -ErrorAction SilentlyContinue) {
            $params = @{
                InputFile = $fullInputPath
                OutputFile = $fullOutputPath
                ErrorAction = 'SilentlyContinue'
            }
            
            # Add WCP DLL path if available
            if ($null -ne $script:Config.WcpDllPath) {
                $params['WCPDllPath'] = $script:Config.WcpDllPath
            }
            
            Expand-WCPFile @params
            
            if (Test-Path $fullOutputPath) {
                Write-VerboseMessage "Successfully extracted"
            } else {
                Write-Warning "Failed to extract $fullInputPath"
            }
        } else {
            Write-Warning "Expand-WCPFile function not found in WCPExtractor module"
            break
        }
    }
}
#endregion

#region XML Processing Functions
function Parse-ManifestXml {
    <#
    .SYNOPSIS
        Parses extracted manifest XML files
    #>
    param([string]$XmlFilePath)
    
    $fullPath = [System.IO.Path]::GetFullPath($XmlFilePath)
    
    if (-not (Test-Path $fullPath)) {
        return $null
    }
    
    $xmlContent = Get-Content -Path $fullPath -Encoding UTF8 -ErrorAction SilentlyContinue
    
    if ($null -eq $xmlContent) {
        Write-Warning "Failed to read XML file: $fullPath"
        return $null
    }
    
    [xml]$xml = $xmlContent
    $assembly = $xml.assembly
    
    if ($null -eq $assembly) {
        return $null
    }
    
    $manifestInfo = [PSCustomObject]@{
        Name = $assembly.assemblyIdentity.name
        Version = $assembly.assemblyIdentity.version
        Architecture = $assembly.assemblyIdentity.processorArchitecture
        Language = $assembly.assemblyIdentity.language
        Files = @()
    }
    
    # Extract file information
    if ($null -ne $assembly.file) {
        foreach ($file in $assembly.file) {
            $fileInfo = [PSCustomObject]@{
                FileName = $file.name
                DestinationPath = $file.destinationPath
                SourceName = $file.sourceName
                ImportPath = $file.importPath
                SourcePath = $file.sourcePath
                ManifestName = [System.IO.Path]::GetFileName($fullPath)
                AssemblyName = $assembly.assemblyIdentity.name
            }
            $manifestInfo.Files += $fileInfo
            $script:Config.AllFiles += $fileInfo
        }
    }
    
    return $manifestInfo
}

function Show-FileInformation {
    <#
    .SYNOPSIS
        Displays file information in GridView and saves to CSV
    #>
    param(
        [array]$FilesList,
        [string]$Feature,
        [string]$OutputPath
    )
    
    if ($FilesList.Count -eq 0) {
        Write-Warning "No files found to display"
        return
    }
    
    # Display in GridView only if NotShowGridView is not set
    if (-not $NotShowGridView) {
        Write-Host "`nDisplaying file information in GridView..." -ForegroundColor Cyan
        $FilesList | Out-GridView -Title "Optional Feature Files for: $Feature"
    } else {
        Write-Host "`nGridView display skipped (NotShowGridView option is set)" -ForegroundColor Gray
    }
    
    # Prepare safe filename for CSV
    $safeFeatureName = if ([string]::IsNullOrWhiteSpace($Feature)) { 
        "AllFeatures" 
    } else { 
        $Feature -replace '[^\w\-]', '_' 
    }
    
    $csvPath = Join-Path $OutputPath "OptionalFeatureFiles_$safeFeatureName.csv"
    
    $FilesList | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
    
    if (Test-Path $csvPath) {
        Write-Host "File information saved to: $csvPath" -ForegroundColor Green
    } else {
        Write-Warning "Failed to save CSV file"
    }
}
#endregion

#region Main Execution
function Main {
    # Check for help parameter
    if ($Help) {
        Show-Help
        return
    }
    
    # Display header
    Write-Header -Title "$($script:Config.ScriptName) v$($script:Config.Version) - Optional Feature File Extractor"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "This script requires PowerShell 7.0 or higher. Current version: $($PSVersionTable.PSVersion)"
        return
    }
    
    # Handle SearchWcpDll option
    if ($SearchWcpDll) {
        Write-Host "`nSearching for wcp.dll using WCPExtractor module..." -ForegroundColor Cyan
        
        # Load WCPExtractor module
        $currentPath = Get-Location
        $modulePath = Join-Path $currentPath "WCPExtractor.psm1"
        
        if (-not (Test-Path $modulePath)) {
            Write-Error "WCPExtractor.psm1 not found in current directory: $currentPath"
            return
        }
        
        Import-Module $modulePath -Force -ErrorAction SilentlyContinue
        
        if (-not (Get-Module -Name WCPExtractor)) {
            Write-Error "Failed to load WCPExtractor module"
            return
        }
        
        # Call Find-LatestWCPDll
        if (Get-Command -Name Find-LatestWCPDll -ErrorAction SilentlyContinue) {
            $wcpPath = Find-LatestWCPDll -ErrorAction SilentlyContinue
            if ($null -ne $wcpPath) {
                Write-Host "`nFound wcp.dll:" -ForegroundColor Green
                Write-Host "  Path: $wcpPath" -ForegroundColor Yellow
                
                # Get version info if file exists
                if (Test-Path $wcpPath) {
                    $fileInfo = Get-Item $wcpPath
                    Write-Host "  Version: $($fileInfo.VersionInfo.FileVersion)" -ForegroundColor Gray
                }
            } else {
                Write-Warning "Find-LatestWCPDll returned no results"
            }
        } else {
            Write-Error "Find-LatestWCPDll function not found in WCPExtractor module"
        }
        
        if ([string]::IsNullOrWhiteSpace($FeatureName)) {
            return
        }
    }
    
    # Check if FeatureName is provided and valid
    if ([string]::IsNullOrWhiteSpace($FeatureName)) {
        Write-Host "`nNo feature name specified. Showing installed optional features..." -ForegroundColor Yellow
        Show-InstalledFeatures | Out-Null
        return
    }
    
    # Verify feature exists
    if (-not (Test-FeatureExists -Feature $FeatureName)) {
        Write-Host "`nShowing installed optional features..." -ForegroundColor Yellow
        Show-InstalledFeatures | Out-Null
        return
    }
    
    # Create feature-specific output directory
    $featureOutputDir = Get-FeatureOutputDirectory -Feature $FeatureName
    Write-Host "`nOutput directory: $featureOutputDir" -ForegroundColor Green
    
    # Find packages with the feature
    Write-Header -Title "Searching for packages" -Color Yellow
    $packages = Get-PackagesWithFeature -Feature $FeatureName
    
    if ($packages.Count -eq 0) {
        Write-Warning "No packages found containing feature '$FeatureName'"
        return
    }
    
    Write-Host "Found $($packages.Count) package(s) with the feature" -ForegroundColor Green
    foreach ($pkg in $packages) {
        Write-Host "  - $($pkg.PackageName) [$($pkg.Source)]" -ForegroundColor Gray
    }
    
    # Collect MUM files for processing if enabled
    $mumFilesToProcess = @()
    
    # Find manifest files
    $allManifests = @()
    
    foreach ($package in $packages) {
        Write-VerboseMessage "Processing package: $($package.PackageName)"
        
        # Generate manifest name and find files
        $manifestPrefix = Get-ManifestFileName -PackageName $package.PackageName
        $manifests = Find-ManifestFiles -ManifestPrefix $manifestPrefix
        
        if ($manifests.Count -gt 0) {
            $allManifests += $manifests
        }
        
        # Check for owner packages
        $ownerPackages = Get-OwnerPackages -PackageName $package.PackageName
        
        foreach ($ownerPackage in $ownerPackages) {
            Write-VerboseMessage "Processing owner package: $($ownerPackage.PackageName)"
            
            # Collect MUM file names if ParsingMum is enabled
            if ($ParsingMum -and -not [string]::IsNullOrWhiteSpace($ownerPackage.InstallName)) {
                $mumFilesToProcess += $ownerPackage.InstallName
            }
            
            $ownerManifestPrefix = Get-ManifestFileName -PackageName $ownerPackage.PackageName
            $ownerManifests = Find-ManifestFiles -ManifestPrefix $ownerManifestPrefix
            
            if ($ownerManifests.Count -gt 0) {
                $allManifests += $ownerManifests
            }
        }
    }
    
    # Process MUM files if enabled
    if ($ParsingMum -and $mumFilesToProcess.Count -gt 0) {
        Write-Header -Title "Processing MUM files" -Color Yellow
        $mumComponents = Process-MumFiles -MumFileNames $mumFilesToProcess
        
        if ($mumComponents.Count -gt 0) {
            Write-Host "Found $($mumComponents.Count) component(s) in MUM files" -ForegroundColor Green
            
            # Find manifest files for MUM components
            foreach ($component in $mumComponents) {
                $componentManifestPrefix = Get-ManifestFileName -PackageName $component
                $componentManifests = Find-ManifestFiles -ManifestPrefix $componentManifestPrefix
                
                if ($componentManifests.Count -gt 0) {
                    $allManifests += $componentManifests
                }
            }
        }
    }
    
    # Remove duplicates
    $allManifests = $allManifests | Select-Object -Unique
    
    Write-Host "`nFound $($allManifests.Count) manifest file(s)" -ForegroundColor Green
    
    if ($allManifests.Count -eq 0) {
        Write-Warning "No manifest files found"
        return
    }
    
    # Copy manifest files
    Write-Header -Title "Copying manifest files" -Color Yellow
    $copiedFiles = Copy-ManifestFiles -ManifestFiles $allManifests -Destination $featureOutputDir
    
    # Extract manifest files
    Write-Header -Title "Extracting manifest files" -Color Yellow
    Extract-ManifestFiles -ManifestFiles $copiedFiles
    
    # Parse extracted XML files
    Write-Header -Title "Parsing manifest files" -Color Yellow
    
    foreach ($copiedFile in $copiedFiles) {
        $extractedFile = "$copiedFile.extracted"
        
        if (Test-Path $extractedFile) {
            Write-VerboseMessage "Parsing: $extractedFile"
            Parse-ManifestXml -XmlFilePath $extractedFile | Out-Null
        }
    }
    
    # Display results
    if ($script:Config.AllFiles.Count -gt 0) {
        Write-Host "`nFound $($script:Config.AllFiles.Count) file(s) in manifests" -ForegroundColor Green
        Show-FileInformation -FilesList $script:Config.AllFiles -Feature $FeatureName -OutputPath $featureOutputDir
    } else {
        Write-Warning "No file information found in manifests"
    }
    
    Write-Host "`nScript completed!" -ForegroundColor Green
}

# Execute main function
Main
#endregion