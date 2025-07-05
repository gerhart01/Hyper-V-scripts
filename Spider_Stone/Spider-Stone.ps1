param(
    [Parameter(Mandatory=$true)]
    [string]$FeatureName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = ".\OptionalFeatureFiles",
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput = $false
)

# Script version
$ScriptVersion = "0.0.1"

# Registry paths
$OptionalFeaturesRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures"
$PackagesRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
$ManifestsPath = "C:\Windows\WinSxS\Manifests"

# Function to write verbose output
function Write-VerboseOutput {
    param([string]$Message)
    if ($VerboseOutput) {
        Write-Host $Message -ForegroundColor Yellow
    }
}

# Function to clean package name for manifest search
function Get-CleanedPackageName {
    param([string]$PackageName)
    
    # Add AMD64_ prefix
    $cleanedName = "AMD64_$PackageName"
    
    # Remove package suffixes and everything after them
    $suffixes = @("-FOD-Package", "-Opt-Package", "-Package")
    foreach ($suffix in $suffixes) {
        if ($cleanedName -like "*$suffix*") {
            $cleanedName = $cleanedName.Split($suffix)[0]
            break
        }
    }
    
    return $cleanedName
}

# Function to find and copy manifest file
function Find-AndCopyManifest {
    param(
        [string]$PackageName,
        [string]$DestinationPath
    )
    
    $cleanedName = Get-CleanedPackageName -PackageName $PackageName
    $manifestPattern = "$cleanedName*.manifest"
    
    Write-VerboseOutput "Searching for manifest: $manifestPattern"
    
    $manifestFiles = Get-ChildItem -Path $ManifestsPath -Filter $manifestPattern -ErrorAction SilentlyContinue
    
    foreach ($manifestFile in $manifestFiles) {
        Write-Host "Found manifest: $($manifestFile.Name)" -ForegroundColor Green
        
        try {
            Copy-Item -Path $manifestFile.FullName -Destination $DestinationPath -Force
            Write-Host "Copied: $($manifestFile.Name)" -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Failed to copy $($manifestFile.Name): $($_.Exception.Message)"
        }
    }
    
    return $manifestFiles.Count
}

# Function to search in Updates subkeys
function Search-InUpdatesSubkeys {
    param([string]$DestinationPath)
    
    Write-VerboseOutput "Searching in Updates subkeys..."
    $foundCount = 0
    $foundPackages = @()
    
    try {
        $packagesKeys = Get-ChildItem -Path $PackagesRegPath -ErrorAction SilentlyContinue
        
        foreach ($packageKey in $packagesKeys) {
            $updatesPath = Join-Path $packageKey.PSPath "Updates"
            
            if (Test-Path $updatesPath) {
                try {
                    $updatesKey = Get-Item -Path $updatesPath -ErrorAction SilentlyContinue
                    $propertyNames = $updatesKey.GetValueNames()
                    
                    if ($propertyNames -contains $FeatureName) {
                        Write-VerboseOutput "Found feature in Updates: $($packageKey.PSChildName)"
                        $parentPackageName = $packageKey.PSChildName
                        $foundPackages += $parentPackageName
                        $foundCount += Find-AndCopyManifest -PackageName $parentPackageName -DestinationPath $DestinationPath
                    }
                }
                catch {
                    Write-VerboseOutput "Error accessing Updates in $($packageKey.PSChildName): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "Error searching in Updates subkeys: $($_.Exception.Message)"
    }
    
    return @{
        Count = $foundCount
        Packages = $foundPackages
    }
}

# Function to search in Owners subkeys for packages found in Updates
function Search-InOwnersSubkeys {
    param(
        [string]$DestinationPath,
        [array]$FoundPackages
    )
    
    Write-VerboseOutput "Searching in Owners subkeys for found packages..."
    $foundCount = 0
    
    try {
        $packagesKeys = Get-ChildItem -Path $PackagesRegPath -ErrorAction SilentlyContinue
        
        foreach ($packageKey in $packagesKeys) {
            $ownersPath = Join-Path $packageKey.PSPath "Owners"
            
            if (Test-Path $ownersPath) {
                try {
                    $ownersKey = Get-Item -Path $ownersPath -ErrorAction SilentlyContinue
                    $propertyNames = $ownersKey.GetValueNames()
                    
                    # Check if any of the found packages are present as parameters in this Owners key
                    foreach ($foundPackage in $FoundPackages) {
                        if ($propertyNames -contains $foundPackage) {
                            Write-VerboseOutput "Found package '$foundPackage' in Owners of: $($packageKey.PSChildName)"
                            $parentPackageName = $packageKey.PSChildName
                            $foundCount += Find-AndCopyManifest -PackageName $parentPackageName -DestinationPath $DestinationPath
                            break # No need to check other packages for this Owners key
                        }
                    }
                }
                catch {
                    Write-VerboseOutput "Error accessing Owners in $($packageKey.PSChildName): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "Error searching in Owners subkeys: $($_.Exception.Message)"
    }
    
    return $foundCount
}

# Function to extract manifest files using wcpex.exe
function Extract-ManifestFiles {
    param([string]$ManifestDirectory)
    
    Write-Host "`nStep 4: Extracting manifest files..." -ForegroundColor Yellow
    
    # Check if wcpex.exe exists in current directory
    $wcpexPath = ".\wcpex.exe"
    if (-not (Test-Path $wcpexPath)) {
        Write-Warning "wcpex.exe not found in current directory. Skipping extraction."
        Write-Host "Please ensure wcpex.exe is in the same directory as this script." -ForegroundColor Yellow
        return 0
    }
    
    $manifestFiles = Get-ChildItem -Path $ManifestDirectory -Filter "*.manifest" -ErrorAction SilentlyContinue
    $extractedCount = 0
    
    if ($manifestFiles.Count -eq 0) {
        Write-Host "No manifest files found to extract." -ForegroundColor Yellow
        return 0
    }
    
    foreach ($manifestFile in $manifestFiles) {
        $inputFile = $manifestFile.FullName
        $outputFile = $manifestFile.FullName + ".extracted"
        
        Write-VerboseOutput "Extracting: $($manifestFile.Name)"
        
        try {
            # Execute wcpex.exe
            $process = Start-Process -FilePath $wcpexPath -ArgumentList "`"$inputFile`"", "`"$outputFile`"" -Wait -PassThru -NoNewWindow -RedirectStandardError "nul"
            
            if ($process.ExitCode -eq 0 -and (Test-Path $outputFile)) {
                Write-Host "Extracted: $($manifestFile.Name) -> $($manifestFile.Name).extracted" -ForegroundColor Green
                $extractedCount++
            } else {
                Write-Warning "Failed to extract $($manifestFile.Name) (Exit code: $($process.ExitCode))"
            }
        }
        catch {
            Write-Warning "Error extracting $($manifestFile.Name): $($_.Exception.Message)"
        }
    }
    
    return $extractedCount
}

function Get-ManifestFileInfo {
    param(
        [string]$XmlFilePath
    )
    
    try {
        if ($Verbose) { 
            Write-Host "Processing: $XmlFilePath" -ForegroundColor Yellow 
        }
        
        # Load XML content
        [xml]$xmlContent = Get-Content -Path $XmlFilePath -Encoding UTF8
        
        # Get assembly information
        $assembly = $xmlContent.assembly
        $assemblyIdentity = $assembly.assemblyIdentity
        
        # Extract file elements
        $files = $assembly.file
        
        $fileInfoList = @()
        
        if ($files) {
            # Handle both single file and multiple files
            if ($files -is [System.Array]) {
                $fileArray = $files
            } else {
                $fileArray = @($files)
            }
            
            foreach ($file in $fileArray) {
                $fileInfo = [PSCustomObject]@{
                    'SourceManifest' = Split-Path $XmlFilePath -Leaf
                    'AssemblyName' = $assemblyIdentity.name
                    'AssemblyVersion' = $assemblyIdentity.version
                    'Language' = $assemblyIdentity.language
                    'Architecture' = $assemblyIdentity.processorArchitecture
                    'FileName' = $file.name
                    'DestinationPath' = $file.destinationPath
                    'SourceName' = $file.sourceName
                    'ImportPath' = $file.importPath
                    'SourcePath' = $file.sourcePath
                    'SecurityDescriptor' = $file.securityDescriptor.name
                }
                
                # Add hash information if requested and available
                if ($IncludeHashInfo -and $file.hash) {
                    $hashInfo = $file.hash
                    $fileInfo | Add-Member -NotePropertyName 'DigestMethod' -NotePropertyValue $hashInfo.DigestMethod.Algorithm
                    $fileInfo | Add-Member -NotePropertyName 'DigestValue' -NotePropertyValue $hashInfo.DigestValue
                    
                    # Transform information
                    if ($hashInfo.Transforms -and $hashInfo.Transforms.Transform) {
                        $fileInfo | Add-Member -NotePropertyName 'HashTransform' -NotePropertyValue $hashInfo.Transforms.Transform.Algorithm
                    }
                }
                
                $fileInfoList += $fileInfo
            }
        }
        
        return $fileInfoList
    }
    catch {
        Write-Warning "Failed to parse $XmlFilePath : $($_.Exception.Message)"
        return @()
    }
}

function Extracted-FileParsing()
{
    param(
    [Parameter(Mandatory=$false)]
    [string]$InputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$FilePattern = "*.manifest.extracted",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeHashInfo = $true
)    
    
    try 
        {
            Write-Host "XML Manifest Files Parser" -ForegroundColor Green
            Write-Host "=========================" -ForegroundColor Green
            Write-Host "Search Path: $InputPath"
            Write-Host "File Pattern: $FilePattern"
            Write-Host "Include Hash Info: $IncludeHashInfo"
            Write-Host ""
            
            # Find XML/manifest files
            $xmlFiles = Get-ChildItem -Path $InputPath -Filter $FilePattern -Recurse
            
            if ($xmlFiles.Count -eq 0) {
                # Try alternative patterns
                Write-Host "No files found with pattern '$FilePattern', trying '*.xml'..." -ForegroundColor Yellow
                $xmlFiles = Get-ChildItem -Path $InputPath -Filter "*.extracted" -Recurse
                
                if ($xmlFiles.Count -eq 0) {
                    throw "No XML or manifest files found in: $InputPath"
                }
            }
            
            Write-Host "Found $($xmlFiles.Count) files to process" -ForegroundColor Cyan
            
            # Process all files
            $allFileInfo = @()
            
            foreach ($file in $xmlFiles) {
                if ($Verbose) {
                    Write-Host "Processing: $($file.Name)" -ForegroundColor Gray
                }
                
                $fileInfo = Get-ManifestFileInfo -XmlFilePath $file.FullName
                $allFileInfo += $fileInfo
            }
            
            # Display results
            if ($allFileInfo.Count -gt 0) {
                Write-Host "`nFound $($allFileInfo.Count) file entries across $($xmlFiles.Count) manifests" -ForegroundColor Green
                Write-Host "Opening results in GridView..." -ForegroundColor Yellow
                
                # Show in GridView with title
                $allFileInfo | Out-GridView -Title "XML Manifest Files Information - $($allFileInfo.Count) entries found"
                
                # Also display summary in console
                Write-Host "`nSummary:" -ForegroundColor Cyan
                Write-Host "=========" -ForegroundColor Cyan
                
                $groupedByAssembly = $allFileInfo | Group-Object AssemblyName
                foreach ($group in $groupedByAssembly) {
                    Write-Host "$($group.Name): $($group.Count) file(s)" -ForegroundColor Gray
                }
                
                $groupedByLanguage = $allFileInfo | Group-Object Language
                Write-Host "`nLanguages found:" -ForegroundColor Cyan
                foreach ($langGroup in $groupedByLanguage) {
                    Write-Host "  $($langGroup.Name): $($langGroup.Count) file(s)" -ForegroundColor Gray
                }
            }
        else 
        {
            Write-Warning "No file information found in the processed XML files"
            Write-Host "This script expects XML manifest files with <file> elements" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Script execution failed: $($_.Exception.Message)"
        exit 1
    }
}

# Main execution
try {
    Write-Host "Spider Stone - Windows Optional Feature Files Finder and Extractor v$ScriptVersion" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "Feature Name: $FeatureName"
    Write-Host "Output Directory: $OutputDirectory"
    Write-Host ""
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script requires administrator privileges for full registry access."
    }
    
    # Step 1: Check if optional feature exists as a subkey in Notifications\OptionalFeatures
    Write-Host "Step 1: Checking if optional feature exists as subkey in OptionalFeatures..." -ForegroundColor Yellow
    
    if (-not (Test-Path $OptionalFeaturesRegPath)) {
        throw "Optional Features registry path not found: $OptionalFeaturesRegPath"
    }
    
    $featureFound = $false
    $allAvailableFeatures = @()
    
    try {
        # Check if there is a subkey with the same name as FeatureName
        $featureSubkeyPath = Join-Path $OptionalFeaturesRegPath $FeatureName
        
        if (Test-Path $featureSubkeyPath) {
            $featureFound = $true
            Write-VerboseOutput "Found feature subkey '$FeatureName' in OptionalFeatures"
            Write-Host "Optional feature '$FeatureName' found as subkey in registry." -ForegroundColor Green
        } else {
            # Collect available subkeys for display
            $optionalFeaturesSubkeys = Get-ChildItem -Path $OptionalFeaturesRegPath -ErrorAction SilentlyContinue
            
            foreach ($subkey in $optionalFeaturesSubkeys) {
                $allAvailableFeatures += $subkey.PSChildName
            }
            
            Write-Warning "Optional feature subkey '$FeatureName' not found in registry."
            Write-Host "Available optional feature subkeys:" -ForegroundColor Cyan
            $allAvailableFeatures | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            return
        }
    }
    catch {
        Write-Warning "Error accessing Optional Features registry: $($_.Exception.Message)"
    }
    
    # Create output directory
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Cyan
    }
    
    # Check if manifests directory exists
    if (-not (Test-Path $ManifestsPath)) {
        throw "Manifests directory not found: $ManifestsPath"
    }
    
    $totalFound = 0
    
    # Step 2: Search in Updates subkeys
    Write-Host "`nStep 2: Searching in Updates subkeys..." -ForegroundColor Yellow
    $updatesResult = Search-InUpdatesSubkeys -DestinationPath $OutputDirectory
    $totalFound += $updatesResult.Count
    $foundPackages = $updatesResult.Packages
    
    # Step 3: Search in Owners subkeys for packages found in Updates
    Write-Host "`nStep 3: Searching in Owners subkeys..." -ForegroundColor Yellow
    if ($foundPackages.Count -gt 0) {
        $totalFound += Search-InOwnersSubkeys -DestinationPath $OutputDirectory -FoundPackages $foundPackages
    } else {
        Write-Host "No packages found in Updates step, skipping Owners search." -ForegroundColor Yellow
    }
    
    # Step 4: Extract manifest files using wcpex.exe
    $extractedCount = Extract-ManifestFiles -ManifestDirectory $OutputDirectory
    
    # Summary
    Write-Host "`nProcessing Complete!" -ForegroundColor Green
    Write-Host "====================" -ForegroundColor Green
    Write-Host "Feature Name: $FeatureName"
    Write-Host "Manifest files found: $totalFound"
    Write-Host "Files extracted: $extractedCount"
    Write-Host "Output directory: $OutputDirectory"
    
    if ($totalFound -gt 0) {
        Write-Host "`nCopied manifest files:" -ForegroundColor Cyan
        Get-ChildItem -Path $OutputDirectory -Filter "*.manifest" | ForEach-Object {
            Write-Host "  $($_.Name)" -ForegroundColor Gray
        }
        
        if ($extractedCount -gt 0) {
            Write-Host "`nExtracted files:" -ForegroundColor Cyan
            Get-ChildItem -Path $OutputDirectory -Filter "*.extracted" | ForEach-Object {
                Write-Host "  $($_.Name)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "No manifest files found for this optional feature." -ForegroundColor Yellow
    }
    
    if ($foundPackages.Count -gt 0) {
        Write-Host "`nPackages found in Updates:" -ForegroundColor Magenta
        $foundPackages | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

Extracted-FileParsing $OutputDirectory

# Usage Examples:
<#
# Script Version: 0.0.1

# Basic usage
.\Spider-Stone.ps1 -FeatureName "Microsoft-Windows-Subsystem-Linux"

# With custom output directory
.\Spider-Stone.ps1 -FeatureName "Microsoft-Windows-Subsystem-Linux" -OutputDirectory "C:\WSLManifests"

# With verbose output
.\Spider-Stone.ps1 -FeatureName "Microsoft-Windows-Subsystem-Linux" -VerboseOutput

# Search for specific feature
.\Spider-Stone.ps1 -FeatureName "TelnetClient" -OutputDirectory ".\TelnetFiles" -VerboseOutput
#>