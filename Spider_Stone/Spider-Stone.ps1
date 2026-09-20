#Requires -Version 7.0

<#
.SYNOPSIS
    Reconstructs the "Optional Feature -> packages -> components -> files" chain and
    exports the full component footprint to CSV and HTML.
.DESCRIPTION
    Given a Windows Optional Feature name, the script locates the related packages and
    WinSxS manifests via Component-Based Servicing (CBS) data, decompresses the
    WCP-compressed manifests with the WCPExtractor module (wcp.dll), and parses them:
    files with hashes, dependencies, registry, categories, directories, localization,
    ETW providers, scheduled tasks and other markers. The result is one CSV per data
    kind plus a self-contained HTML report. Runs fully locally.

    A bilingual (English + Russian) help screen is available via -Help / -?.
.PARAMETER FeatureName
    Name of the Windows Optional Feature to analyze. Without it, the script lists the
    installed features.
.PARAMETER OutputDirectory
    Directory for results (copied manifests, CSV, HTML). Default: .\OptionalFeatureFiles
.PARAMETER VerboseOutput
    Verbose progress logging.
.PARAMETER ParsingMum
    Recursively parse MUM files from C:\Windows\servicing\Packages.
.PARAMETER NotShowGridView
    Do not open the results in Out-GridView.
.PARAMETER OpenReport
    Open the generated HTML report in the default browser when the run finishes.
.PARAMETER ComponentFilter
    Output only components whose name contains this word (case-insensitive
    substring). Filters files, dependencies, registry, CSVs, HTML and GridView.
.PARAMETER PathToWcp
    Explicit path to wcp.dll used to decompress manifests.
.PARAMETER SearchWcpDll
    Find and show the latest wcp.dll for the system architecture
    (WCPExtractor\Find-LatestWCPDll), then exit.
.PARAMETER Help
    Show the built-in help (alias -?).
.EXAMPLE
    .\Spider-Stone.ps1
    List the installed Optional Features.
.EXAMPLE
    .\Spider-Stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput
    Analyze a feature with recursive MUM parsing and verbose logging.
.EXAMPLE
    .\Spider-Stone.ps1 -SearchWcpDll
    Find the latest wcp.dll for the current architecture.
.EXAMPLE
    .\Spider-Stone.ps1 -FeatureName "Containers" -ComponentFilter "Defender"
    Analyze a feature but output only components whose name contains "Defender".
.EXAMPLE
    .\Spider-Stone.ps1 -FeatureName "DiskIo-QoS"
    Analyze a feature. The HTML report (Report_DiskIo-QoS.html) is generated
    automatically in the output directory - no separate switch is needed. Its path is
    printed to the console when the run finishes.
.NOTES
    Version : 0.0.2
    Author  : Spider Stone
    Requires: PowerShell 7.0+, WCPExtractor.psm1 module in the same folder.
              Administrator rights recommended (CBS registry, WinSxS files).
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

    [switch]$OpenReport,

    [Parameter(Mandatory = $false)]
    [string]$ComponentFilter,

    [Parameter(Mandatory = $false)]
    [string]$PathToWcp,
    
    [switch]$SearchWcpDll,
    
    [Parameter(Mandatory = $false)]
    [Alias("?")]
    [switch]$Help
)

#region Console Encoding
# Force UTF-8 console output so Cyrillic text (progress bars, help, messages) and
# other non-ASCII names render correctly instead of as "????" on consoles whose
# active code page is not UTF-8 (the common cause of garbled output). Wrapped in
# try/catch because redirected or non-interactive hosts can reject the change.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
    # No real console (output redirected to a file/pipe); text still writes fine.
}
#endregion

#region Script Configuration
$script:Config = @{
    Version = "0.0.2"
    ScriptName = "Spider Stone"
    AllFiles = @()
    # Component-level collections extracted from manifests (each exported to its own CSV)
    Components    = @()   # one row per manifest: full assemblyIdentity + display name + counts
    Dependencies  = @()   # dependentAssembly edges (component -> component)
    RegistryItems = @()   # registryKey/registryValue the component installs
    Categories    = @()   # categoryMembership (component -> feature/category)
    Directories   = @()   # directory entries the component owns/creates
    Strings       = @()   # localization stringTable (displayName/description/...)
    Providers     = @()   # ETW providers the component registers
    Tasks         = @()   # scheduled tasks the component installs
    Extras        = @()   # deployment/infFile/appxRegistration/serviceData/migration markers
    WcpModuleLoaded = $false
    WcpDllPath = $null
    ProcessedMumFiles = @()
    RegistryPaths = @{
        OptionalFeatures = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures"
        Packages = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        UpdateDetect = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\UpdateDetect"
    }
    ManifestsPath = (Join-Path $env:SystemRoot "WinSxS\Manifests")
    ServicingPath = (Join-Path $env:SystemRoot "servicing\Packages")
    SuffixesToRemove = @("-fod-package", "-opt-package", "-package")
    # Architecture prefixes of WinSxS manifest file names
    # (<arch>_<name>_<pubKey>_<ver>_<lang>_<hash>.manifest). A feature on x64 also stages
    # wow64/x86/msil components (~1/4 of all manifests), so ALL are searched - not just the
    # running architecture, which would silently miss those components.
    ManifestArchPrefixes = @("amd64", "wow64", "x86", "msil", "arm64", "arm")
}
#endregion

#region Help Function
function Show-Help {
    <#
    .SYNOPSIS
        Displays help information for the script
    #>
    
    $helpText = @"

$($script:Config.ScriptName) v$($script:Config.Version) - Windows Optional Feature analyzer
Chain: feature -> packages -> components -> files. Output: CSV + HTML report. Fully local.

================================  ENGLISH  ================================

USAGE:
    .\Spider-Stone.ps1 [-FeatureName <string>] [-OutputDirectory <string>] [-ParsingMum]
                       [-NotShowGridView] [-OpenReport] [-ComponentFilter <string>]
                       [-PathToWcp <string>] [-SearchWcpDll] [-VerboseOutput] [-Help]

PARAMETERS:
    -FeatureName <string>
        Name of the Windows Optional Feature to analyze.
        Without it, the installed features are listed.

    -OutputDirectory <string>
        Directory for results (manifests, CSV, HTML).
        Default: .\OptionalFeatureFiles

    -ParsingMum
        Recursively parse MUM files from C:\Windows\servicing\Packages.

    -NotShowGridView
        Do not open the results in Out-GridView.

    -OpenReport
        Open the generated HTML report in the default browser when done.

    -ComponentFilter <string>
        Output only components whose name contains this word (case-insensitive).
        Filters files, dependencies, registry, CSVs, HTML and GridView.

    -PathToWcp <string>
        Explicit path to wcp.dll used to decompress manifests.

    -SearchWcpDll
        Find and show the latest wcp.dll for the system architecture
        (WCPExtractor\Find-LatestWCPDll), then exit.

    -VerboseOutput
        Verbose progress logging.

    -Help, -?
        Show this help.

EXAMPLES:
    # List installed features
    .\Spider-Stone.ps1

    # Analyze a specific feature
    .\Spider-Stone.ps1 -FeatureName "Windows-Defender-Default-Definitions"

    # With recursive MUM parsing and verbose log
    .\Spider-Stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput

    # Only components whose name contains "Defender"
    .\Spider-Stone.ps1 -FeatureName "Containers" -ComponentFilter "Defender"

    # Custom output directory, no GridView
    .\Spider-Stone.ps1 -FeatureName "RSAT" -OutputDirectory "C:\Temp\RSAT" -NotShowGridView

    # Use a specific wcp.dll
    .\Spider-Stone.ps1 -FeatureName "RSAT" -PathToWcp "C:\Windows\System32\wcp.dll"

    # Just find the latest wcp.dll
    .\Spider-Stone.ps1 -SearchWcpDll

OUTPUT (in <OutputDirectory>\<Feature>\):
    OptionalFeatureFiles_*.csv  component files (hashes, paths, SDDL, hardlinks)
    Components_*.csv            one row per component (identity + DisplayName)
    Dependencies_*.csv          component -> component dependencies
    Registry_*.csv              component registry footprint
    Categories_*.csv            category/feature membership
    Directories_*.csv           component directories + SDDL
    Strings_*.csv               localization (displayName/description)
    Providers_*.csv             ETW providers
    Tasks_*.csv                 scheduled tasks
    Extras_*.csv                deployment/infFile/appx/service/migration markers
    Report_*.html              summary HTML report (dark/light theme)

HTML REPORT:
    Generated automatically for any feature analysis - no separate switch needed.
    Just pass -FeatureName; the file path is printed to the console when done
    (line "HTML report : ..."). The path is shown as a terminal hyperlink, but
    note that Windows Terminal only opens http/https links on click - to open the
    local report automatically, add -OpenReport (launches the default browser).
    The file is self-contained, opens in a browser with no internet. Example:
        .\Spider-Stone.ps1 -FeatureName "DiskIo-QoS"
        # -> <OutputDirectory>\DiskIo-QoS\Report_DiskIo-QoS.html
    Open it right after the analysis:
        Invoke-Item .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html

NOTES:
    - Requires PowerShell 7.0 or newer
    - Requires the WCPExtractor.psm1 module in the same folder
    - Administrator rights recommended (CBS registry, WinSxS files)


================================  РУССКИЙ  ================================

ИСПОЛЬЗОВАНИЕ:
    .\Spider-Stone.ps1 [-FeatureName <string>] [-OutputDirectory <string>] [-ParsingMum]
                       [-NotShowGridView] [-OpenReport] [-ComponentFilter <string>]
                       [-PathToWcp <string>] [-SearchWcpDll] [-VerboseOutput] [-Help]

ПАРАМЕТРЫ:
    -FeatureName <string>
        Имя Windows Optional Feature для анализа.
        Без него выводится список установленных фич.

    -OutputDirectory <string>
        Каталог для результатов (манифесты, CSV, HTML).
        По умолчанию: .\OptionalFeatureFiles

    -ParsingMum
        Рекурсивно разбирать MUM-файлы из C:\Windows\servicing\Packages.

    -NotShowGridView
        Не открывать результаты в Out-GridView.

    -OpenReport
        Открыть готовый HTML-отчёт в браузере по умолчанию по завершении.

    -ComponentFilter <string>
        Выводить только компоненты, чьё наименование содержит это слово (без учёта
        регистра). Фильтрует файлы, зависимости, реестр, CSV, HTML и GridView.

    -PathToWcp <string>
        Явный путь к wcp.dll для распаковки манифестов.

    -SearchWcpDll
        Найти и показать актуальную wcp.dll под разрядность системы
        (WCPExtractor\Find-LatestWCPDll) и выйти.

    -VerboseOutput
        Подробное логирование хода работы.

    -Help, -?
        Показать эту справку.

ПРИМЕРЫ:
    # Список установленных фич
    .\Spider-Stone.ps1

    # Анализ конкретной фичи
    .\Spider-Stone.ps1 -FeatureName "Windows-Defender-Default-Definitions"

    # С рекурсивным разбором MUM и подробным логом
    .\Spider-Stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput

    # Только компоненты, чьё наименование содержит "Defender"
    .\Spider-Stone.ps1 -FeatureName "Containers" -ComponentFilter "Defender"

    # Свой каталог вывода, без GridView
    .\Spider-Stone.ps1 -FeatureName "RSAT" -OutputDirectory "C:\Temp\RSAT" -NotShowGridView

    # Указать конкретную wcp.dll
    .\Spider-Stone.ps1 -FeatureName "RSAT" -PathToWcp "C:\Windows\System32\wcp.dll"

    # Просто найти актуальную wcp.dll
    .\Spider-Stone.ps1 -SearchWcpDll

ВЫХОДНЫЕ ДАННЫЕ (в <OutputDirectory>\<Feature>\):
    OptionalFeatureFiles_*.csv  файлы компонентов (хэши, пути, SDDL, хардлинки)
    Components_*.csv            по строке на компонент (identity + DisplayName)
    Dependencies_*.csv          зависимости компонент -> компонент
    Registry_*.csv              реестровый след компонента
    Categories_*.csv            членство в категориях/фичах
    Directories_*.csv           каталоги компонента + SDDL
    Strings_*.csv               локализация (displayName/description)
    Providers_*.csv             ETW-провайдеры
    Tasks_*.csv                 задачи планировщика
    Extras_*.csv                deployment/infFile/appx/service/migration-маркеры
    Report_*.html              сводный HTML-отчёт (тёмная/светлая тема)

HTML-ОТЧЁТ:
    Формируется автоматически при анализе любой фичи — отдельный ключ не нужен.
    Достаточно указать -FeatureName; по завершении путь к файлу выводится в консоль
    (строка "HTML report : ..."). Путь показывается как гиперссылка, но Windows
    Terminal по клику открывает только http/https — чтобы локальный отчёт открылся
    автоматически, добавьте -OpenReport (запустит браузер по умолчанию). Файл
    самодостаточный, открывается в браузере без интернета. Пример:
        .\Spider-Stone.ps1 -FeatureName "DiskIo-QoS"
        # -> <OutputDirectory>\DiskIo-QoS\Report_DiskIo-QoS.html
    Открыть сразу после анализа:
        Invoke-Item .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html

ЗАМЕЧАНИЯ:
    - Требуется PowerShell 7.0 или новее
    - Требуется модуль WCPExtractor.psm1 в той же папке
    - Для чтения реестра CBS и файлов WinSxS рекомендуются права администратора

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

function Write-StageProgress {
    <#
    .SYNOPSIS
        Draws a Write-Progress bar and, when driven by a front-end (e.g. the GUI),
        also emits a machine-readable progress line.
    .DESCRIPTION
        Always renders the normal Write-Progress bar (unchanged CLI behavior).
        Additionally, only when the environment variable SPIDERSTONE_PROGRESS_STDOUT
        equals '1', writes a parseable marker to the host stream:
            ##PROGRESS##|<Activity>|<Percent>|<Status>
        Write-Host is used on purpose: it does not go to the success (output) stream,
        so it never pollutes the return value of the calling function.
    #>
    param(
        [Parameter(Mandatory)][string]$Activity,
        [int]$PercentComplete = 0,
        [string]$Status = "",
        [switch]$Completed
    )

    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
    } else {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }

    if ($env:SPIDERSTONE_PROGRESS_STDOUT -eq '1') {
        $pct = if ($Completed) { 100 } else { $PercentComplete }
        Write-Host "##PROGRESS##|$Activity|$pct|$Status"
    }
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

    # Machine-readable feature list for a front-end (e.g. the GUI dropdown/autocomplete).
    # Emitted via Write-Host only when opted in, so normal CLI output is unchanged.
    if ($env:SPIDERSTONE_PROGRESS_STDOUT -eq '1') {
        foreach ($feature in $allFeatures) { Write-Host "##FEATURE##|$feature" }
    }

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
function Get-CbsPackageDiscovery {
    <#
    .SYNOPSIS
        Fast, low-memory discovery of feature packages and their owner packages.
    .DESCRIPTION
        Scans the CBS Packages hive with the .NET Microsoft.Win32.RegistryKey API
        (10-20x faster than the PowerShell registry provider) in two passes over a
        single subkey-name enumeration:
          pass 1 - packages whose 'Updates' subkey lists the feature;
          pass 2 - packages whose 'Owners' subkey references any feature package.
        Memory stays tiny: only a HashSet of found package names is retained (no
        full owner index is built), so no memory-tradeoff switch is needed.
        Returns an object with .FeaturePackages and .OwnerPackages arrays.
    #>
    param([string]$Feature)

    $result = [PSCustomObject]@{ FeaturePackages = @(); OwnerPackages = @() }

    Write-VerboseMessage "Searching for feature in Packages registry (.NET RegistryKey API)..."

    $baseKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    $baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($baseKeyPath)
    if ($null -eq $baseKey) {
        Write-Error "Packages registry path not found"
        return $result
    }

    try {
        $names = $baseKey.GetSubKeyNames()
        $total = $names.Length

        # Case-insensitive set of package names that carry the feature.
        $featureNames  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $featurePkgs   = [System.Collections.Generic.List[object]]::new()
        $ownerPkgs     = [System.Collections.Generic.List[object]]::new()

        # --- Pass 1: feature packages (Updates subkey lists the feature) ---
        $act1 = "Scanning CBS packages for feature '$Feature'"
        $idx = 0
        foreach ($name in $names) {
            $idx++
            if ($total -gt 0 -and ($idx % 200 -eq 0 -or $idx -eq $total)) {
                Write-StageProgress -Activity $act1 -Status "$idx / $total (found: $($featurePkgs.Count))" `
                               -PercentComplete (($idx / $total) * 100)
            }
            $pkgKey = $baseKey.OpenSubKey($name)
            if ($null -eq $pkgKey) { continue }
            try {
                $upd = $pkgKey.OpenSubKey("Updates")
                if ($null -ne $upd) {
                    try {
                        foreach ($vn in $upd.GetValueNames()) {
                            if ($vn -eq $Feature) {
                                Write-VerboseMessage "Found feature in package: $name"
                                [void]$featureNames.Add($name)
                                $featurePkgs.Add([PSCustomObject]@{ PackageName = $name; Source = "Packages" })
                                break
                            }
                        }
                    } finally { $upd.Dispose() }
                }
            } finally { $pkgKey.Dispose() }
        }
        if ($total -gt 0) { Write-StageProgress -Activity $act1 -Completed }

        # --- Pass 2: owner packages (Owners subkey references a feature package) ---
        # Skipped entirely when nothing was found (common case), saving a full scan.
        if ($featureNames.Count -gt 0) {
            $act2 = "Scanning for owner packages"
            $idx = 0
            foreach ($name in $names) {
                $idx++
                if ($total -gt 0 -and ($idx % 200 -eq 0 -or $idx -eq $total)) {
                    Write-StageProgress -Activity $act2 -Status "$idx / $total (owners: $($ownerPkgs.Count))" `
                                   -PercentComplete (($idx / $total) * 100)
                }
                $pkgKey = $baseKey.OpenSubKey($name)
                if ($null -eq $pkgKey) { continue }
                try {
                    $own = $pkgKey.OpenSubKey("Owners")
                    if ($null -ne $own) {
                        try {
                            foreach ($vn in $own.GetValueNames()) {
                                if ($featureNames.Contains($vn)) {
                                    $ic = $pkgKey.GetValue("InstallClient"); if ($null -eq $ic) { $ic = "N/A" }
                                    $inm = $pkgKey.GetValue("InstallName");  if ($null -eq $inm) { $inm = "N/A" }
                                    $ownerInfo = [PSCustomObject]@{
                                        PackageName   = $name
                                        InstallClient = [string]$ic
                                        InstallName   = [string]$inm
                                    }
                                    Write-VerboseMessage "Found owner package: $name (owns $vn)"
                                    Write-Host "  Owner Package: $($ownerInfo.PackageName)" -ForegroundColor Yellow
                                    Write-Host "  InstallClient: $($ownerInfo.InstallClient)" -ForegroundColor Gray
                                    Write-Host "  InstallName: $($ownerInfo.InstallName)" -ForegroundColor Gray
                                    $ownerPkgs.Add($ownerInfo)
                                    break
                                }
                            }
                        } finally { $own.Dispose() }
                    }
                } finally { $pkgKey.Dispose() }
            }
            if ($total -gt 0) { Write-StageProgress -Activity $act2 -Completed }
        }

        $result.FeaturePackages = $featurePkgs.ToArray()
        $result.OwnerPackages   = $ownerPkgs.ToArray()
    }
    finally {
        $baseKey.Dispose()
    }

    return $result
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

    # Guard the cast: a few servicing files that slip through the filter are binary
    # (e.g. catalogs) and are not valid XML; skip them quietly instead of erroring.
    try {
        [xml]$xml = $xmlContent
    } catch {
        Write-VerboseMessage "Skipping non-XML file: $MumFilePath"
        return $components
    }

    # Find all assemblyIdentity elements with name attributes.
    # MUM files declare a default namespace (urn:schemas-microsoft-com:asm.v3), so a
    # plain "//assemblyIdentity" XPath matches NOTHING; use local-name() to ignore the
    # namespace and catch every assemblyIdentity regardless of prefix/namespace.
    $assemblyIdentities = $xml.SelectNodes("//*[local-name()='assemblyIdentity'][@name]")
    
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
        
        # Search for MUM file (only *.mum - the filter would otherwise also match the
        # binary *.cat catalogs sharing the same base name, which are not XML).
        $mumFiles = Get-ChildItem -Path $mumPath -Filter "*$mumName*.mum" -ErrorAction SilentlyContinue
        
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
function Get-ManifestNameCore {
    <#
    .SYNOPSIS
        Builds the architecture-independent manifest name core from a package/component name.
    .DESCRIPTION
        Lowercases the name and trims the packaging suffix (-package / -fod-package /
        -opt-package). The architecture prefix (amd64_/wow64_/x86_/msil_/...) is NOT added
        here - Find-ManifestFiles adds it and searches every architecture, because a feature
        on x64 also stages wow64/x86/msil components.
    #>
    param([string]$PackageName)

    $manifestName = $PackageName.ToLower()

    # Remove suffixes
    foreach ($suffix in $script:Config.SuffixesToRemove) {
        if ($manifestName.Contains($suffix)) {
            $index = $manifestName.IndexOf($suffix)
            $manifestName = $manifestName.Substring(0, $index)
            break
        }
    }

    Write-VerboseMessage "Manifest name core: $manifestName"
    return $manifestName
}

function Find-ManifestFiles {
    <#
    .SYNOPSIS
        Finds WinSxS manifests for a name core across ALL architectures.
    .DESCRIPTION
        WinSxS manifest file names are <arch>_<name>_<pubKey>_<ver>_<lang>_<hash>.manifest.
        A feature on x64 stages not only amd64 components but also wow64/x86/msil ones, so
        every architecture prefix in Config.ManifestArchPrefixes is searched. Searching only
        the running architecture (the old behavior) silently missed ~1/4 of components.
    #>
    param([string]$NameCore)

    $foundFiles = @()

    if (-not (Test-Path $script:Config.ManifestsPath)) {
        Write-Warning "Manifests directory not found: $($script:Config.ManifestsPath)"
        return $foundFiles
    }

    foreach ($arch in $script:Config.ManifestArchPrefixes) {
        $searchPattern = "${arch}_${NameCore}*.manifest"
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

    $total = @($ManifestFiles).Count
    $idx = 0
    foreach ($file in $ManifestFiles) {
        $idx++
        if ($total -gt 0) {
            Write-StageProgress -Activity "Copying manifests" `
                           -Status "$idx of $total : $($file.Name)" `
                           -PercentComplete (($idx / $total) * 100)
        }
        $destPath = Join-Path $fullDestination $file.Name

        if (Copy-Item -Path $file.FullName -Destination $destPath -Force -PassThru -ErrorAction SilentlyContinue) {
            Write-VerboseMessage "Copied: $($file.Name)"
            $copiedFiles += $destPath
        } else {
            Write-Warning "Failed to copy $($file.Name)"
        }
    }
    if ($total -gt 0) { Write-StageProgress -Activity "Copying manifests" -Completed }

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

    $total = @($ManifestFiles).Count
    $idx = 0
    foreach ($file in $ManifestFiles) {
        $idx++
        if ($total -gt 0) {
            Write-StageProgress -Activity "Decompressing manifests (WCP)" `
                           -Status "$idx of $total : $([System.IO.Path]::GetFileName($file))" `
                           -PercentComplete (($idx / $total) * 100)
        }
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

            # Isolate each file: Expand-WCPFile ends its catch with `throw`, so an unsupported
            # type (e.g. DCS/type 5) or any decompression failure would otherwise terminate the
            # whole loop (and the run). Catch here so one bad manifest is skipped, not fatal.
            try {
                Expand-WCPFile @params
            } catch {
                Write-Warning "Failed to extract $fullInputPath : $($_.Exception.Message)"
                continue
            }

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
    if ($total -gt 0) { Write-StageProgress -Activity "Decompressing manifests (WCP)" -Completed }
}
#endregion

#region XML Processing Functions
function Get-XmlAttr {
    <#
    .SYNOPSIS
        Safely reads an attribute from an XML node (namespace-agnostic; '' if missing/null)
    #>
    param($Node, [string]$Name)
    if ($null -eq $Node) { return '' }
    return $Node.GetAttribute($Name)
}

function Parse-ManifestXml {
    <#
    .SYNOPSIS
        Parses an extracted manifest and extracts the full component footprint.
    .DESCRIPTION
        Beyond <file> entries, pulls the data verified present in WinSxS manifests:
        full assemblyIdentity (incl. publicKeyToken/buildType/versionScope), per-file
        SHA hash + securityDescriptor + hardlink target, dependencies, registry footprint,
        category memberships, directories, localization strings, ETW providers, scheduled
        tasks, and deployment/infFile/appx/service markers. Uses local-name() XPath so it
        works across the asm.v1/v2/v3, xmldsig, ETW and task-scheduler namespaces.
    #>
    param([string]$XmlFilePath)

    $fullPath = [System.IO.Path]::GetFullPath($XmlFilePath)
    if (-not (Test-Path $fullPath)) { return $null }

    $xmlContent = Get-Content -Path $fullPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($xmlContent)) {
        Write-Warning "Failed to read XML file: $fullPath"
        return $null
    }

    try { [xml]$xml = $xmlContent } catch { Write-Warning "Invalid XML: $fullPath"; return $null }

    $asmNode = $xml.SelectSingleNode("/*[local-name()='assembly']")
    if ($null -eq $asmNode) { return $null }
    $idNode = $asmNode.SelectSingleNode("*[local-name()='assemblyIdentity']")

    $manifestName = [System.IO.Path]::GetFileName($fullPath)
    $asmName        = Get-XmlAttr $idNode 'name'

    # Component name filter: skip this manifest entirely (files + every collection)
    # unless the component name contains the requested word (case-insensitive).
    if (-not [string]::IsNullOrWhiteSpace($ComponentFilter) -and
        $asmName.IndexOf($ComponentFilter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Write-VerboseMessage "Skipping '$asmName' (does not match -ComponentFilter '$ComponentFilter')"
        return $null
    }

    $asmVersion     = Get-XmlAttr $idNode 'version'
    $asmArch        = Get-XmlAttr $idNode 'processorArchitecture'
    $asmLang        = Get-XmlAttr $idNode 'language'
    $asmPubKey      = Get-XmlAttr $idNode 'publicKeyToken'
    $asmBuildType   = Get-XmlAttr $idNode 'buildType'
    $asmVerScope    = Get-XmlAttr $idNode 'versionScope'
    $asmIdType      = Get-XmlAttr $idNode 'type'

    # Localization: displayName / description for the component summary
    $dispNode = $xml.SelectSingleNode("//*[local-name()='string'][@id='displayName']")
    $descNode = $xml.SelectSingleNode("//*[local-name()='string'][@id='description']")
    $displayName = Get-XmlAttr $dispNode 'value'
    $description = Get-XmlAttr $descNode 'value'

    $manifestInfo = [PSCustomObject]@{
        Name = $asmName; Version = $asmVersion; Architecture = $asmArch; Language = $asmLang; Files = @()
    }

    # ---- Files (enriched: hash, securityDescriptor, hardlink, full identity) ----
    $fileNodes = $xml.SelectNodes("//*[local-name()='file']")
    foreach ($file in $fileNodes) {
        $algNode = $file.SelectSingleNode(".//*[local-name()='DigestMethod']")
        $valNode = $file.SelectSingleNode(".//*[local-name()='DigestValue']")
        $sdNode  = $file.SelectSingleNode("*[local-name()='securityDescriptor']")
        $links   = $file.SelectNodes("*[local-name()='link']") | ForEach-Object { $_.GetAttribute('destination') }
        $alg = Get-XmlAttr $algNode 'Algorithm'

        $fileInfo = [PSCustomObject]@{
            FileName          = Get-XmlAttr $file 'name'
            DestinationPath   = Get-XmlAttr $file 'destinationPath'
            SourceName        = Get-XmlAttr $file 'sourceName'
            ImportPath        = Get-XmlAttr $file 'importPath'
            SourcePath        = Get-XmlAttr $file 'sourcePath'
            WriteableType     = Get-XmlAttr $file 'writeableType'
            HashAlgorithm     = if ($alg) { ($alg -split '#')[-1] } else { '' }
            HashValue         = if ($valNode) { $valNode.InnerText } else { '' }
            SecurityDescriptor= Get-XmlAttr $sdNode 'name'
            LinkTarget        = ($links -join '; ')
            ManifestName      = $manifestName
            AssemblyName      = $asmName
            Component         = $asmName
            Version           = $asmVersion
            Architecture      = $asmArch
            PublicKeyToken    = $asmPubKey
        }
        $manifestInfo.Files += $fileInfo
        $script:Config.AllFiles += $fileInfo
    }

    # ---- Component summary row ----
    $script:Config.Components += [PSCustomObject]@{
        Component = $asmName; Version = $asmVersion; Architecture = $asmArch; Language = $asmLang
        PublicKeyToken = $asmPubKey; BuildType = $asmBuildType; VersionScope = $asmVerScope; IdentityType = $asmIdType
        DisplayName = $displayName; Description = $description
        FileCount = $fileNodes.Count
        ManifestName = $manifestName
    }

    # ---- Dependencies (component -> component) ----
    foreach ($dep in $xml.SelectNodes("//*[local-name()='dependentAssembly']")) {
        $di = $dep.SelectSingleNode("*[local-name()='assemblyIdentity']")
        if ($null -eq $di) { continue }
        $script:Config.Dependencies += [PSCustomObject]@{
            Component = $asmName
            DependencyType = Get-XmlAttr $dep 'dependencyType'
            DependsOnName = Get-XmlAttr $di 'name'
            DependsOnVersion = Get-XmlAttr $di 'version'
            DependsOnArch = Get-XmlAttr $di 'processorArchitecture'
            DependsOnLanguage = Get-XmlAttr $di 'language'
            DependsOnPublicKeyToken = Get-XmlAttr $di 'publicKeyToken'
            DependsOnVersionScope = Get-XmlAttr $di 'versionScope'
            ManifestName = $manifestName
        }
    }

    # ---- Registry footprint ----
    foreach ($key in $xml.SelectNodes("//*[local-name()='registryKey']")) {
        $keyName = Get-XmlAttr $key 'keyName'
        $keySd   = Get-XmlAttr ($key.SelectSingleNode("*[local-name()='securityDescriptor']")) 'name'
        $values  = $key.SelectNodes("*[local-name()='registryValue']")
        if ($values.Count -eq 0) {
            $script:Config.RegistryItems += [PSCustomObject]@{
                Component=$asmName; KeyName=$keyName; ValueName=''; ValueType=''; Value=''; SecurityDescriptor=$keySd; ManifestName=$manifestName }
        } else {
            foreach ($v in $values) {
                $script:Config.RegistryItems += [PSCustomObject]@{
                    Component=$asmName; KeyName=$keyName
                    ValueName = Get-XmlAttr $v 'name'; ValueType = Get-XmlAttr $v 'valueType'; Value = Get-XmlAttr $v 'value'
                    SecurityDescriptor=$keySd; ManifestName=$manifestName }
            }
        }
    }

    # ---- Category memberships (component -> feature/category) ----
    foreach ($id in $xml.SelectNodes("//*[local-name()='categoryMembership']/*[local-name()='id']")) {
        $script:Config.Categories += [PSCustomObject]@{
            Component=$asmName
            CategoryName = Get-XmlAttr $id 'name'; CategoryVersion = Get-XmlAttr $id 'version'
            CategoryPublicKeyToken = Get-XmlAttr $id 'publicKeyToken'; TypeName = Get-XmlAttr $id 'typeName'
            ManifestName=$manifestName }
    }

    # ---- Directories ----
    foreach ($d in $xml.SelectNodes("//*[local-name()='directory']")) {
        $script:Config.Directories += [PSCustomObject]@{
            Component=$asmName; DestinationPath = Get-XmlAttr $d 'destinationPath'; Owner = Get-XmlAttr $d 'owner'
            SecurityDescriptor = Get-XmlAttr ($d.SelectSingleNode("*[local-name()='securityDescriptor']")) 'name'
            ManifestName=$manifestName }
    }

    # ---- Localization strings ----
    foreach ($s in $xml.SelectNodes("//*[local-name()='string']")) {
        $script:Config.Strings += [PSCustomObject]@{
            Component=$asmName; StringId = Get-XmlAttr $s 'id'; Value = Get-XmlAttr $s 'value'; ManifestName=$manifestName }
    }

    # ---- ETW providers ----
    foreach ($p in $xml.SelectNodes("//*[local-name()='provider']")) {
        $script:Config.Providers += [PSCustomObject]@{
            Component=$asmName; ProviderName = Get-XmlAttr $p 'name'; Guid = Get-XmlAttr $p 'guid'
            MessageFileName = Get-XmlAttr $p 'messageFileName'; ResourceFileName = Get-XmlAttr $p 'resourceFileName'
            ManifestName=$manifestName }
    }

    # ---- Scheduled tasks ----
    foreach ($t in $xml.SelectNodes("//*[local-name()='Task']")) {
        $uri = $t.SelectSingleNode(".//*[local-name()='URI']")
        $src = $t.SelectSingleNode(".//*[local-name()='Source']")
        $aut = $t.SelectSingleNode(".//*[local-name()='Author']")
        $script:Config.Tasks += [PSCustomObject]@{
            Component=$asmName
            Uri = if($uri){$uri.InnerText}else{''}; Source = if($src){$src.InnerText}else{''}; Author = if($aut){$aut.InnerText}else{''}
            ManifestName=$manifestName }
    }

    # ---- Extra markers: deployment / infFile / appxRegistration / serviceData / migration / protocolDriver ----
    foreach ($kind in 'deployment','infFile','deconstructionTool','appxRegistration','serviceData','migration','protocolDriver','networkComponents','counterSet') {
        foreach ($n in $xml.SelectNodes("//*[local-name()='$kind']")) {
            $script:Config.Extras += [PSCustomObject]@{
                Component=$asmName; Kind=$kind
                Name = (Get-XmlAttr $n 'name'); Detail = $n.OuterXml.Substring(0, [Math]::Min(200, $n.OuterXml.Length))
                ManifestName=$manifestName }
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

function Export-ComponentData {
    <#
    .SYNOPSIS
        Exports every component-level collection to its own CSV in the output directory.
    #>
    param(
        [string]$Feature,
        [string]$OutputPath
    )

    $safeFeatureName = if ([string]::IsNullOrWhiteSpace($Feature)) { "AllFeatures" } else { $Feature -replace '[^\w\-]', '_' }

    $sets = [ordered]@{
        Components   = $script:Config.Components
        Dependencies = $script:Config.Dependencies
        Registry     = $script:Config.RegistryItems
        Categories   = $script:Config.Categories
        Directories  = $script:Config.Directories
        Strings      = $script:Config.Strings
        Providers    = $script:Config.Providers
        Tasks        = $script:Config.Tasks
        Extras       = $script:Config.Extras
    }

    Write-Header -Title "Component footprint" -Color Yellow
    foreach ($kv in $sets.GetEnumerator()) {
        $rows = $kv.Value
        if ($null -eq $rows -or $rows.Count -eq 0) {
            Write-Host ("  {0,-13}: 0" -f $kv.Key) -ForegroundColor DarkGray
            continue
        }
        $csvPath = Join-Path $OutputPath ("{0}_{1}.csv" -f $kv.Key, $safeFeatureName)
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Host ("  {0,-13}: {1,5}  -> {2}" -f $kv.Key, $rows.Count, [System.IO.Path]::GetFileName($csvPath)) -ForegroundColor Green
    }
}

function ConvertTo-HtmlSafe {
    <# HTML-encodes a value (built-in, no System.Web dependency). #>
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HtmlSection {
    <#
    .SYNOPSIS
        Renders one collection as a collapsible <details> section with a table.
    #>
    param(
        [string]$Title,
        [string]$Icon,
        [array]$Rows,
        [string[]]$Columns,
        [int]$MaxRows = 500
    )

    $count = if ($Rows) { $Rows.Count } else { 0 }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<details><summary><span class='sname'>$(ConvertTo-HtmlSafe $Title)</span><span class='badge'>$count</span></summary>")

    if ($count -eq 0) {
        [void]$sb.Append("<p class='empty'>No entries.</p></details>")
        return $sb.ToString()
    }

    [void]$sb.Append("<div class='tablewrap'><table><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(ConvertTo-HtmlSafe $c)</th>") }
    [void]$sb.Append("</tr></thead><tbody>")

    foreach ($r in ($Rows | Select-Object -First $MaxRows)) {
        [void]$sb.Append("<tr>")
        foreach ($c in $Columns) {
            $cls = if ($c -match 'Hash|Guid|Token|Value$|Uri') { " class='mono'" } else { "" }
            [void]$sb.Append("<td$cls>$(ConvertTo-HtmlSafe $r.$c)</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    if ($count -gt $MaxRows) {
        [void]$sb.Append("<p class='note'>Showing first $MaxRows of $count rows &mdash; full data in the matching CSV.</p>")
    }
    [void]$sb.Append("</details>")
    return $sb.ToString()
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Writes a self-contained, theme-aware HTML report of the component footprint.
    #>
    param(
        [string]$Feature,
        [string]$OutputPath
    )

    $safeFeatureName = if ([string]::IsNullOrWhiteSpace($Feature)) { "AllFeatures" } else { $Feature -replace '[^\w\-]', '_' }
    $reportPath = Join-Path $OutputPath ("Report_{0}.html" -f $safeFeatureName)
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $cfg = $script:Config
    $cards = @(
        @{ n = 'Components';   v = $cfg.Components.Count }
        @{ n = 'Files';        v = $cfg.AllFiles.Count }
        @{ n = 'Dependencies'; v = $cfg.Dependencies.Count }
        @{ n = 'Registry';     v = $cfg.RegistryItems.Count }
        @{ n = 'Categories';   v = $cfg.Categories.Count }
        @{ n = 'Directories';  v = $cfg.Directories.Count }
        @{ n = 'Providers';    v = $cfg.Providers.Count }
        @{ n = 'Tasks';        v = $cfg.Tasks.Count }
    )
    $cardHtml = ($cards | ForEach-Object {
        "<div class='card'><div class='num'>$($_.v)</div><div class='lbl'>$(ConvertTo-HtmlSafe $_.n)</div></div>"
    }) -join ''

    $sections = [System.Text.StringBuilder]::new()
    [void]$sections.Append((New-HtmlSection -Title 'Components' -Icon '&#129513;' -Rows $cfg.Components -Columns 'Component','DisplayName','Version','Architecture','Language','PublicKeyToken','BuildType','VersionScope','FileCount'))
    [void]$sections.Append((New-HtmlSection -Title 'Files' -Icon '&#128196;' -Rows $cfg.AllFiles -Columns 'Component','FileName','DestinationPath','HashAlgorithm','HashValue','SecurityDescriptor','LinkTarget'))
    [void]$sections.Append((New-HtmlSection -Title 'Dependencies' -Icon '&#128279;' -Rows $cfg.Dependencies -Columns 'Component','DependencyType','DependsOnName','DependsOnVersion','DependsOnArch','DependsOnPublicKeyToken'))
    [void]$sections.Append((New-HtmlSection -Title 'Registry' -Icon '&#128273;' -Rows $cfg.RegistryItems -Columns 'Component','KeyName','ValueName','ValueType','Value','SecurityDescriptor'))
    [void]$sections.Append((New-HtmlSection -Title 'Categories' -Icon '&#127991;' -Rows $cfg.Categories -Columns 'Component','CategoryName','CategoryVersion','TypeName'))
    [void]$sections.Append((New-HtmlSection -Title 'Directories' -Icon '&#128193;' -Rows $cfg.Directories -Columns 'Component','DestinationPath','Owner','SecurityDescriptor'))
    [void]$sections.Append((New-HtmlSection -Title 'Localization strings' -Icon '&#127760;' -Rows $cfg.Strings -Columns 'Component','StringId','Value'))
    [void]$sections.Append((New-HtmlSection -Title 'ETW providers' -Icon '&#128225;' -Rows $cfg.Providers -Columns 'Component','ProviderName','Guid','MessageFileName','ResourceFileName'))
    [void]$sections.Append((New-HtmlSection -Title 'Scheduled tasks' -Icon '&#9200;' -Rows $cfg.Tasks -Columns 'Component','Uri','Source','Author'))
    [void]$sections.Append((New-HtmlSection -Title 'Deployment / AppX / services' -Icon '&#128230;' -Rows $cfg.Extras -Columns 'Component','Kind','Name'))

    $css = @'
:root{--bg:#eceef1;--panel:#ffffff;--ink:#161b21;--muted:#5a6572;--line:#dce0e5;--accent:#a5620a;--accentbg:#f6efe1;--mono:#0f766e;--chip:#e6eaef;--shadow:0 1px 2px rgba(20,28,38,.05)}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1116;--panel:#151b23;--ink:#e6edf4;--muted:#93a0ad;--line:#242d38;--accent:#e0a54a;--accentbg:#251d10;--mono:#48c4b6;--chip:#1d2530;--shadow:0 1px 2px rgba(0,0,0,.3)}}
:root[data-theme=dark]{--bg:#0d1116;--panel:#151b23;--ink:#e6edf4;--muted:#93a0ad;--line:#242d38;--accent:#e0a54a;--accentbg:#251d10;--mono:#48c4b6;--chip:#1d2530;--shadow:0 1px 2px rgba(0,0,0,.3)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI Variable Text","Segoe UI",system-ui,Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:34px 22px 64px}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:600;color:var(--accent)}
header h1{margin:6px 0 6px;font-size:30px;font-weight:700;letter-spacing:-.01em;text-wrap:balance}
header .sub{color:var(--muted);font-size:13px}
header .sub strong{color:var(--ink);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(124px,1fr));gap:10px;margin:26px 0 30px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:15px 14px;box-shadow:var(--shadow)}
.card .num{font-size:25px;font-weight:700;color:var(--ink);font-variant-numeric:tabular-nums;line-height:1.1}
.card .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-top:5px}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0;overflow:hidden;box-shadow:var(--shadow)}
summary{cursor:pointer;padding:13px 16px 13px 30px;list-style:none;display:flex;align-items:center;gap:10px;position:relative}
summary::-webkit-details-marker{display:none}
summary::before{content:"";position:absolute;left:14px;top:50%;width:6px;height:6px;margin-top:-3px;border-right:2px solid var(--accent);border-bottom:2px solid var(--accent);transform:rotate(-45deg);transition:transform .15s ease}
details[open]>summary::before{transform:rotate(45deg)}
@media(prefers-reduced-motion:reduce){summary::before{transition:none}}
.sname{font-weight:600;font-size:15px}
summary:hover{background:var(--accentbg)}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.badge{margin-left:auto;background:var(--chip);color:var(--muted);border-radius:20px;padding:2px 11px;font-size:12px;font-weight:600;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;border-top:1px solid var(--line)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:8px 14px;border-bottom:1px solid var(--line);white-space:nowrap;max-width:520px;overflow:hidden;text-overflow:ellipsis}
thead th{position:sticky;top:0;background:var(--panel);color:var(--muted);font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:.06em}
tbody tr:hover{background:var(--accentbg)}
td.mono{font-family:"Cascadia Code","Cascadia Mono",Consolas,ui-monospace,"Liberation Mono",monospace;color:var(--mono);font-size:12px}
.empty{padding:14px 16px 16px 30px;color:var(--muted);margin:0;font-size:13px}
.note{padding:9px 16px;color:var(--muted);font-size:12px;margin:0;border-top:1px solid var(--line);background:var(--accentbg)}
footer{margin-top:32px;color:var(--muted);font-size:12px;text-align:center}
footer strong{color:var(--accent);font-weight:600}
'@

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spider Stone - $(ConvertTo-HtmlSafe $Feature)</title><style>$css</style></head>
<body><div class="wrap">
<header>
<div class="eyebrow">Component-Based Servicing &middot; WinSxS footprint</div>
<h1>Spider&nbsp;Stone</h1>
<div class="sub">Feature <strong>$(ConvertTo-HtmlSafe $Feature)</strong> &nbsp;&middot;&nbsp; $($cfg.Components.Count) component(s), $($cfg.AllFiles.Count) file(s) &nbsp;&middot;&nbsp; generated $now</div></header>
<div class="cards">$cardHtml</div>
$($sections.ToString())
<footer>Spider Stone v$($script:Config.Version) &bull; data also exported as CSV alongside this report</footer>
</div></body></html>
"@

    [System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)
    if (Test-Path $reportPath) {
        $fullReport = [System.IO.Path]::GetFullPath($reportPath)
        # When writing to an interactive console, emit an OSC 8 terminal hyperlink so
        # the path is Ctrl+Click-able (Windows Terminal, VS Code, and the Windows 11 /
        # Server 2025 conhost all support OSC 8). The visible link text is the full
        # path, so even a terminal that ignores OSC 8 still shows a usable path. When
        # output is redirected to a file/pipe, print a plain path with no escapes.
        if (-not [Console]::IsOutputRedirected) {
            $uri = ([System.Uri]$fullReport).AbsoluteUri
            $e = [char]27
            $link = "$e]8;;$uri$e\$fullReport$e]8;;$e\"
            Write-Host "`n  HTML report : " -ForegroundColor Cyan -NoNewline
            Write-Host $link -ForegroundColor Cyan -NoNewline
            # Windows Terminal highlights file:// links but, for security, only opens
            # http/https on click - so point users at -OpenReport for reliable opening.
            if (-not $OpenReport) {
                Write-Host "  (re-run with the -OpenReport script parameter to open it in the browser)" -ForegroundColor DarkGray
            } else {
                Write-Host ""
            }
        } else {
            Write-Host "`n  HTML report : $fullReport" -ForegroundColor Cyan
        }

        # Open the report in the default browser when requested.
        if ($OpenReport) {
            try {
                Start-Process $fullReport -ErrorAction Stop
                Write-Host "  Opening report in the default browser..." -ForegroundColor Green
            } catch {
                Write-Warning "Could not open the report automatically: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Warning "Failed to write HTML report"
    }
    return $reportPath
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
    
    # Find packages with the feature (single fast .NET scan: feature + owner packages)
    Write-Header -Title "Searching for packages" -Color Yellow
    $discovery = Get-CbsPackageDiscovery -Feature $FeatureName
    $packages = $discovery.FeaturePackages

    if ($packages.Count -eq 0) {
        Write-Warning "No packages found containing feature '$FeatureName'"
        return
    }

    Write-Host "Found $($packages.Count) package(s) with the feature" -ForegroundColor Green
    foreach ($pkg in $packages) {
        Write-Host "  - $($pkg.PackageName) [$($pkg.Source)]" -ForegroundColor Gray
    }

    # Seed names for the recursive MUM component chain. A feature's real payload is
    # often described ONLY through MUM files - e.g. an OptionalFeature marker package
    # whose FOD/content package pulls in dozens of component packages, each a nearly
    # empty MUM with a single <update>. So we seed the chain with the feature name and
    # every discovered package name (the feature name catches the FOD/content MUMs by
    # substring; recursion then follows the real assemblyIdentity references).
    $mumFilesToProcess = @()
    if (-not [string]::IsNullOrWhiteSpace($FeatureName)) { $mumFilesToProcess += $FeatureName }

    # Find manifest files
    $allManifests = @()

    # Feature packages -> manifests (+ seed their names for the MUM chain)
    foreach ($package in $packages) {
        Write-VerboseMessage "Processing package: $($package.PackageName)"
        $mumFilesToProcess += $package.PackageName

        $manifestCore = Get-ManifestNameCore -PackageName $package.PackageName
        $manifests = Find-ManifestFiles -NameCore $manifestCore

        if ($manifests.Count -gt 0) {
            $allManifests += $manifests
        }
    }

    # Owner packages (discovered once in the same scan) -> manifests + MUM install names
    foreach ($ownerPackage in $discovery.OwnerPackages) {
        Write-VerboseMessage "Processing owner package: $($ownerPackage.PackageName)"

        if (-not [string]::IsNullOrWhiteSpace($ownerPackage.InstallName) -and $ownerPackage.InstallName -ne "N/A") {
            $mumFilesToProcess += $ownerPackage.InstallName
        }

        $ownerManifestCore = Get-ManifestNameCore -PackageName $ownerPackage.PackageName
        $ownerManifests = Find-ManifestFiles -NameCore $ownerManifestCore

        if ($ownerManifests.Count -gt 0) {
            $allManifests += $ownerManifests
        }
    }

    # Follow the MUM chain when explicitly requested (-ParsingMum), or automatically as
    # a fallback when direct package -> manifest matching found nothing (the usual case
    # for OptionalFeature markers, whose payload lives entirely in the MUM chain).
    $mumFallback = ($allManifests.Count -eq 0)
    if (($ParsingMum -or $mumFallback) -and $mumFilesToProcess.Count -gt 0) {
        Write-Header -Title "Processing MUM files" -Color Yellow
        if ($mumFallback -and -not $ParsingMum) {
            Write-Host "No manifests matched package names directly; following the MUM component chain..." -ForegroundColor Yellow
        }

        $mumComponents = Process-MumFiles -MumFileNames ($mumFilesToProcess | Select-Object -Unique)

        if ($mumComponents.Count -gt 0) {
            Write-Host "Found $($mumComponents.Count) component(s) in MUM files" -ForegroundColor Green

            # Find manifest files for MUM components
            foreach ($component in $mumComponents) {
                $componentManifestCore = Get-ManifestNameCore -PackageName $component
                $componentManifests = Find-ManifestFiles -NameCore $componentManifestCore

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
        Write-Warning "No manifest files found for feature '$FeatureName' (checked package manifests and the MUM component chain)."
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

    $parseTotal = @($copiedFiles).Count
    $parseIdx = 0
    foreach ($copiedFile in $copiedFiles) {
        $parseIdx++
        if ($parseTotal -gt 0) {
            Write-StageProgress -Activity "Parsing manifests" `
                           -Status "$parseIdx of $parseTotal : $([System.IO.Path]::GetFileName($copiedFile))" `
                           -PercentComplete (($parseIdx / $parseTotal) * 100)
        }
        $extractedFile = "$copiedFile.extracted"

        if (Test-Path $extractedFile) {
            Write-VerboseMessage "Parsing: $extractedFile"
            Parse-ManifestXml -XmlFilePath $extractedFile | Out-Null
        }
    }
    if ($parseTotal -gt 0) { Write-StageProgress -Activity "Parsing manifests" -Completed }

    # Report on the component name filter, if one was supplied
    if (-not [string]::IsNullOrWhiteSpace($ComponentFilter)) {
        $matched = $script:Config.Components.Count
        Write-Host ("`nComponent filter '{0}': {1} component(s) matched" -f $ComponentFilter, $matched) -ForegroundColor Cyan
        if ($matched -eq 0) {
            Write-Warning "No components contain '$ComponentFilter' - nothing to export. Run without -ComponentFilter to see all components."
        }
    }

    # Display results
    if ($script:Config.AllFiles.Count -gt 0) {
        Write-Host "`nFound $($script:Config.AllFiles.Count) file(s) in manifests" -ForegroundColor Green
        Show-FileInformation -FilesList $script:Config.AllFiles -Feature $FeatureName -OutputPath $featureOutputDir
    } else {
        Write-Warning "No file information found in manifests"
    }

    # Export the full component footprint (one CSV per data kind) + a readable HTML report
    Export-ComponentData -Feature $FeatureName -OutputPath $featureOutputDir
    Export-HtmlReport -Feature $FeatureName -OutputPath $featureOutputDir | Out-Null

    Write-Host "`nScript completed!" -ForegroundColor Green
}

# Execute main function
Main
#endregion