# Spider Stone
Windows Optional Feature Files Finder and Extractor for Hyper-V components

![](./images/image001.png)

![](./images/image002.png)

## Script overview

Extracts and analyzes Windows Optional Feature manifest files from the system registry and WinSxS store (specially for Hyper-V components)

## Requirements

- **PowerShell**: Version 7.0 or higher
- **Module**: WCPExtractor.psm1 (must be in the same directory as the script)
- **Privileges**: Administrator rights may be required for accessing system files
- **OS**: Windows 10/11 or Windows Server
- **Architecture**: AMD64 and ARM64

## Installation

1. Download `Spider_Stone.ps1` from that repository
2. Place `WCPExtractor.psm1` (based on https://github.com/smx-smx/wcpex/) in the same directory 
3. Open PowerShell 7+ as Administrator
4. Navigate to the script directory
5. Run the script with desired parameters

### Parameters

| Parameter        | Type | Description | Default |
|------------------|------|-------------|---------|
| `FeatureName` | string | Name of the Windows Optional Feature to analyze | - |
| `OutputDirectory` | string | Directory where manifest files will be copied and extracted | `.\OptionalFeatureFiles` |
| `VerboseOutput` | switch | Enable verbose output for detailed logging | `$false` |
| `ParsingMum` | switch | Enable parsing of MUM files from servicing packages (show lists of MUM-files in console output) | `$false` |
| `NotShowGridView` | switch | Do not display results in GridView | `$false` |
| `PathToWcp` | string | Full path to the wcp.dll file to use for extraction | - |
| `SearchWcpDll` | switch | Search for the latest version of wcp.dll using WCPExtractor | `$false` |
| `-Help`, `-?` | switch | Show help information | `$false` |

### Usage Examples

#### Show all installed optional features
```powershell
.\Spider_Stone.ps1
```

#### Analyze a specific feature
```powershell
.\Spider_Stone.ps1 -FeatureName "Microsoft-Hyper-V"
```

#### Analyze with verbose output and MUM parsing
```powershell
.\Spider_Stone.ps1 -FeatureName "Microsoft-Hyper-V" -ParsingMum -VerboseOutput
```

#### Export to custom directory without GridView
```powershell
.\Spider_Stone.ps1 -FeatureName "Microsoft-Hyper-V" -OutputDirectory "C:\Temp\Features" -NotShowGridView
```

#### Use specific wcp.dll for extraction
```powershell
.\Spider_Stone.ps1 -FeatureName "Microsoft-Hyper-V" -PathToWcp "C:\Windows\System32\wcp.dll"
```

#### Search for wcp.dll before analysis
```powershell
.\Spider_Stone.ps1 -SearchWcpDll
```

### Output Files
- **\*.manifest**: Original compressed manifest files
- **\*.manifest.extracted**: Decompressed XML content
- **GridView Display**: Interactive table showing file information
- **csv-files**: output information

## Contributing

Contributing are welcome

## Version History

0.0.1  
  * Initial release  

0.0.2  
  * Added additional parameters (SearchWcpDll, PathToWcp, NotShowGridView)
  * replaced wcpex.dll to WCPExtractor.psm1 


## Support

For issues or questions:
1. Check error messages for specific guidance
2. Verify administrator privileges
3. Ensure all dependencies are present (Powershell 7+)
4. Review verbose output for detailed information (-VerboseOutput)

## Licenses

GPL3 for Spider Stone  
Zlib license for WCPExtractor.psm1  

#AI generated