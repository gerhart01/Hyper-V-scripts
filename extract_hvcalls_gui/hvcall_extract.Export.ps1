#------------------------------------------------------------------------
# Source File Information (DO NOT MODIFY)
# Source ID: 1ab55cda-c6c0-4abc-992f-c7515eea66c9
# Source File: hvcall_extract.pff
#------------------------------------------------------------------------
#========================================================================
# Code Generated By: SAPIEN Technologies, Inc., PrimalForms 2011 v2.0.6
# Generated On: 7/7/2021 4:04 PM
# Generated By: User
#========================================================================
#----------------------------------------------
#region Application Functions
#----------------------------------------------

function OnApplicationLoad {
	#Note: This function is not called in Projects
	#Note: This function runs before the form is created
	#Note: To get the script directory in the Packager use: Split-Path $hostinvocation.MyCommand.path
	#Note: To get the console output in the Packager (Windows Mode) use: $ConsoleOutput (Type: System.Collections.ArrayList)
	#Important: Form controls cannot be accessed in this function
	#TODO: Add snapins and custom code to validate the application load		
	
	return $true #return true for success or false for failure
}

function OnApplicationExit {
	#Note: This function is not called in Projects
	#Note: This function runs after the form is closed
	#TODO: Add custom code to clean up and unload snapins when the application exits
	
	$script:ExitCode = 0 #Set the exit code for the Packager
}

#endregion Application Functions

#----------------------------------------------
# Generated Form Function
#----------------------------------------------
function Call-hvcall_extract_pff {

	#----------------------------------------------
	#region Import the Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load("System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[void][reflection.assembly]::Load("System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[void][reflection.assembly]::Load("System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
	[void][reflection.assembly]::Load("System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[void][reflection.assembly]::Load("mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	#endregion Import Assemblies

	#----------------------------------------------
	#region Generated Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$formHvcall_extractLaunch = New-Object System.Windows.Forms.Form
	$buttonOpen = New-Object System.Windows.Forms.Button
	$textbox2 = New-Object System.Windows.Forms.TextBox
	$buttonGetHyperVFilesFromCu = New-Object System.Windows.Forms.Button
	$buttonStart = New-Object System.Windows.Forms.Button
	$richtextbox1 = New-Object System.Windows.Forms.RichTextBox
	$buttonSelectFolderWithHype = New-Object System.Windows.Forms.Button
	$textbox1 = New-Object System.Windows.Forms.TextBox
	$Sel = New-Object System.Windows.Forms.Button
	$folderbrowserdialog1 = New-Object System.Windows.Forms.FolderBrowserDialog
	$openfiledialog1 = New-Object System.Windows.Forms.OpenFileDialog
	$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState		

	#endregion Generated Form Objects

	#----------------------------------------------
	# User Generated Script
	#----------------------------------------------
	
	
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
	
	#$script:dir_with_hvcalls_bin = "F:\ida_files\10x6421H1\4hypercalls\test\Win1021H1"
	#$script:path_to_ida = "F:\Tools\IDA7.5SP3\ida64.exe"

    #$dir_with_hvcalls_bin = "F:\ida_files\11x64\4hypercalls\"
    $script:dir_with_hvcalls_bin = "E:\hv_files\"
    $script:path_to_ida = "C:\Program Files\IDA PRO\ida64.exe"
	$script:path_to_script = (Get-Location).Path + "\extract_hvcalls.py"
	$ida_extension = ".i64"

    $textbox2.Text = $dir_with_hvcalls_bin
    $textbox1.Text = $path_to_ida
	
	
	$bin_array = @(
	    "winhvr.sys", 
	    "winhv.sys", 
	    "securekernel.exe", 
	    "ntoskrnl.exe",
	    "ntkrla57.exe"
	    "securekernella57.exe"
	)
	
	function PrintText()
	{
		param (
			[string]$text,
			[string]$color
		)
		$richTextBox1.SelectionColor = $color
		$richTextBox1.AppendText($text + "`n")
		$richTextBox1.SelectionStart = $richTextBox1.Text.Length
		$richTextBox1.ScrollToCaret()
	}
	
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
	                Copy-Item $file $script:dir_with_hvcalls_bin
	           } 
               else
               {
                    PrintText "File $file is not found" "red"
               }     
	    }    
	}
	
	# Uncomment if you working with current Windows distr
	# GetHvcallBinaries
	
	function hvcall_extract
	{
		if ($script:dir_with_hvcalls_bin -eq ""){
			PrintText "Specify the directory with Hyper-V binaries" "red"
			return $false
		}
		
		if ($script:path_to_ida -eq "")
		{
			PrintText "Specify the IDA PRO executable (file ida64.exe)" "red"
			return $false
		}
		
		if ($script:path_to_script -eq "")
		{
			PrintText "Specify the directory with hvcall_path.py" "red"
			return $false
		}
			

        $path_to_ida = '"' + $path_to_ida + '"'
		
		Get-ChildItem $script:dir_with_hvcalls_bin | where {($_.extension -eq ".sys") -or ($_.extension -eq ".exe")} | ForEach-Object { 
			
		    $fn = $_.FullName
	
		    $file_version = (Get-Command $_.FullName).FileVersionInfo.ProductVersion
	
		    $short_idb = $_.Name.Replace($_.extension, $ida_extension)
	
		    $idb_path =  $fn + $ida_extension
	
		    if ((Test-Path $idb_path) -eq $True)
		    {
		        $ida_params = '-A -S'+$path_to_script+' '+ $idb_path
				PrintText ("processing "+$short_idb+"...  "+$file_version) "black"
		    } 
		    else
		    {
		    	$ida_params = '-c -A -S'+$path_to_script+' '+$fn
				PrintText ("processing "+$_.Name+"...  "+$file_version) "black"
		    }

		    $expr = "&$path_to_ida "+$ida_params
		    
		    Invoke-Expression $expr
		}
	}
	
	
	function OnApplicationLoad {
		#Note: This function is not called in Projects
		#Note: This function runs before the form is created
		#Note: To get the script directory in the Packager use: Split-Path $hostinvocation.MyCommand.path
		#Note: To get the console output in the Packager (Windows Mode) use: $ConsoleOutput (Type: System.Collections.ArrayList)
		#Important: Form controls cannot be accessed in this function
		#TODO: Add snapins and custom code to validate the application load
		
		return $true #return true for success or false for failure
	}
	
	function fbtnSelectHvBin_Click
	{
		$openFileDialog1.Filter = "Folder | *.*"
		$openFileDialog1.CheckFileExists = $false
		$openFileDialog1.InitialDirectory = "."
		$res = $openFileDialog1.ShowDialog()
		if ($res -eq [Windows.Forms.DialogResult]::OK)
		{
			$fullPath = $openFileDialog1.FileName
			$folderPath = $fullPath.Substring(0, $fullPath.LastIndexOf('\'))
			$textbox2.Text = $folderPath
			$script:dir_with_hvcalls_bin = $folderPath
		}
	}
	
	function fbtnSelectIdaPath_Click
	{
		$openFileDialog1.FileName = "ida64.exe"
		$openFileDialog1.Filter = "IDA PRO executable | * .exe"
		$openFileDialog1.CheckFileExists = $false
		$openFileDialog1.InitialDirectory = "."
		$res = $openFileDialog1.ShowDialog()
		$script:path_to_ida = $openFileDialog1.FileName
		if ($res -eq [Windows.Forms.DialogResult]::OK)
		{
			$textbox1.Text = $script:path_to_ida
		}
	}
	
	
	function OnApplicationExit {
		#Note: This function is not called in Projects
		#Note: This function runs after the form is closed
		#TODO: Add custom code to clean up and unload snapins when the application exits
		
		$script:ExitCode = 0 #Set the exit code for the Packager
	}
	
	$FormEvent_Load={
		#TODO: Initialize Form Controls here
		
		if ($script:dir_with_hvcalls_bin -ne "")
		{	
			$textbox2.Text = $script:dir_with_hvcalls_bin
		}
		if ($script:path_to_ida -ne "")
		{
			$textbox1.Text = $script:path_to_ida
		}
	}
	
	$Sel_Click={
		fbtnSelectIdaPath_Click	
	}
	
	
	$buttonSelectFolderWithHype_Click={
		fbtnSelectHvBin_Click
	}
	
	$linklabelHyperVBinariesFolder_LinkClicked=[System.Windows.Forms.LinkLabelLinkClickedEventHandler]{
	#Event Argument: $_ = [System.Windows.Forms.LinkLabelLinkClickedEventArgs]
		#TODO: Place custom script here
		
		if ($textbox2.Text -eq "")
		{
			PrintText ("Please, specify directory with Hyper-V") "red"
		} else 
		{
			Invoke-Item $textbox2.Text
		}
	}
	
	$buttonStart_Click={
		#TODO: Place custom script here
		if ($textbox2.Text -ne "")
		{
			$script:dir_with_hvcalls_bin = $textbox2.Text
		}	
		hvcall_extract
	}
	$buttonOpen_Click={
		#TODO: Place custom script here
		if ($textbox2.Text -eq "")
		{
			PrintText ("Please, specify directory with Hyper-V") "red"
		} else 
		{
			Invoke-Item $textbox2.Text
		}
	}
	
	# --End User Generated Script--
	#----------------------------------------------
	# Generated Events
	#----------------------------------------------
	
	$Form_StateCorrection_Load=
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$formHvcall_extractLaunch.WindowState = $InitialFormWindowState
	}

	#----------------------------------------------
	#region Generated Form Code
	#----------------------------------------------
	#
	# formHvcall_extractLaunch
	#
	$formHvcall_extractLaunch.Controls.Add($buttonOpen)
	$formHvcall_extractLaunch.Controls.Add($textbox2)
	$formHvcall_extractLaunch.Controls.Add($buttonGetHyperVFilesFromCu)
	$formHvcall_extractLaunch.Controls.Add($buttonStart)
	$formHvcall_extractLaunch.Controls.Add($richtextbox1)
	$formHvcall_extractLaunch.Controls.Add($buttonSelectFolderWithHype)
	$formHvcall_extractLaunch.Controls.Add($textbox1)
	$formHvcall_extractLaunch.Controls.Add($Sel)
	$formHvcall_extractLaunch.ClientSize = New-Object System.Drawing.Size(794,476)
	$formHvcall_extractLaunch.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$formHvcall_extractLaunch.Name = "formHvcall_extractLaunch"
	$formHvcall_extractLaunch.Text = "Hvcall_extract launcher"
	$formHvcall_extractLaunch.add_Load($FormEvent_Load)
	#
	# buttonOpen
	#
	$buttonOpen.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$buttonOpen.Location = New-Object System.Drawing.Point(473,87)
	$buttonOpen.Name = "buttonOpen"
	$buttonOpen.Size = New-Object System.Drawing.Size(75,23)
	$buttonOpen.TabIndex = 9
	$buttonOpen.Text = "Open"
	$buttonOpen.UseVisualStyleBackColor = $True
	$buttonOpen.add_Click($buttonOpen_Click)
	#
	# textbox2
	#
	$textbox2.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$textbox2.Location = New-Object System.Drawing.Point(25,87)
	$textbox2.Name = "textbox2"
	$textbox2.Size = New-Object System.Drawing.Size(440,20)
	$textbox2.TabIndex = 8
	#
	# buttonGetHyperVFilesFromCu
	#
	$buttonGetHyperVFilesFromCu.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$buttonGetHyperVFilesFromCu.Location = New-Object System.Drawing.Point(554,169)
	$buttonGetHyperVFilesFromCu.Name = "buttonGetHyperVFilesFromCu"
	$buttonGetHyperVFilesFromCu.Size = New-Object System.Drawing.Size(222,41)
	$buttonGetHyperVFilesFromCu.TabIndex = 7
	$buttonGetHyperVFilesFromCu.Text = "Get Hyper-V files from current Windows"
	$buttonGetHyperVFilesFromCu.UseVisualStyleBackColor = $True
	#
	# buttonStart
	#
	$buttonStart.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$buttonStart.Location = New-Object System.Drawing.Point(322,169)
	$buttonStart.Name = "buttonStart"
	$buttonStart.Size = New-Object System.Drawing.Size(143,41)
	$buttonStart.TabIndex = 6
	$buttonStart.Text = "Start"
	$buttonStart.UseVisualStyleBackColor = $True
	$buttonStart.add_Click($buttonStart_Click)
	#
	# richtextbox1
	#
	$richtextbox1.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$richtextbox1.Location = New-Object System.Drawing.Point(2,216)
	$richtextbox1.Name = "richtextbox1"
	$richtextbox1.Size = New-Object System.Drawing.Size(787,247)
	$richtextbox1.TabIndex = 5
	$richtextbox1.Text = ""
	#
	# buttonSelectFolderWithHype
	#
	$buttonSelectFolderWithHype.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$buttonSelectFolderWithHype.Location = New-Object System.Drawing.Point(554,87)
	$buttonSelectFolderWithHype.Name = "buttonSelectFolderWithHype"
	$buttonSelectFolderWithHype.Size = New-Object System.Drawing.Size(222,48)
	$buttonSelectFolderWithHype.TabIndex = 3
	$buttonSelectFolderWithHype.Text = "Select folder with Hyper-V binaries"
	$buttonSelectFolderWithHype.UseVisualStyleBackColor = $True
	$buttonSelectFolderWithHype.add_Click($buttonSelectFolderWithHype_Click)
	#
	# textbox1
	#
	$textbox1.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$textbox1.Location = New-Object System.Drawing.Point(25,12)
	$textbox1.Name = "textbox1"
	$textbox1.Size = New-Object System.Drawing.Size(440,20)
	$textbox1.TabIndex = 2
	#
	# Sel
	#
	$Sel.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$Sel.Location = New-Object System.Drawing.Point(554,12)
	$Sel.Name = "Sel"
	$Sel.Size = New-Object System.Drawing.Size(222,49)
	$Sel.TabIndex = 0
	$Sel.Text = "Select Path to IDA PRO"
	$Sel.UseVisualStyleBackColor = $True
	$Sel.add_Click($Sel_Click)
	#
	# folderbrowserdialog1
	#
	#
	# openfiledialog1
	#
	$openfiledialog1.CheckFileExists = $False
	$openfiledialog1.InitialDirectory = "."
	$openfiledialog1.ShowHelp = $True
	#endregion Generated Form Code

	#----------------------------------------------

	#Save the initial state of the form
	$InitialFormWindowState = $formHvcall_extractLaunch.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$formHvcall_extractLaunch.add_Load($Form_StateCorrection_Load)
	#Show the Form
	return $formHvcall_extractLaunch.ShowDialog()

} #End Function

#Call OnApplicationLoad to initialize
if(OnApplicationLoad -eq $true)
{
	#Create the form
	Call-hvcall_extract_pff | Out-Null
	#Perform cleanup
	OnApplicationExit
}
