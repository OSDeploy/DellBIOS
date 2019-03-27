<#
    .SYNOPSIS
        Downloads BIOS Updates
    .DESCRIPTION
        Allows the selection of Bios Updates to download for Dell systems.
    .NOTES
        Name: Get-DellBiosUpdate.ps1
        Author: David Segura
		Version: 18.05.30
    .PARAMETER Path
        Required.  Path to save the Bios Updates
    .EXAMPLE
        Downloads Bios Updates to C:\DellBiosUpdates
        Get-DellBiosUpdate -Path C:\DellBiosUpdates
    .PARAMETER OldRevisions
        Specify Delete or Show for old Bios Updates
    .EXAMPLE
        Downloads Bios Updates to C:\DellBiosUpdates and automatically removes old Bios revisions
        Get-DellBiosUpdate -Path C:\DellBiosUpdates -OldRevisions Delete
    .EXAMPLE
        Downloads Bios Updates to C:\DellBiosUpdates and shows old Bios revisions that can be selected for deletion
        Get-DellBiosUpdate -Path C:\DellBiosUpdates -OldRevisions Show
#>

function Get-DellBiosUpdate
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)]
		[string]$Path,
		[switch]$HideDownloaded,
        [ValidateSet('Delete','Show')]
        [string]$OldRevisions
	)

	#======================================================================================
	#System Information
	$global:Manufacturer = $((Get-WmiObject -Class Win32_ComputerSystem).Manufacturer).Trim()
	$Model = $((Get-WmiObject -Class Win32_ComputerSystem).Model).Trim()
	try {$SystemSKU = $((Get-WmiObject -Class Win32_ComputerSystem).SystemSKUNumber).Trim()}
	catch {$SystemSKU = "Unknown"}
	$SerialNumber = $((Get-WmiObject -Class Win32_BIOS).SerialNumber).Trim()
	$BIOSVersion = $((Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion).Trim()
	$RunningOS = $((Get-WmiObject -Class Win32_OperatingSystem).Caption).Trim()
	$OSArchitecture = $((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture).Trim()
	
	Write-Host "Manufacturer: $Manufacturer" -ForegroundColor Cyan
	Write-Host "Model: $Model" -ForegroundColor Cyan
	Write-Host "SystemSKU: $SystemSKU" -ForegroundColor Cyan
	Write-Host "SerialNumber: $SerialNumber" -ForegroundColor Cyan
	Write-Host "BIOS Version: $BIOSVersion" -ForegroundColor Cyan
	Write-Host "Running OS: $RunningOS" -ForegroundColor Cyan
	Write-Host "OS Architecture: $OSArchitecture" -ForegroundColor Cyan
	if ($env:SystemDrive -eq "X:") {Write-Host "System is running in WinPE" -ForegroundColor Green}
	Write-Host ""
	#======================================================================================
	$DellBiosRoot = $Path
	$DellBiosBin = Join-Path $DellBiosRoot "Bin"
	Write-Host "DellBios Root: $DellBiosRoot" -ForegroundColor Cyan
	Write-Host "DellBios Bin: $DellBiosBin" -ForegroundColor Cyan
	CreateDirectory -Path $DellBiosBin
	Write-Host ""
	#======================================================================================
	$DellDownloadsUrl = "http://downloads.dell.com/"
	$DellCatalogPcUrl = "http://downloads.dell.com/catalog/CatalogPC.cab"
	$DellCatalogPcCab = Join-Path $DellBiosBin ($DellCatalogPcUrl | Split-Path -Leaf)
	$DellCatalogPcXml = Join-Path $DellBiosBin "CatalogPC.xml"
	Write-Host "Dell Downloads URL: $DellDownloadsUrl" -ForegroundColor Cyan
	Write-Host "Dell Catalog URL: $DellCatalogPcUrl" -ForegroundColor Cyan
	Write-Host "Dell Catalog CAB: $DellCatalogPcCab" -ForegroundColor Cyan
	Write-Host "Dell Catalog XML: $DellCatalogPcXml" -ForegroundColor Cyan
	Write-Host ""
	#======================================================================================
	Write-Host "Downloading $DellCatalogPcUrl ..." -ForegroundColor Green
	try {	
		(New-Object System.Net.WebClient).DownloadFile($DellCatalogPcUrl, $DellCatalogPcCab)
		#Start-BitsTransfer -Source $DellCatalogPcUrl -Destination $DellCatalogPcCab
	} catch { 
		Write-Host "Download Failed!" -ForegroundColor Red
	}
	#======================================================================================
	if ( test-path $DellCatalogPcCab ) {
		Write-Host "Success!"
		Write-Host ""
		Write-Host "Unblocking $DellCatalogPcCab ..." -ForegroundColor Green
		Unblock-File -Path $DellCatalogPcCab
		Start-Sleep -s 1
		Write-Host "Success!"
		Write-Host ""
		Write-Host "Expanding $DellCatalogPcCab ..." -ForegroundColor Green
		Expand "$DellCatalogPcCab" "$DellCatalogPcXml" | Out-String | Write-Host
	}
	#======================================================================================
	if ( ! ( test-path $DellCatalogPcXml ) ) { 
		Write-Host "Could not expand required Dell Update Catalog ... Exiting" -ForegroundColor Red
		Return
	} else {
		Write-Host "Success!"
	}
	Write-Host ""
	#======================================================================================
	$DellFlash64wUrl = "http://downloads.dell.com/FOLDER04165397M/1/Flash64W.zip"
	$DellFlash64wZip = Join-Path $DellBiosBin ($DellFlash64wUrl | Split-Path -Leaf)
	$DellFlash64wExe = Join-Path $DellBiosBin "Flash64W.exe"
	Write-Host "Dell Flash64 URL: $DellFlash64wUrl" -ForegroundColor Cyan
	Write-Host "Dell Flash64 Zip: $DellFlash64wZip" -ForegroundColor Cyan
	Write-Host "Dell Flash64 Exe: $DellFlash64wExe" -ForegroundColor Cyan
	Write-Host ""
	#======================================================================================
	Write-Host "Downloading $DellFlash64wUrl ..." -ForegroundColor Green
	try {	
		(New-Object System.Net.WebClient).DownloadFile($DellFlash64wUrl, $DellFlash64wZip)
	} catch { 
		Write-Host "Download Failed!" -ForegroundColor Red
	}
	#======================================================================================
	if ( test-path $DellFlash64wZip ) {
		Write-Host "Success!"
		Write-Host ""
		Write-Host "Unblocking $DellFlash64wZip ..." -ForegroundColor Green
		Unblock-File -Path $DellFlash64wZip
		Start-Sleep -s 1
		Write-Host "Success!"
		Write-Host ""
		Write-Host "Expanding $DellFlash64wZip ..." -ForegroundColor Green
		Expand-Archive -Path $DellFlash64wZip -DestinationPath $DellBiosBin -Force
	}
	
	if ( ! ( test-path $DellFlash64wExe ) ) { 
		Write-Host "Could not download the required Dell Flash64W.exe ... Exiting" -ForegroundColor Red
		Return
	} else {
		Copy-Item -Path $DellFlash64wExe -Destination $DellBiosRoot
		Write-Host "Success!"
	}
	Write-Host ""
	#======================================================================================
	$UpdateBiosPS1 = Join-Path $DellBiosRoot "Update-DellBios.ps1"
	$UpdateBiosPrompt = Join-Path $DellBiosRoot "Update-DellBios-Prompt.cmd"
	$UpdateBiosSilent = Join-Path $DellBiosRoot "Update-DellBios-Silent.cmd"
	$UpdateBiosRestart = Join-Path $DellBiosRoot "Update-DellBios-Restart.cmd"
	Write-Host "Update-DellBios PS1: $UpdateBiosPS1" -ForegroundColor Cyan
	Write-Host "Update-DellBios Cmd Prompt: $UpdateBiosPrompt" -ForegroundColor Cyan
	Write-Host "Update-DellBios Cmd Silent: $UpdateBiosSilent" -ForegroundColor Cyan
	Write-Host "Update-DellBios Cmd Restart: $UpdateBiosRestart" -ForegroundColor Cyan
	Write-Host "Updating Scripts ..." -ForegroundColor Green
	Copy-Item -Path (Join-Path $PSScriptRoot "Update-DellBios.ps1") -Destination $DellBiosRoot
	Copy-Item -Path (Join-Path $PSScriptRoot "Update-DellBios-Prompt.cmd") -Destination $DellBiosRoot
	Copy-Item -Path (Join-Path $PSScriptRoot "Update-DellBios-Silent.cmd") -Destination $DellBiosRoot
	Copy-Item -Path (Join-Path $PSScriptRoot "Update-DellBios-Restart.cmd") -Destination $DellBiosRoot
	Write-Host ""
	#======================================================================================
	Write-Host "Reading $DellCatalogPcXml ..." -ForegroundColor Green
	[xml]$XMLDellUpdateCatalog = Get-Content "$DellCatalogPcXml" -ErrorAction Stop
	Write-Host "Success!"
	Write-Host ""
	#======================================================================================
	Write-Host "Loading Dell Update Catalog XML Nodes ..." -ForegroundColor Green
	$DellUpdateList = $XMLDellUpdateCatalog.Manifest.SoftwareComponent
	Write-Host "Success!"
	Write-Host ""
	#======================================================================================
	Write-Host "Generating a list of previous downloads in $DellBiosRoot ..." -ForegroundColor Green
	$DownloadedFiles = @(Get-ChildItem -Path $DellBiosRoot -Include *.exe -Exclude "Flash64W.exe" -Recurse -File)
	Write-Host "Success!"
	Write-Host ""
	#======================================================================================
	Write-Host "Filtering Dell Update Catalog XML for BIOS Downloads ..." -ForegroundColor Green
	$DellUpdateList = $DellUpdateList | Where-Object {$_.ComponentType.Display.'#cdata-section'.Trim() -eq 'BIOS'}
	Write-Host "Success!"
	Write-Host ""
	#======================================================================================
	Write-Host "Finding existing BIOS Updates ..." -ForegroundColor Green
	$Orphans = @()
	foreach ($Orphan in $DownloadedFiles) {
		If ((split-path $DellUpdateList.path -leaf) -NotContains $Orphan.Name) {
		$Orphans += $Orphan
		}
	}
	Write-Host "Success!"
	#======================================================================================
	if ($OldRevisions -eq 'Delete') {
		$Orphans = $Orphans | Select-Object -Property Name, FullName, CreationTime
		foreach ($OrphanSelected in $Orphans) {
			$OrphanFile = $OrphanSelected.FullName
			Write-Host "Removing $OrphanFile ..." -ForegroundColor Green
			Remove-Item -Path $OrphanFile
		}
	}
	#======================================================================================
	if ($OldRevisions -eq 'Show') {
		$Orphans = $Orphans | Select-Object -Property Name, FullName, CreationTime | Out-GridView -PassThru -Title "Superseded BIOS Updates: Press OK to Remove or Cancel to Skip"
		foreach ($OrphanSelected in $Orphans) {
			Write-Host "Removing $OrphanSelected ..." -ForegroundColor Green
			Remove-Item -Path $OrphanSelected.FullName
		}
	}
	#======================================================================================
	Write-Host ""
	Write-Host "Generating Update List Array ..." -ForegroundColor Green
	$DellUpdateList = $DellUpdateList | Select-Object @{Label="ReleaseDate";Expression = {[datetime] ($_.dateTime)};},
	@{Label="Downloaded";Expression = {($DownloadedFiles.Name -Contains (split-path -leaf $_.path))};},
	@{Label="PackageGroup";Expression={"Undefined"};},
	@{Label="BiosGroup";Expression={($_.SupportedDevices.Device.Display.'#cdata-section'.Trim() -replace "PRECISION","Precision" -replace "Dell ","" -replace "  "," ")};},
	@{Label="FileName";Expression = {(split-path -leaf $_.path)};},
	@{Label="DellVersion";Expression={$_.dellVersion};},
	@{Label="Size(MB)";Expression={'{0:f2}' -f ($_.size/1MB)};},
	@{Label="PackageID";Expression={$_.packageID};},
	@{Label="Name";Expression={($_.Name.Display.'#cdata-section'.Trim())};},
	#@{Label="VendorVersion";Expression={$_.vendorVersion};},
	@{Label="SupportedBrand";Expression={($_.SupportedSystems.Brand.Display.'#cdata-section'.Trim())};},
	@{Label="SupportedModel";Expression={($_.SupportedSystems.Brand.Model.Display.'#cdata-section'.Trim() | Select-Object -unique)};},
	@{Label="SupportedSystemID";Expression={($_.SupportedSystems.Brand.Model.systemID.Trim() | Select-Object -unique)};},
	@{Label="DownloadURL";Expression={-join ($DellDownloadsUrl, $_.path)};}
	#@{Label="PackageType";Expression={$_.packageType};},
	#@{Label="ReleaseID";Expression={$_.ReleaseID};},
	#@{Label="HashMD5";Expression={$_.HashMD5};},
	#@{Label="Description";Expression={($_.Description.Display.'#cdata-section'.Trim())};},
	#@{Label="Category";Expression={($_.Category.Display.'#cdata-section'.Trim())};},
	#@{Label="SupportedOperatingSystems";Expression={($_.SupportedOperatingSystems.OperatingSystem.Display.'#cdata-section'.Trim())};},
	#@{Label="Criticality";Expression={($_.Criticality.Display.'#cdata-section'.Trim())};},
	#| Sort-Object ReleaseDate -Descending | Out-GridView -OutputMode Multiple -Title "Select Dell BIOS Downloads"
	Write-Host "Success!"
	#======================================================================================
	#Remove Old Updates
	$DellUpdateList = $DellUpdateList | Where-Object {$_.PackageID -ne "9J7J6"}
	$DellUpdateList = $DellUpdateList | Where-Object {$_.PackageID -ne "CN8JD"}
	$DellUpdateList = $DellUpdateList | Where-Object {$_.PackageID -ne "W7RCH"}
	$DellUpdateList = $DellUpdateList | Where-Object {$_.PackageID -ne "9MDXF"}	#T3600 A15
	$DellUpdateList = $DellUpdateList | Where-Object {$_.PackageID -ne "9PM1X"}	#T5600 A15

	#Remove T0N11 32
	$DellUpdateList = $DellUpdateList | Where-Object {$_.DownloadURL -NotLike "*WN32*"}
			
	#if ($SystemCompatible) {
	#	Write-Host "Filtering XML for items compatible with SystemSKU $SystemSKU"
	#	$DellUpdateList = $DellUpdateList | Where-Object {$_.SupportedSystems.Brand.Model.systemID -Contains $SystemSKU}
	#}

	foreach ($Download in $DellUpdateList) {
		$Download.Name = $Download.Name -replace "DELL", ""
		$Download.Name = $Download.Name -replace "LATITUDE", "Latitude"
		$Download.Name = $Download.Name -replace "System BIOS", ""
		$Download.Name = $Download.Name.Trim()
		$Download.SupportedBrand = $Download.SupportedBrand -replace "Optiplex", "OptiPlex"
		$Download.SupportedBrand = $Download.SupportedBrand -replace "XPSNotebook", "XPS"
		$Download.SupportedModel = $Download.SupportedModel -replace "2-IN-1", "2-in-1"
		$Download.SupportedModel = $Download.SupportedModel -replace "BIOS", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "OptiPlex", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "Precision", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "System", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "Tower", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "XL", ""
		$Download.SupportedModel = $Download.SupportedModel -replace "XPS", ""
		$Download.SupportedModel = $Download.SupportedModel.Trim()
		$Download.BiosGroup = $Download.BiosGroup -replace "2-IN-1", "2-in-1"
		$Download.BiosGroup = $Download.BiosGroup -replace "/", " "
		$Download.BiosGroup = $Download.BiosGroup -replace "Plano", "Latitude"
		$Download.BiosGroup = $Download.BiosGroup -replace "SW,,LAT,", "Latitude "
		$Download.BiosGroup = $Download.BiosGroup -replace "BIOS", ""
		$Download.BiosGroup = $Download.BiosGroup -replace "PRO", "Pro"
		$Download.BiosGroup = $Download.BiosGroup -replace "System", ""
		$Download.BiosGroup = $Download.BiosGroup -replace "LATITUDE", "Latitude"
		$Download.BiosGroup = $Download.BiosGroup -replace "OptiPlex", "OptiPlex"
		$Download.BiosGroup = $Download.BiosGroup.Trim()
		if ($Download.SupportedSystemID -eq '0493') {$Download.SupportedSystemID = "0493"}
		if ($Download.SupportedSystemID -eq '053D') {$Download.SupportedSystemID = "053D"}
		
		if ($Download.SupportedSystemID -eq '0233') {$Download.SupportedModel = "E6400"}
		if ($Download.SupportedSystemID -eq '040A') {$Download.SupportedModel = "E6410"}
		if ($Download.SupportedSystemID -eq '0493') {$Download.SupportedModel = "E6420"}
		if ($Download.SupportedSystemID -eq '053D') {$Download.SupportedModel = "E5530 non-vPro"}
		if ($Download.SupportedSystemID -eq '054A') {$Download.SupportedModel = "E5530 vPro"}
		if ($Download.SupportedSystemID -eq '054C') {$Download.SupportedModel = "L421X"}
		if ($Download.SupportedSystemID -eq '054E') {$Download.SupportedModel = "9Q23"}
		if ($Download.SupportedSystemID -eq '05C2') {$Download.SupportedModel = "3011 AIO"}
		if ($Download.SupportedSystemID -eq '0608') {$Download.SupportedModel = "3540"}
		if ($Download.SupportedSystemID -eq '060F') {$Download.SupportedModel = "7404 Rugged"}
		if ($Download.SupportedSystemID -eq '0610') {$Download.SupportedModel = "7204 Rugged"}
		if ($Download.SupportedSystemID -eq '0625') {$Download.SupportedModel = "9030 AIO"}
		if ($Download.SupportedSystemID -eq '062F') {$Download.SupportedModel = "5404 Rugged"}
		if ($Download.SupportedSystemID -eq '0673') {$Download.SupportedModel = "7350 2-in-1"}
		if ($Download.SupportedSystemID -eq '06A2') {$Download.SupportedModel = "7202 Rugged"}
		if ($Download.SupportedSystemID -eq '07A4') {$Download.SupportedModel = "5285 2-in-1"}
		if ($Download.SupportedSystemID -eq '07AA') {$Download.SupportedModel = "5289 2-in-1"}
		if ($Download.SupportedSystemID -eq '07AB') {$Download.SupportedModel = "7389 2-in-1"}
		if ($Download.SupportedSystemID -eq '07BA') {$Download.SupportedModel = "3379 2-in-1"}
		if ($Download.SupportedSystemID -eq '07D3') {$Download.SupportedModel = "7212 Rugged"}
		if ($Download.SupportedSystemID -eq '07F0') {$Download.SupportedModel = "5055 S"}
		if ($Download.SupportedSystemID -eq '07F1') {$Download.SupportedModel = "5055 B"}
		if ($Download.SupportedSystemID -eq '0823') {$Download.SupportedModel = "7390 2-in-1"}
		
		#if ($Download.SupportedSystemID -eq '0496') {$Download.SupportedModel = ($Download.SupportedModel -replace "XL", "")}
		#if ($Download.SupportedSystemID -eq '0497') {$Download.SupportedModel = ($Download.SupportedModel -replace "XL", "")}
		#if ($Download.SupportedSystemID -eq '0617') {$Download.SupportedModel = ($Download.SupportedModel -replace "XL", "")}

		if ($Download.SupportedSystemID -eq '0727') {$Download.BiosGroup = $Download.SupportedModel}
		
		#$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")
		
		if ($Download.BiosGroup -eq 'Latitude 5250') {$Download.SupportedModel = "5250"}
		if ($Download.BiosGroup -eq 'Latitude 5250') {$Download.SupportedSystemID = "0644"}
		if ($Download.BiosGroup -eq 'Latitude 5450') {$Download.SupportedModel = "5450"}
		if ($Download.BiosGroup -eq 'Latitude 5450') {$Download.SupportedSystemID = "0645"}
		if ($Download.BiosGroup -eq 'Latitude 5550') {$Download.SupportedModel = "5550"}
		if ($Download.BiosGroup -eq 'Latitude 5550') {$Download.SupportedSystemID = "0646"}
		if ($Download.BiosGroup -eq 'Latitude 7250') {$Download.SupportedModel = "7250"}
		if ($Download.BiosGroup -eq 'Latitude 7250') {$Download.SupportedSystemID = "0647"}
		if ($Download.BiosGroup -eq 'Latitude E5250') {$Download.SupportedModel = "E5250"}
		if ($Download.BiosGroup -eq 'Latitude E5250') {$Download.SupportedSystemID = "062A"}
		if ($Download.BiosGroup -eq 'Latitude E5450') {$Download.SupportedModel = "E5450"}
		if ($Download.BiosGroup -eq 'Latitude E5450') {$Download.SupportedSystemID = "062B"}
		if ($Download.BiosGroup -eq 'Latitude E5550') {$Download.SupportedModel = "E5550"}
		if ($Download.BiosGroup -eq 'Latitude E5550') {$Download.SupportedSystemID = "062C"}
		if ($Download.BiosGroup -eq 'Latitude E7250') {$Download.SupportedModel = "E7250"}
		if ($Download.BiosGroup -eq 'Latitude E7250') {$Download.SupportedSystemID = "062D"}
		
		if ($Download.SupportedSystemID -eq '05E3') {$Download.BiosGroup = "XPS 9Q33 9Q34"}
		if ($Download.SupportedSystemID -eq '0603') {$Download.BiosGroup = "Venue 11 Pro 5130"}
		if ($Download.SupportedSystemID -eq '0630') {$Download.BiosGroup = "Venue 8 Pro 5830"}
		if ($Download.SupportedSystemID -eq '06DA') {$Download.BiosGroup = "Precision 7510 7710"}
		if ($Download.SupportedSystemID -eq '06DC') {$Download.BiosGroup = "Latitude E7270 E7470"}
		if ($Download.SupportedSystemID -eq '06E0') {$Download.BiosGroup = "Latitude E5270 E5470 E5570 Precision 3510"}
		if ($Download.SupportedSystemID -eq '06E6') {$Download.BiosGroup = "Latitude 5175 5179 2-in-1"}
		if ($Download.SupportedSystemID -eq '06E7') {$Download.BiosGroup = "Venue 8 Pro 5855 10 Pro 5056"}
		if ($Download.SupportedSystemID -eq '06F1') {$Download.BiosGroup = "Latitude 3460 3560"}
		if ($Download.SupportedSystemID -eq '06F3') {$Download.BiosGroup = "Latitude 3470 3570"}
		if ($Download.SupportedSystemID -eq '0702') {$Download.BiosGroup = "Latitude 7275 XPS 9250"}
		if ($Download.SupportedSystemID -eq '071D') {$Download.BiosGroup = "Latitude 5414 7214 7414 Rugged"}
		if ($Download.SupportedSystemID -eq '0739') {$Download.BiosGroup = "Precision 7820 7920"}
		if ($Download.SupportedSystemID -eq '07B0') {$Download.BiosGroup = "Precision 7520 7720"}
		if ($Download.SupportedSystemID -eq '07B3') {$Download.BiosGroup = "Latitude 3180 3189"}
		if ($Download.SupportedSystemID -eq '07B8') {$Download.BiosGroup = "Latitude 3480 3580"}
		if ($Download.SupportedSystemID -eq '07D0') {$Download.BiosGroup = "Latitude 5280 5480 5580 Precision 3520"}
		if ($Download.SupportedSystemID -eq '07F3') {$Download.BiosGroup = "Latitude 7280 7380 7480"}
		if ($Download.SupportedSystemID -eq '0816') {$Download.BiosGroup = "Latitude 5290 5490 5590"}
		if ($Download.SupportedSystemID -eq '081B') {$Download.BiosGroup = "Latitude 7290 7390 7490"}
		if ($Download.SupportedSystemID -eq '0839') {$Download.BiosGroup = "Latitude 3490 3590"}
		
		if ($Download.BiosGroup -eq '') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		
		if ($Download.SupportedSystemID -eq '040A') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0493') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '04EB') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '04EC') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0533') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0534') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0535') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '053D') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0543') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '054A') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '05BD') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '05C2') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0606') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0608') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '060A') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '060F') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0610') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0617') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0618') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0619') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0623') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '062F') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0665') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0673') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '06A2') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '06B7') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '06C7') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '06E4') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0704') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0718') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0738') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '075B') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '075D') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '077A') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '079D') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '079E') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07A4') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07AA') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07AB') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07BA') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07BE') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07D3') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '07E6') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '080D') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0823') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '0878') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '087C') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		if ($Download.SupportedSystemID -eq '087D') {$Download.BiosGroup = ($Download.SupportedBrand.Trim(), $Download.SupportedModel.Trim() -join " ")}
		
		
	}

	#Define Dell PackageGroup
	#Processed in order, first entry wins
	foreach ($Download in $DellUpdateList) {
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.SupportedBrand -like '*Cloud*') 		{$Download.PackageGroup = 'CloudClient'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'XPS*') 			{$Download.PackageGroup = 'XPS'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'Latitude 10*') 	{$Download.PackageGroup = 'Tablet'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Venue*') 		{$Download.PackageGroup = 'Tablet'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude 5*') 	{$Download.PackageGroup = 'Latitude5'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude E5*') 	{$Download.PackageGroup = 'Latitude5'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude 6*') 	{$Download.PackageGroup = 'Latitude6'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude E6*') 	{$Download.PackageGroup = 'Latitude6'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude 7*') 	{$Download.PackageGroup = 'Latitude7'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Latitude E7*') 	{$Download.PackageGroup = 'Latitude7'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.SupportedBrand -like '*Latitude*') 		{$Download.PackageGroup = 'Latitude'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'Precision M*')	{$Download.PackageGroup = 'PrecisionM'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like '*Rack*')			{$Download.PackageGroup = 'PrecisionR'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'Precision R*')	{$Download.PackageGroup = 'PrecisionR'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'Precision T*')	{$Download.PackageGroup = 'PrecisionT'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.BiosGroup -like 'Precision*')		{$Download.PackageGroup = 'Precision'}

		if ($Download.PackageGroup -eq 'Undefined' -and $Download.SupportedModel -like '*AIO*') 			{$Download.PackageGroup = 'OptiPlexAIO'}
		if ($Download.PackageGroup -eq 'Undefined' -and $Download.SupportedBrand -like '*OptiPlex*') 		{$Download.PackageGroup = 'OptiPlex'}
	}

	Write-Host ""
	$DellBiosUpdateXml = Join-Path $DellBiosRoot "DellBios.xml"
	$DellBiosUpdateCsv = Join-Path $DellBiosRoot "DellBios.csv"
	Write-Host "Exporting XML to $DellBiosUpdateXml ..." -ForegroundColor Green
	$DellUpdateList | Export-Clixml -Path $DellBiosUpdateXml
	Write-Host "Exporting CSV to $DellBiosUpdateCsv ..." -ForegroundColor Green
	$DellUpdateList | Export-Csv -Path $DellBiosUpdateCsv -NoTypeInformation
	
	$BiosSubdirs = @(Get-ChildItem -Path $DellBiosRoot -Directory)
	
	if ($HideDownloaded.IsPresent) {
		Write-Host ""
		Write-Host "Hiding Downloaded BIOS Updates ..." -ForegroundColor Green
		$DellUpdateList = $DellUpdateList | Where-Object {$_.Downloaded -ne 'True'}
		Write-Host "Success!"
	}

	Write-Host ""
	Write-Host "Displaying Dell Bios Update Download Grid ..." -ForegroundColor Green
	Write-Host ""
	$DellDownloads = $DellUpdateList | Sort-Object ReleaseDate -Descending | Out-GridView -OutputMode Multiple -Title "Select Dell BIOS Downloads"
	
	#Exit the script if cancelled
	if($null -eq $DellDownloads) {
		Write-Host ""
		Write-Host "Script was cancelled . . . Exiting!" -ForegroundColor Cyan
		Return
	}

	foreach ($Download in $DellDownloads) {
		$SourceFile = $Download.DownloadURL.Trim()
		Write-Host "Downloading: $SourceFile" -ForegroundColor Green

		$DestDirName = $Download.BiosGroup.Trim()

		$DownloadGroup = $Download.PackageGroup.Trim()

		$DownloadDir = Join-Path $DellBiosRoot (Join-Path $DownloadGroup $DestDirName)
		#Write-Host "Download Directory: $DownloadDir"
					
		CreateDirectory -Path $DownloadDir

		$DownloadFile = Join-Path $DownloadDir (split-path -leaf $Download.DownloadURL.Trim())
		Write-Host "$DownloadFile" -ForegroundColor Green
			
		if (!(Test-Path $DownloadFile)) {
			#Import-Module BitsTransfer
			#Write-Host "Starting Bits Transfer . . ."
			Start-BitsTransfer -Source $SourceFile -Destination $DownloadFile
			Write-Host "Success!"
		} else {
			Write-Host "Destination file already exists!"
		}
		Write-Host ""
	}
	
	$BiosSubdirs = @(Get-ChildItem -Path $DellBiosRoot -Directory -Exclude "Bin")
	
	foreach ($Subdir in $BiosSubdirs) {
		Write-Host ""
		$DellBiosUpdateXml = Join-Path $DellBiosRoot (Join-Path $Subdir.Name "DellBios.xml")
		$DellBiosUpdateCsv = Join-Path $DellBiosRoot (Join-Path $Subdir.Name "DellBios.csv")
		Write-Host "Updating XML to $DellBiosUpdateXml ..." -ForegroundColor Green
		$DellUpdateList | Export-Clixml -Path $DellBiosUpdateXml
		Write-Host "Updating CSV to $DellBiosUpdateCsv ..." -ForegroundColor Green
		$DellUpdateList | Export-Csv -Path $DellBiosUpdateCsv -NoTypeInformation
		
		Copy-Item -Path $DellFlash64wExe -Destination (Join-Path $DellBiosRoot $Subdir.Name)
		Copy-Item -Path $UpdateBiosPS1 -Destination (Join-Path $DellBiosRoot $Subdir.Name)
		Copy-Item -Path $UpdateBiosPrompt -Destination (Join-Path $DellBiosRoot $Subdir.Name)
		Copy-Item -Path $UpdateBiosSilent -Destination (Join-Path $DellBiosRoot $Subdir.Name)
		Copy-Item -Path $UpdateBiosRestart -Destination (Join-Path $DellBiosRoot $Subdir.Name)

		Write-Host "Success!"
	}

	Write-Host ""
	Write-Host "Complete!"
}

function CreateDirectory ( [string] $Path ) {
	#Write-Host "Creating Directory $Path"
	if ( ! ( test-path $Path ) ) { New-Item -Type Directory -Path $Path }
}
