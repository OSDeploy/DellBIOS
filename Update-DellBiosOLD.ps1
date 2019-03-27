<#
    .SYNOPSIS
        Updates Dell Bios
    .DESCRIPTION
        Automatically updates the BIOS using Dell Update Catalog
    .NOTES
        Name: Update-DellBios.ps1
        Author: David Segura
		Version: 18.05.30
    .PARAMETER Silent
        Silently update the BIOS and exit
    .PARAMETER Restart
        Silently update the BIOS and restart the computer
    .EXAMPLE
		Update-DellBios
		Launches the BIOS Upgrade with Prompts
    .EXAMPLE
		Update-DellBios -Silent
		Silently update the BIOS and exit
    .EXAMPLE
		Update-DellBios -Restart
		Silently update the BIOS and restart the computer
#>

[CmdletBinding()]
Param(
	[switch]$Restart,
	[switch]$Silent
)

Write-Host "Update-DellBios.ps1 PowerShell Script" -ForegroundColor Green

#Run Elevated
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Checking User Account Control settings ..." -ForegroundColor Green
	if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 0) {
        #UAC Disabled
        Write-Host "User Account Control is Disabled ... " -ForegroundColor Green
        Write-Host "You will need to correct your UAC Settings ..." -ForegroundColor Green
        Write-Host "Try running this script in an Elevated PowerShell session ... Exiting" -ForegroundColor Green
        Start-Sleep -s 10
        Return
    } else {
        #UAC Enabled
        Write-Host "UAC is Enabled" -ForegroundColor Green
	    Start-Sleep -s 3
		if ($Silent) {
			Write-Host "This script will relaunch with Elevated Permissions (Silent) ..." -ForegroundColor Green
			Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Silent" -Verb RunAs -Wait
		} elseif($Restart) {
			Write-Host "This script will relaunch with Elevated Permissions (Restart) ..." -ForegroundColor Green
			Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Restart" -Verb RunAs -Wait
		} else {
			Write-Host "This script will relaunch with Elevated Permissions ..." -ForegroundColor Green
			Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
		}
		Exit 0
    }
} else {
Write-Host "Running with Elevated Permissions ..." -ForegroundColor Green
Write-Host ""
}

Start-Transcript -path (Join-Path $env:Temp BiosUpdate.log)


#Check if this is a Dell System
if ( ! ($((Get-WmiObject -Class Win32_ComputerSystem).Manufacturer).Trim() -like "*Dell*")) {
	Write-Host "This script will only run on Dell Systems.  Exiting . . ." -ForegroundColor Green
	Start-Sleep -s 5
	Stop-Transcript
	Exit 0
}

	#======================================================================================
	#System Information
	$Manufacturer = $((Get-WmiObject -Class Win32_ComputerSystem).Manufacturer).Trim()
	$Model = $((Get-WmiObject -Class Win32_ComputerSystem).Model).Trim()

    #Try to get the SystemSKU from WMI
	try {$SystemSKU = $((Get-WmiObject -Class Win32_ComputerSystem).SystemSKUNumber).Trim()}
	catch {
        Write-Host "SystemSKU not in WMI" -ForegroundColor Red
        $SystemSKU = "Unknown"
    }

    If ($SystemSKU -eq "Unknown") {
        #Try to get the SystemSKU from the Registry
        try {$SystemSKU = $((Get-ItemProperty -Path HKLM:\HARDWARE\DESCRIPTION\System\BIOS).SystemSKU).Trim()}
	    catch {
            Write-Host "SystemSKU not in Registry" -ForegroundColor Red
            $SystemSKU = "Unknown"
        }
    }

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

	$DellBiosRoot = $PSScriptRoot
	$DellBiosUpdateXml = Join-Path $DellBiosRoot "DellBios.xml"
	$DellFlash64wExe = Join-Path $DellBiosRoot "Flash64W.exe"
	
	Write-Host "Dell Bios Update Root: $DellBiosRoot" -ForegroundColor Cyan
	Write-Host "Dell Bios Update Xml: $DellBiosUpdateXml" -ForegroundColor Cyan
	Write-Host "Dell Flash64 Exe: $DellFlash64wExe" -ForegroundColor Cyan
	Write-Host ""

	if ( ! ( test-path $DellBiosUpdateXml ) ) { 
		Write-Host "Could not locate $DellBiosUpdateXml ... Exiting" -ForegroundColor Red
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}
	
	if ( ! ( test-path $DellFlash64wExe ) ) { 
		Write-Host "Could not locate $DellFlash64wExe ... Exiting" -ForegroundColor Red
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}

	Write-Host ""
	Write-Host "Reading $DellBiosUpdateXml ..." -ForegroundColor Green
	$DellBiosUpdateList = Import-CliXml $DellBiosUpdateXml
	Write-Host "Success!"

	Write-Host ""
	If ($SystemSKU.Length -eq 4) {
		Write-Host "Filtering XML for items compatible with SystemSKU $SystemSKU ..." -ForegroundColor Green
		$DellBiosUpdateList = $DellBiosUpdateList | Where-Object {$_.SupportedSystemID -Contains $SystemSKU}
		Write-Host "Success!"
	} else {
		Write-Host "Filtering XML for items compatible with $Model ..." -ForegroundColor Green
		$DellBiosUpdateList = $DellBiosUpdateList | Where-Object {$_.SupportedDevices -Contains $Model}
		Write-Host "Success!"
	}

	if ($DellBiosUpdateList.PackageID.Count -eq '1') {
		$DellBiosUpdateList
	} else {
		Write-Host "Could not locate a compatible BIOS Update ... Exiting" -ForegroundColor Green
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}

	$BiosUpdate = @(Get-ChildItem -Path $DellBiosRoot -Include $DellBiosUpdateList.FileName -Recurse -File)

	if ($BiosUpdate.Count -eq '1') {
		Write-Host "Local Bios Update" -ForegroundColor Green
		$BiosUpdate
	} else {
		Write-Host "Could not locate a downloaded BIOS Update ... Exiting" -ForegroundColor Green
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}

	$DownloadedBiosVersion = $DellBiosUpdateList.DellVersion

	if ($BIOSVersion -like "A*") {
		$BIOSVersion = $BIOSVersion -replace "A",""
		$DownloadedBiosVersion = $DownloadedBiosVersion -replace "A",""
	} elseif ($BIOSVersion -like "*.*") {
		$BIOSVersion = [Version]$BIOSVersion
		$DownloadedBiosVersion = [Version]$DownloadedBiosVersion
	}

	if ($BIOSVersion -eq $DownloadedBiosVersion) {
		Write-Host "You are running the current BIOS Version ... Exiting" -ForegroundColor Cyan
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}

	if ($BIOSVersion -gt $DownloadedBiosVersion) {
		Write-Host "You are running a newer BIOS Version ... Exiting" -ForegroundColor Cyan
		Start-Sleep -s 5
		Stop-Transcript
		Exit 0
	}

	Write-Host "Bios Update will be applied" -ForegroundColor Green
	Write-Host "Starting Dell Bios Update ..." -ForegroundColor Green
	
	#Registry Restart Computer Key
	$registryPath = "HKLM:\Software\BiosUpdate"
	$registryName = "RebootPending"
	$registryValue = "0"

	if (!(Test-Path $registryPath)) {
		New-Item -Path $registryPath -Force | Out-Null
		New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType String -Force | Out-Null
	}

	if ($env:SystemDrive -eq "X:") {
		if ($OSArchitecture -like "*64*") {
			if ($Silent) {
			Write-Host "Executing (Silent): $DellFlash64wExe /b=`"$BiosUpdate`"" -ForegroundColor Green
			Start-Process -FilePath $DellFlash64wExe -ArgumentList "/b=`"$BiosUpdate`"","/s" -Wait
			New-ItemProperty -Path $registryPath -Name $registryName -Value "1" -PropertyType String -Force | Out-Null
			Stop-Transcript
			[System.Environment]::Exit(0)
			} elseif ($Restart) {
			Write-Host "System will restart automatically" -ForegroundColor Green
			Write-Host "Executing (Restart): $DellFlash64wExe /b=`"$BiosUpdate`"" -ForegroundColor Green
			Stop-Transcript
			Start-Process -FilePath $DellFlash64wExe -ArgumentList "/b=`"$BiosUpdate`"","/s","/r" -Wait
			[System.Environment]::Exit(0)
			} else {
			Write-Host "System will restart automatically" -ForegroundColor Green
			Write-Host "Executing: $DellFlash64wExe /b=`"$BiosUpdate`"" -ForegroundColor Green
			Start-Process -FilePath $DellFlash64wExe -ArgumentList "/b=`"$BiosUpdate`"" -Wait
			Stop-Transcript
			[System.Environment]::Exit(0)
			}
		}
	}

	if ($RunningOS -Like "*Windows 10*") {
		Write-Host "Checking Bitlocker ..." -ForegroundColor Green
		#http://www.dptechjournal.net/2017/01/powershell-script-to-deploy-dell.html
		#https://github.com/dptechjournal/Dell-Firmware-Updates/blob/master/Install_Dell_Bios_upgrade.ps1
		$drive = Get-BitLockerVolume | where { $_.ProtectionStatus -eq "On" -and $_.VolumeType -eq "OperatingSystem" }
		if ($drive) {
			Write-Host "Suspending Bitlocker ..." -ForegroundColor Green
			Suspend-BitLocker -Mountpoint $drive -RebootCount 1
			if (Get-BitLockerVolume -MountPoint $drive | where ProtectionStatus -eq "On") {
				Write-Host "Suspending Bitlocker Failed ... Exiting" -ForegroundColor Green
				Stop-Transcript
				Exit 0
			}
		}
	}
		
	if ($Silent) {
		Write-Host "Executing (Silent): $BiosUpdate" -ForegroundColor Green
		Start-Process ($BiosUpdate.FullName) -ArgumentList "/s" -Wait
		New-ItemProperty -Path $registryPath -Name $registryName -Value "1" -PropertyType String -Force | Out-Null
		Stop-Transcript
		[System.Environment]::Exit(0)
	} elseif ($Restart) {
		Write-Host "System will restart automatically" -ForegroundColor Green
		Write-Host "Executing (Restart): $BiosUpdate" -ForegroundColor Green
		Stop-Transcript
		Start-Process ($BiosUpdate.FullName) -ArgumentList "/s","/r" -Wait
		[System.Environment]::Exit(0)
	} else {
		Write-Host "System will restart automatically" -ForegroundColor Green
		Write-Host "Executing: $BiosUpdate" -ForegroundColor Green
		Start-Process ($BiosUpdate.FullName) -Wait
		Stop-Transcript
		[System.Environment]::Exit(0)
	}