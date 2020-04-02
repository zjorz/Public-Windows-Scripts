### Abstract: This PoSH Script Joins A Stand Alone Server To An AD Domain Through A Targeted RODC
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2013-04-12: Initial version of the script in PowerShell (v0.1)
### 2017-03-16: Added description for code 1219, added logging (same folder as script), check and clean any site related setting in registry,
###				added check that script is executed with admin credentials, added check for connectivity to RODC (v0.2)
###
### WARNING:	This script checks connectivity to the targeted RODC for a specific set of ports. The script is configured with default ports
###				that are required, but it is also configured with a "Custom RPC Static Port For NetLogon" (40961) as that is what I have configured in
###				my test/demo environment. If you are using a different port number, then make sure to change that first before running the script.
###				If you use the dynamic range of RPC ports OR you do not have a firewall between your servers and RODCs, then remove that custom port number!
###

<#
.SYNOPSIS
	Joins a stand alone server to an AD domain through a targeted RODC.

.DESCRIPTION
    Joins a stand alone server to an AD domain through a targeted RODC.

.PARAMETER adDomain
	The FQDN of the AD domain, the server needs to be joined to.
	
.PARAMETER rodcFQDN
	The FQDN of the RODC that will be targeted to join the server to the AD domain through a read-only join.

.PARAMETER ipAddressLocalHost
	The IP address of the local server.

.PARAMETER compAccountPWD
	The password of the computer account that was set during the pre-creation of that computer account.

.EXAMPLE
	- Join the server SERVER1 to the AD domain COMPANY.COM through the RODC RODC1.COMPANY.COM
	
	.\Read-Only-Domain-Join.ps1 -adDomain COMPANY.COM -rodcFQDN RODC1.COMPANY.COM -ipAddressLocalHost 192.168.6.3 -compAccountPWD 'MyPa$$w0rd'

.NOTES
	This script requires local administrator permissions.
#>

Param(
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the FQDN of the AD domain to join to.')]
	[ValidateNotNullOrEmpty()]
	[string]$adDomain,
	
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the FQDN of the RODC to target for the read-only domain join.')]
	[ValidateNotNullOrEmpty()]
	[string]$rodcFQDN,
	
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the IP address of the local stand alone server.')]
	[ValidateNotNullOrEmpty()]
	[string]$ipAddressLocalHost,
	
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the password that was set for the pre-created computer account.')]
	[ValidateNotNullOrEmpty()]
	[string]$compAccountPWD
)

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFileFullPath" -append -inputObject "$datetimeLogLine$dataToLog"
	#Write-Output($datetimeLogLine + $dataToLog)
	If ($lineType -eq $NULL) {
		Write-Host "$datetimeLogLine$dataToLog"
	}
	If ($lineType -eq "SUCCESS") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "ERROR") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "WARNING") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "HEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Magenta
	}
	If ($lineType -eq "REMARK") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Cyan
	}
}

### FUNCTION: Test Credentials For Admin Privileges
Function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

### FUNCTION: Test The Port Connection
# Source: # Based Upon http://gallery.technet.microsoft.com/scriptcenter/97119ed6-6fb2-446d-98d8-32d823867131
Function PortConnectionCheck($fqdnServer,$port,$timeOut) {
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer,$port,$null,$null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		#$error.Clear()
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Determine The Network ID To Which The IP Address And Subnet Mask Belong
# Written By Nathan Linley | http://myitpath.blogspot.com
# Source Of Original Script: http://poshcode.org/2888
Function Get-NetworkID ([string]$ipAddress, [string]$subnetMask) {
	$ipOctets = $ipAddress.split(".")
	$subnetOctets = $subnetMask.split(".")
	$result = ""
	For ($i = 0; $i -lt 4; $i++) {
		$result += $ipOctets[$i] -band $subnetOctets[$i]
		$result += "."
	}
	$result = $result.substring(0,$result.length -1)
	return $result
}

### FUNCTION: Determine The Subnet Mask Based Upon The Specified Mask Bits
Function Get-SubnetMask-ByLength ([int]$length) {
	If ($length -eq $null -or $length -gt 32 -or $length -lt 0) {
		Write-Error "Function 'Get-SubnetMask-ByLength'...: Invalid Subnet Mask Length Provided. Please Provide A Number BETWEEN 0 And 32"
		Return $null
	}
	switch ($length) {
		"32" {return "255.255.255.255"}
		"31" {return "255.255.255.254"}
		"30" {return "255.255.255.252"}
		"29" {return "255.255.255.248"}
		"28" {return "255.255.255.240"}
		"27" {return "255.255.255.224"}
		"26" {return "255.255.255.192"}
		"25" {return "255.255.255.128"}
		"24" {return "255.255.255.0"}
		"23" {return "255.255.254.0"}
		"22" {return "255.255.252.0"}
		"21" {return "255.255.248.0"}
		"20" {return "255.255.240.0"}
		"19" {return "255.255.224.0"}
		"18" {return "255.255.192.0"}
		"17" {return "255.255.128.0"}
		"16" {return "255.255.0.0"}
		"15" {return "255.254.0.0"}
		"14" {return "255.252.0.0"}
		"13" {return "255.248.0.0"}
		"12" {return "255.240.0.0"}
		"11" {return "255.224.0.0"}
		"10" {return "255.192.0.0"}
		"9" {return "255.128.0.0"}
		"8" {return "255.0.0.0"}
		"7" {return "254.0.0.0"}
		"6" {return "252.0.0.0"}
		"5" {return "248.0.0.0"}
		"4" {return "240.0.0.0"}
		"3" {return "224.0.0.0"}
		"2" {return "192.0.0.0"}
		"1" {return "128.0.0.0"}
		"0" {return "0.0.0.0"}
	}
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ READ-ONLY DOMAIN JOIN THROUGH AN RODC +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 140
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 140) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 140
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
$localComputer = Get-WmiObject -Class Win32_ComputerSystem
$localComputerName = $localComputer.Name
$scriptFileFullPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $scriptFileFullPath
$logFileFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_Read-Only-Domain-Join_" + $localComputerName + ".log")
$rodcNBT = $rodcFQDN.Substring(0,$rodcFQDN.IndexOf("."))
$userName = $adDomain + "\" + $localComputerName + "`$"
$userPassword = $compAccountPWD
$ports = 53,88,135,389,445,464,636,3268,3269,40961	# DNS, Kerberos, RPC Endpoint Mapper, LDAP, SMB, Kerberos Change/Set Password, LDAP-SSL, GC, GC-SSL, Custom RPC Static Port For NetLogon

### Definition Of Some Variables
Set-Variable JOIN_DOMAIN -option Constant -value 1					# Joins a computer to a domain. If this value is not specified, the join is a computer to a workgroup
Set-Variable ACCT_CREATE -option Constant -value 2					# Creates an account on a domain
Set-Variable ACCT_DELETE -option Constant -value 4					# Deletes an account when a domain exists
Set-Variable WIN9X_UPGRADE -option Constant -value 16				# The join operation is part of an upgrade from Windows 98 or Windows 95 to Windows 2000 or Windows NT
Set-Variable DOMAIN_JOIN_IF_JOINED -option Constant -value 32		# Allows a join to a new domain, even if the computer is already joined to a domain
Set-Variable JOIN_UNSECURE -option Constant -value 64				# Performs an unsecured join
Set-Variable MACHINE_PASSWORD_PASSED -option Constant -value 128	# The machine, not the user, password passed. This option is only valid for unsecure joins
Set-Variable DEFERRED_SPN_SET -option Constant -value 256			# Writing SPN and DnsHostName attributes on the computer object should be deferred until the rename that follows the join
Set-Variable NETSETUP_JOIN_READONLY -option Constant -value 2048	# Use an RODC to perform the domain join against
Set-Variable INSTALL_INVOCATION -option Constant -value 262144		# The APIs were invoked during install

### Domain Join Options To Use
$domainJoinOption = $JOIN_DOMAIN + $MACHINE_PASSWORD_PASSED + $NETSETUP_JOIN_READONLY
 
Logging ""
Logging "**********************************************************" "HEADER"
Logging "*                                                        *" "HEADER"
Logging "*     --> Read-Only Domain Join Through An RODC <--      *" "HEADER"
Logging "*                                                        *" "HEADER"
Logging "*      Written By: Jorge de Almeida Pinto [MVP-EMS]      *" "HEADER"
Logging "*                                                        *" "HEADER"
Logging "            BLOG: 'Jorge's Quest For Knowledge'          *" "HEADER"
Logging "       (http://jorgequestforknowledge.wordpress.com/)    *" "HEADER"
Logging "*                                                        *" "HEADER"
Logging "**********************************************************" "HEADER"
Logging ""

### Pre-Requisites Check
Logging ""
Logging "------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "+++ PRE-REQUISITES CHECK +++" "HEADER"

Logging ""
Logging "ATTENTION: To Execute This Script, The Following Pre-Requisites Must Be met:" "WARNING"
Logging " * Local Server Is Configured Correctly With IP Address, Subnet Mask And DNS Servers..." "WARNING"
Logging " * Admin Account Must Be(Direct) Member Of Local 'Administrators' Group!..." "WARNING"
Logging " * If UAC Is Used, Admin Account Must Be Running Within An Elevated Administrator Command Prompt!..." "WARNING"
Logging " * Required Ports Must Be Opened Between This Server And Targeted RODC!..." "WARNING"
Logging ""
Logging "ATTENTION: This Script Will Fail Without The Pre-Requisites Mentioned Above!" "WARNING"
Logging ""
Logging "Press Any Key To Continue...(TWICE)"
Logging ""
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

### Checking For Admin Credentials And If Those Admin Credentials have Been Elevated Due To UAC
If (!(Test-Admin)) {
	Logging ""
	Logging "WARNING:" "ERROR"
	Logging " * Your Admin Account IS NOT A (Direct) Member Of The Local 'Administrators' Group!..." "ERROR"
	Logging " * Your Admin Account IS NOT Running Within An Elevated Administrator Command Prompt!..." "ERROR"
	Logging ""
	Logging "Aborting Script..." "ERROR"
	Logging ""
	EXIT
} Else {
	Logging ""
	Logging "SUCCESS:" "SUCCESS"
	Logging " * Your Admin Account IS A (Direct) Member Of The Local 'Administrators' Group!..." "SUCCESS"
	Logging " * Your Admin Account IS Running Within An Elevated Administrator Command Prompt!..." "SUCCESS"
	Logging ""
	Logging "Continuing Script..." "SUCCESS"
	Logging ""
}

### Checking Connectivity (TCP Only!) Between This Server And The Target RODC
$checkOK = $true
$ports | %{
	$port = $_
	$connectionResult = $null
	$connectionResult = PortConnectionCheck $rodcFQDN $port 500
	If ($connectionResult -eq "SUCCESS") {
		Logging "The RODC '$rodcFQDN' IS Accessible And Listening On Port '$port'..." "SUCCESS"
	}
	If ($connectionResult -eq "ERROR") {
		Logging "The RODC '$rodcFQDN' IS NOT Accessible And Listening On Port '$port'..." "ERROR"
		$checkOK = $false
	}
}
If (!$checkOK) {		
	Logging  ""
	Logging "WARNING:" "ERROR"
	Logging " * One Or More Of The Required Ports IS/ARE NOT Available..." "ERROR"
	Logging ""
	Logging "Aborting Script..." "ERROR"
	Logging ""
	EXIT
} Else {
	Logging  ""
	Logging "SUCCESS:" "SUCCESS"
	Logging " * All The Required Ports ARE Available..." "SUCCESS"
	Logging ""
	Logging "Continuing Script..." "SUCCESS"
	Logging ""
}

### Checking Local Registry Settings For Site Definition
$regNameExistSiteName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SiteName -ErrorAction SilentlyContinue
If ($regNameExistSiteName) {
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SiteName -Force
	Logging ""
	Logging "Registry Value 'SiteName' In 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' Exists..."
	Logging ""
	Logging "Registry Value 'SiteName' Has Been Deleted..."
	Logging ""
}
$regNameExistDynamicSiteName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name DynamicSiteName -ErrorAction SilentlyContinue
If ($regNameExistDynamicSiteName) {
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name DynamicSiteName -Force
	Logging ""
	Logging "Registry Value 'DynamicSiteName' In 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' Exists..."
	Logging ""
	Logging "Registry Value 'DynamicSiteName' Has Been Deleted..."
	Logging ""
}

### Change Preferred Error Action
$ErrorActionPreference = "SilentlyContinue"

### Connecting To AD On The RODC And Getting Some NCs
$rootDSEldapPath = "LDAP://$rodcFQDN/rootDSE"
$directoryEntryrootDSE = New-Object System.DirectoryServices.DirectoryEntry($rootDSEldapPath, $userName, $userPassword)
$defaultNamingContext = $directoryEntryrootDSE.defaultNamingContext
$configurationNamingContext = $directoryEntryrootDSE.configurationNamingContext

### Checking Pre-Created Computer Account Exists And The Correct Password Of The Computer Account Is Being Used
$defaultNCldapPath = "LDAP://$rodcFQDN/$defaultNamingContext"
$defaultNCdirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($defaultNCldapPath, $userName, $userPassword)
$SearcherSRVCompAccount = $null
$SearcherSRVCompAccount = New-Object DirectoryServices.DirectorySearcher($defaultNCdirectoryEntry)
$SearcherSRVCompAccount.SearchScope = "Subtree"
$SearcherSRVCompAccount.Filter = "(&(objectClass=computer)(sAMAccountName=$localComputerName`$))"
$SearcherSRVCompAccountResult = $null
$SearcherSRVCompAccountResult = $SearcherSRVCompAccount.FindOne()
$dnSRVCompAccount = $null
$dnSRVCompAccount = $SearcherSRVCompAccountResult.Properties.distinguishedname
If ($dnSRVCompAccount) {
	Logging  ""
	Logging "SUCCESS:" "SUCCESS"
	Logging " * A Computer Account For This Server DOES Exist...And" "SUCCESS"
	Logging " * A Correct Password Is Being Used..." "SUCCESS"
	Logging ""
	Logging "Continuing Script..." "SUCCESS"
	Logging ""
} Else {
	Logging  ""
	Logging "WARNING:" "ERROR"
	Logging " * A Computer Account For This Server DOES NOT Exist...Or" "ERROR"
	Logging " * An Incorrect Password Is Being Used..." "ERROR"
	Logging ""
	Logging "Aborting Script..." "ERROR"
	Logging ""
	EXIT
}

### Change Preferred Error Action To Default
$ErrorActionPreference = "Continue"

$regNameExistSiteName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SiteName -ErrorAction SilentlyContinue
If ($regNameExistSiteName) {
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SiteName -Force
	Logging ""
	Logging "Registry Value 'SiteName' In 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' Exists..."
	Logging ""
	Logging "Registry Value 'SiteName' Has Been Deleted..."
	Logging ""
}
$regNameExistDynamicSiteName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name DynamicSiteName -ErrorAction SilentlyContinue
If ($regNameExistDynamicSiteName) {
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name DynamicSiteName -Force
	Logging ""
	Logging "Registry Value 'DynamicSiteName' In 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' Exists..."
	Logging ""
	Logging "Registry Value 'DynamicSiteName' Has Been Deleted..."
	Logging ""
}

### Initiating Read-Only Domain Join
Logging ""
Logging "------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "+++ INITIATING READ-ONLY DOMAIN JOIN +++" "HEADER"

### Determining The AD Site Of The Specified/Targeted RODC
$rodcCompAccountldapPath = "LDAP://$rodcFQDN/CN=$rodcNBT,OU=Domain Controllers,$defaultNamingContext"
$rodcCompAccountdirectoryEntry = $null
$rodcCompAccountdirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($rodcCompAccountldapPath, $userName, $userPassword)
$SearcherRodcCompAccount = $null
$SearcherRodcCompAccount = New-Object DirectoryServices.DirectorySearcher($rodcCompAccountdirectoryEntry)
$SearcherRodcCompAccount.SearchScope = "Base"
$SearcherRodcCompAccount.Filter = "(&(objectClass=computer)(dNSHostName=$rodcFQDN))"
$SearcherRodcCompAccount.PropertiesToLoad.Add("msDS-SiteName") | Out-Null
$SearcherRodcCompAccountResult = $null
$SearcherRodcCompAccountResult = $SearcherRodcCompAccount.FindOne()
$rodcADSite = $null
[string]$rodcADSite = $SearcherRodcCompAccountResult.Properties."msds-sitename"

### Matching The IP Address Of The Local Server Against An AD Site In The AD Forest
$subnetsContainerldapPath = "LDAP://$rodcFQDN/CN=Subnets,CN=Sites,$configurationNamingContext"
$subnetsContainerdirectoryEntry = $null
$subnetsContainerdirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($subnetsContainerldapPath, $userName, $userPassword)
$searcherSubnets = $null
$searcherSubnets = New-Object DirectoryServices.DirectorySearcher($subnetsContainerdirectoryEntry)
$searcherSubnets.SearchScope = "Subtree"
$searcherSubnets.PropertiesToLoad.Add("name") | Out-Null
$searcherSubnets.PropertiesToLoad.Add("siteObject") | Out-Null
# We Can Take Network Masks In Both Length And Full Octet Format
# We Need To Use Both. LDAP Searches
# Use Length, And Network ID Generation Is By Full Octet Format.
$startMaskLength = 32                     
For ($i = $startMaskLength; $i -ge 0; $i--) {
	# Loop Through Netmasks From /32 To /0 Looking For A Subnet Match In AD
	# Go Through All Masks From Longest To Shortest
	$subnetMask = &Get-SubnetMask-ByLength $i
	$networkID = &Get-NetworkID $ipAddressLocalHost $subnetMask
	   
	# LDAP Search For The Network
	$searcherSubnets.filter = "(&(objectClass=subnet)(objectCategory=subnet)(cn=" + $networkID + "/" + $i + "))"
	$subnetObjectResult = $null
	$subnetObjectResult = $searcherSubnets.FindOne()
	#$subnetObjectsList = $searcherSubnets.FindAll()
	#$subnetsTable = @()
	#$subnetObjectsList.Properties | %{
	#	$subnetsTableObj = "" | Select "AD Subnet","AD Site"
	#	$subnetsTableObj."AD Subnet" = ($_.name)[0]
	#	$subnetsTableObj."AD Site" = $(($_.siteobject)[0]).Substring(3,$(($_.siteobject)[0]).IndexOf(",")-3)
	#	$subnetsTable += $subnetsTableObj
	#}
	#$subnetsTable | FT -Autosize
	If ($subnetObjectResult -ne $null) {
		# If A Match Is Found, Return It Since It Is The Longest Length (Closest Match)
		$localComputerADSubnet = $null
		[string]$localComputerADSubnet = $($subnetObjectResult.Properties.name)
		$localComputerADSite = $null
		[string]$localComputerADSite = $($subnetObjectResult.Properties.siteobject).Substring(3,$($subnetObjectResult.Properties.siteobject).IndexOf(",")-3)
		#return $localComputerADSite
		Break
	}
	$subnetObjectResult = $null
	[string]$localComputerADSubnet = $null
	[string]$localComputerADSite = $null
}

If ($localComputerADSubnet -eq $null -Or $localComputerADSite -eq $null) {
	[string]$localComputerADSubnet = "NO_MATCH_FOUND"
	[string]$localComputerADSite = "NO_MATCH_FOUND"
}

### Present The Information
Logging ""
Logging "Trying To Join The Local Computer '$localComputerName' To The AD Domain '$adDomain' Using The RODC '$rodcFQDN'..."
Logging ""
Logging "FQDN AD Domain............: $adDomain"
Logging "FQDN RODC.................: $rodcFQDN"
Logging "AD Site RODC..............: $rodcADSite"
Logging "AD Site Local Computer....: $localComputerADSite"
Logging "Matching AD Subnet........: $localComputerADSubnet"
Logging "Local Computer Name.......: $localComputerName ($localComputerName`$)"
Logging "Distinguished Name........: $dnSRVCompAccount"
Logging "Computer Account Password.: $compAccountPWD"
Logging ""

### AD Sites Must Match, Otherwise Something Is Wrong
If ($rodcADSite.ToUpper() -ne $localComputerADSite.ToUpper() -Or $localComputerADSite -eq "NO_MATCH_FOUND") {
	Logging ""
	Logging "WARNING:" "ERROR"
	Logging " * The AD Site Of The Local Computer DOES NOT Match The AD Site Of The Specified RODC..." "ERROR"
	Logging " * Make Sure The IP Address Of The Local Server Is Configured Correctly So That It Will Match Against The Same AD Site As The Targeteed RODC..." "ERROR"
	Logging " * The Cause Of The Mismatch Can Be:" "ERROR"
	Logging "   * The Specified IP Address IS NOT Correct..." "ERROR"
	Logging "   * The Specified RODC IS NOT Correct..." "ERROR"
	Logging "   * The AD Subnet For The Local Computer Is Linked To The Incorrect AD Site..." "ERROR"
	Logging ""
	Logging "Aborting Script..." "ERROR"
	Logging ""
	EXIT
}

### Joining The Local Computer To The AD Domain Using The Specified Domain Join Options
$returnErrorCode = $localComputer.JoinDomainOrWorkGroup($adDomain + "\" + $rodcFQDN, $compAccountPWD, $null, $null, $domainJoinOption)
# List of 'system error codes' (http://msdn.microsoft.com/en-us/library/ms681381.aspx) and 
# List of 'network management error codes' (http://msdn.microsoft.com/en-us/library/aa370674(VS.85).aspx)
$returnErrorDescription = switch ($($returnErrorCode.ReturnValue)) {
	0 {"SUCCESS: The Operation Completed Successfully."} 
	5 {"FAILURE: Access Is Denied."} 
	53 {"FAILURE: The Network Path Was Not Found."}
	64 {"FAILURE: The Specified Network Name Is No Longer Available."}
	87 {"FAILURE: The Parameter Is Incorrect."} 
	1219 {"FAILURE: Logon Failure: Multiple Credentials In Use For Target Server."}
	1326 {"FAILURE: Logon Failure: Unknown Username Or Bad Password."} 
	1355 {"FAILURE: The Specified Domain Either Does Not Exist Or Could Not Be Contacted."} 
	2691 {"FAILURE: The Machine Is Already Joined To The Domain."} 
	default {"FAILURE: Unknown Error!"}
}

If ($($returnErrorCode.ReturnValue) -eq "0") {
	Logging "Domain Join Result Code...: $($returnErrorCode.ReturnValue)" "SUCCESS"
	Logging "Domain Join Result Text...: $returnErrorDescription" "SUCCESS"
} Else {
	Logging "Domain Join Result Code...: $($returnErrorCode.ReturnValue)" "ERROR"
	Logging "Domain Join Result Text...: $returnErrorDescription" "ERROR"
}

If ($($returnErrorCode.ReturnValue) -eq "0") {
	Logging ""
	Logging "REMARK:" "REMARK"
	Logging " * The Computer Account Password Will Be Changed Shortly After The Domain Join!" "REMARK"
	Logging ""
	Logging "!!! THE COMPUTER WILL REBOOT AUTOMATICALLY IN 2 MINUTES !!!" "REMARK"
	Logging ""
	Logging "!!! TO STOP THE REBOOT USE THE COMMAND: SHUTDOWN /A !!!" "REMARK"
	SHUTDOWN /R /T 120
}
Logging ""
Logging "+++ FINISHED +++" "HEADER"
Logging "------------------------------------------------------------------------------------------------------------------" "HEADER"