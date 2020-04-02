### Abstract: This PoSH Script Tests Connectivity To Specified Servers For Specified Ports
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2017-09-15: Initial version of the script (v0.1)
### 2019-10-04: Fixed some minor bugs (v0.2)
###

<#
.SYNOPSIS
	This PoSH Script Tests Connectivity To Specified Servers For Specified Ports.

.DESCRIPTION
	This PoSH Script Tests Connectivity To Specified Servers For Specified Ports.
	One server or multiple servers can be specified.
	One port, multiple ports or a range of ports can be specified
	It is also port to use a pre-defined template of ports

	TCP:22			SSH
	TCP:53			DNS
	TCP:80			HTTP
	TCP:88			Kerberos
	TCP:135			RPC Endpoint mapper
	TCP:280			HP SIM
	TCP:389			LDAP
	TCP:443			HTTPS
	TCP:445			SMB
	TCP:464			Kerberos Change/Set Password
	TCP:636			LDAP-S
	TCP:1025-5000	RPC Dynamic Port Range (Legacy)
	TCP:1688		Windows Activation
	TCP:2301		HP SIM
	TCP:2381		HP SIM
	TCP:3268		GC
	TCP:3269		GC-S
	TCP:3389		RDP
	TCP:5722		RPC DFSR
	TCP:5723		SCOM
	TCP:5985		Windows Remote Management
	TCP:8014		SEP
	TCP:8530		SCCM
	TCP:8531		SCCM
	TCP:40960		AD Replication (Custom)
	TCP:40961		NetLogon (Custom)
	TCP:40962		DFS Replication (Custom)
	TCP:49152-65535	RPC Dynamic Port Range

	UDP:53			DNS
	UDP:67			DHCP
	UDP:123			NTP
	UDP:161			HP SIM
	UDP:162			HP SIM
	UDP:389			LDAP
	UDP:464			Kerberos Change/Set Password

.EXAMPLE
	Test ports connectivity against servers "SERVER1.COMPANY.COM" and "SERVER2.COMPANY.COM" for ports 80,443,5000-5010
	
	Port-Test.ps1 -servers "SERVER1.COMPANY.COM","SERVER2.COMPANY.COM" -ports 80,443,"5000-5010"
	
.EXAMPLE
	Test ports connectivity against servers "SERVER1.COMPANY.COM" and "SERVER2.COMPANY.COM" for port template MemberToDC
	
	Port-Test.ps1 -servers "SERVER1.COMPANY.COM","SERVER2.COMPANY.COM" -portTemplate MembersToDCDefault

.NOTES
	This script does not require any special permissions.
	It can only check for TCP ports, not UDP ports and the latter are connectionless.
	When specifying a range of ports, make sure to enclose it with quotes!
#>

Param(
    [Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
			HelpMessage='Please specify one or a list of servers (command separated).')]
    [ValidateNotNullOrEmpty()]
	[string[]]$servers,

    [Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
			HelpMessage='Please specify one or a list of ports (command separated).')]
	[string[]]$ports,
	
    [Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
			HelpMessage='Please specify one port template.')]
	[ValidateSet("RODCtoRWDCCustom", "RODCtoRWDCDefault", "RWDCtoRODCCustom", "RWDCtoRODCDefault", "MembersToDCCustom", "MembersToDCDefault", "MembersToDCLegacy", "MembersToDCMixed", "WindowsActivation", "WindowsRemote", "SCCM", "SCOM", "SEP", "HPSIM")]
	[string]$portTemplate
)

### FUNCTION: Test The Port Connection
Function PortConnectionCheck($fqdnServer,$port,$timeOut) {
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer,$port,$null,$null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
	$connectionResult = $null
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		$connectionResult = "ERROR"
	} Else {
		#$error.Clear()
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			$connectionResult = "ERROR"
		} Else {
			$connectionResult = "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
	
	If ($connectionResult -eq "SUCCESS") {
		Write-Host "Server: '$fqdnServer' | Port: '$port' | Reachable/Listening!..." -ForeGroundColor Green
	}
	If ($connectionResult -eq "ERROR") {
		Write-Host "Server: '$fqdnServer' | Port: '$port' | NOT Reachable/Listening!..." -ForeGroundColor Red
	}
}

### Port Templates
If ($ports -eq $null -And $portTemplate -eq "RODCtoRWDCCustom") {
	$ports = "53","88","135","389","445","464","636","3268-3269","5722","40960-40962"
}
If ($ports -eq $null -And $portTemplate -eq "RODCtoRWDCDefault") {
	$ports = "53","88","135","389","445","464","636","3268-3269","5722","49152-65535"
}
If ($ports -eq $null -And $portTemplate -eq "RWDCtoRODCCustom") {
	$ports = "135","445","40960"
}
If ($ports -eq $null -And $portTemplate -eq "RWDCtoRODCDefault") {
	$ports = "135","49152-65535"
}
If ($ports -eq $null -And $portTemplate -eq "MemberstoDCCustom") {
	$ports = "53","88","135","389","445","464","636","3268-3269","40960-40962"
}
If ($ports -eq $null -And $portTemplate -eq "MemberstoDCDefault") {
	$ports = "53","88","135","389","445","464","636","3268-3269","49152-65535"
}
If ($ports -eq $null -And $portTemplate -eq "MemberstoDCLegacy") {
	$ports = "53","88","135","389","445","464","636","1025-5000","3268-3269"
}
If ($ports -eq $null -And $portTemplate -eq "MemberstoDCMixed") {
	$ports = "53","88","135","389","445","464","636","1025-5000","3268-3269","49152-65535"
}
If ($ports -eq $null -And $portTemplate -eq "WindowsActivation") {
	$ports = "1688"
}
If ($ports -eq $null -And $portTemplate -eq "WindowsRemote") {
	$ports = "5985","3389"
}
If ($ports -eq $null -And $portTemplate -eq "SCCM") {
	$ports = "80","8530-8531"
}
If ($ports -eq $null -And $portTemplate -eq "SCOM") {
	$ports = "5723"
}
If ($ports -eq $null -And $portTemplate -eq "SEP") {
	$ports = "80","8014"
}
If ($ports -eq $null -And $portTemplate -eq "HPSIM") {
	$ports = "22","280","2301","2381"
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ TESTING TCP PORTS AGAINST SERVERS +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 400
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

Write-Host ""
Write-Host "**********************************************************" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "*       --> Testing TCP Ports Against Servers <--        *" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "*      Written By: Jorge de Almeida Pinto [MVP-EMS]      *" -ForeGroundColor Cyan
Write-Host "*                                                        *" -ForeGroundColor Cyan
Write-Host "**********************************************************" -ForeGroundColor Cyan
Write-Host ""

### Definition Of Some Constants
$execDateTime = Get-Date
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
$fqdnDomainName = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$fqdnLocalComputer = $localComputerName + "." + $fqdnDomainName
$scriptFullPath = $MyInvocation.MyCommand.Definition
$cmdLineUsed = $MyInvocation.Line

Write-Host ""
Write-Host "Execution Date/Time......................: $execDateTime"
Write-Host "Local Computer FQDN......................: $fqdnLocalComputer"
Write-Host ""
Write-Host "Script Full Path.........................: $scriptFullPath"
Write-Host "Script Command Line Used.................: $cmdLineUsed"
Write-Host ""
If ($servers) {
	$srv = 1
	$servers | %{
		Write-Host "Server ($srv)...............................: '$($_.ToUpper())'"
		$srv += 1
	}
}
If ($ports) {
	$prt = 1
	$ports | %{
		Write-Host "Port ($prt).................................: '$($_.ToUpper())'"
		$prt += 1
	}
}
Write-Host ""
Write-Host ""

$servers | %{
	$server = $_
	$ports | %{
		$port = $null
		$portStart = $null
		$portEnd = $null
		$portTarget = $null
		$port = $_
		If ($port.contains("-")) {
			$portStart = $port.Substring(0,$port.IndexOf("-"))
			$portEnd = $port.Substring($port.IndexOf("-") + 1)
			
			$portStart..$portEnd | %{
				$portTarget = $_
				PortConnectionCheck $server $portTarget 500
				Write-Host ""
			}
			
		} Else {
			$portTarget = $port
			PortConnectionCheck $server $portTarget 500
			Write-Host ""
		}
	}
}

Write-Host ""
Write-Host "WARNING: Remember That You May Also Need To Have UDP Ports Open, Which CANNOT BE Tested With This Script!!!" -ForeGroundColor Yellow
Write-Host ""