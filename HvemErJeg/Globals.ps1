#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$Global:NetworkCategory_Private_Found 	= $False
$Global:NetworkCategory_Public_Found 	= $False
$Global:NetworkCategory_Domain_Found 	= $False
$Global:IsOnVPN 						= $False
$Global:VpnIpAdress 					= ""
$Global:VpnNetProfileName 				= ""
$Global:Page_user 						= 1

$Global:UserAdInfo						= New-Object System.Data.DataTable

$Global:Debug = $False
$Global:FoundInstalledSw = ""
$Global:FoundReliabilityRecords = ""
$Global:FoundPnpDevices = ""
$Global:FoundMachineHwTable = ""
#$Global:FoundUserGroupList = ""
$InstalledSoftwareBlock
#$Global:NetworkInfoList = ""



#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory



#  -----------------    Domain related functions  ---------------------------------------

function GetAdsiPathForCurrentDomain
{
	$Root 				= [ADSI]"LDAP://RootDSE"
	$GetAdsiPathStr 	= 'LDAP://' + $Root.rootDomainNamingContext
	return $GetAdsiPathStr
}

Function GetNameFromADSPath
{
	param (
		[Parameter(Mandatory = $true)]
		[String[]]$ADSPathString
	)
	$NameToReturn 				= ""
	$AdsSearcher 				= [adsisearcher]"(&(objectCategory=Group)(objectClass=Group)(distinguishedName=$ADSPathString))"
	$AdsSearcher.PropertiesToLoad.AddRange(('name'))
	#$AdsSearcher.searchRoot    =   [ADSI]$AdsiPathForDomain
	$AdsSearcherList 			= $AdsSearcher.FindAll()
	foreach ($AdsSearcherItem in $AdsSearcherList)
	{
		$NameToReturn 			= $AdsSearcherItem.Properties.name
	}
	Return $NameToReturn
}

Function ConvertTo-Date
{
	Param (
		[Parameter(ValueFromPipeline = $true, mandatory = $true)]
		$AdDateTimeVal
	)
	
	process
	{
		$lngValue = $AdDateTimeVal
		if (($lngValue -eq 0) -or ($lngValue -gt [DateTime]::MaxValue.Ticks))
		{
			$ReadableDate = "<Never>"
		}
		else
		{
			$Date = [DateTime]$lngValue
			$ReadableDate = $Date.AddYears(1600).ToLocalTime()
		}
		$ReadableDate
	}
}

function GetLdapPath
{
	param (
		[String[]]$ObjectType,
		[String[]]$ObjectName,
		[String[]]$AdsiPathString)
	
	If ($AdsiPathString -eq $null)
	{ $AdsiPathString = GetAdsiPathForCurrentDomain }
	
	Switch ($ObjectType)
	{
		"Machine"   { $AdsiSearcher = [adsisearcher]"(&(objectCategory=computer)(cn=$ObjectName))" }
		"User"      { $AdsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$ObjectName))" }
		"Group"     { $AdsiSearcher = [adsisearcher]"(&(objectCategory=Group)(objectClass=Group)(cn=$ObjectName))" }
	}
	
	$AdsiSearcher.searchRoot = [ADSI]$AdsiPathString[0]
	$AdsiSearchList = $AdsiSearcher.FindAll()
	foreach ($ObjItem in $AdsiSearchList)
	{
		$FoundLdapPathStr = $ObjItem.path
		
	}
	Return $FoundLdapPathStr
}

function GetLdapFromDomainShortName
{
	param (
		[string]$DomainShortnameToFind
	)
	$DomainArray = @()
	$CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$DomainArray += $CurrentDomain
	
	$TrustedDomainsList = $CurrentDomain.GetAllTrustRelationships()
	foreach ($TrustedDomain in $TrustedDomainsList)
	{
		$DomainArray += $TrustedDomain.Targetname
	}
	
	$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$TrustedForestList = $Forest.GetAllTrustRelationships()
	foreach ($TrustedForest in $TrustedForestList)
	{
		$DomainArray += $TrustedForest.Targetname
	}
	
	foreach ($DomainItems in $DomainArray)
	{
		if ($DomainItems -like "*$DomainShortnameToFind*")
		{
			[String]$DomainName = $DomainItems.tostring()
			$LdapStr = "LDAP://"
			$DomainNameParts = $DomainName -split '\.'
			foreach ($DomainNamePart in $DomainNameParts)
			{
				$LdapStr = $LdapStr + "DC=$DomainNamePart,"
			}
			$LdapStr = $LdapStr.Substring(0, $LdapStr.length - 1)
			break
		}
	}
	
	Return $LdapStr
}

function Get-ForetakFromLdap
{
	param
	(
		[parameter(Mandatory = $true)]
		[String]$LdapString
	)
	$LdapString = $LdapString -replace 'LDAP://,', ''
	
	$Warning = ""
	$FoundForetak = "Unknown"
	
	switch -wildcard ($LdapString)
	{
		"*OU=Maskiner*"				{ $ObjType = "Machine" }
		"*OU=Brukere*"				{ $ObjType = "User" }
		"*OU=Maskiner Staging*"		{ $Warning = "Staging" }
		"*OU=OUS,DC=ad*"			{ $FoundForetak = "OUS" }
		"*DC=ahus*"					{ $FoundForetak = "Ahus" }
		"*OU=Pilot og Test*"		{ $FoundForetak = "Pilot" }
		Default 					{ $Warning = " " }
	}
	
	If (($Warning -eq "") -and ($FoundForetak -eq "Unknown"))
	{
		$OuArray = $LdapString -split ','
		$ArrayCount = 1
		
		if ($ObjType -eq "Machine")
		{
			foreach ($OuItem in $OuArray)
			{
				if ($OuItem -eq 'OU=Foretak') { $FoundForetak = $($OuArray[$ArrayCount - 2]).replace("OU=", "") }
				$ArrayCount++
			}
		}
		
		if ($ObjType -eq "User")
		{
			foreach ($OuItem in $OuArray)
			{
				if ($OuItem -eq 'OU=MIIS') { $FoundForetak = $($OuArray[$ArrayCount - 2]).replace("OU=", "") }
				$ArrayCount++
			}
		}	
	}
	
	return "$Warning $FoundForetak".Trim()
}

Function GetAdSubnetInfo
{
	[CmdletBinding()]
	param (
		[Parameter()]
		[IPAddress]$Ip4Adress
	)
	
	$FoundAdNetId = ""
	$sitesDN = "LDAP://CN=Sites," + $([adsi] "LDAP://RootDSE").Get("ConfigurationNamingContext")
	$subnetsDN = "LDAP://CN=Subnets,CN=Sites," + $([adsi] "LDAP://RootDSE").Get("ConfigurationNamingContext")
	
	foreach ($subnet in $([adsi]$subnetsDN).psbase.children)
	{
		$CurrNetAdr = ([IPAddress](($subnet.cn -split "/")[0]))
		$CurrAdSn = ([IPAddress]"$([system.convert]::ToInt64(("1" * [int](($subnet.cn -split "/")[1])).PadRight(32, "0"), 2))")
		if ((([IPAddress]$Ip4Adress).Address -band ([IPAddress]$CurrAdSn).Address) -eq ([IPAddress]$CurrNetAdr).Address)
		{
			$FoundAdNetId = $($subnet.cn)
			
			$site = [adsi] "LDAP://$($subnet.siteObject)"
			if ($site.cn -ne $null)
			{
				$siteName = ([string]$site.cn).toUpper()
			}
			
			$SubNetDescription = $subnet.description[0]
			$SubNetLocation = $subnet.Location[0]
			$AdSiteForAdress = @{
				ip = "$Ip4Adress"
				sn = "$CurrAdSn"
				AdCidr = "$FoundAdNetId"
				AdSiteName = "$siteName"
				SubNetDescription = "$SubNetDescription"
				SubNetLocation = "$SubNetLocation"
				Isfound = $True
			}
			Break
			
		}
	}
	if ($FoundAdNetId -eq "")
	{
		$AdSiteForAdress = @{
			ip = "$Ip4Adress"
			sn = ""
			AdCidr = ""
			AdSiteName = ""
			SubNetDescription = ""
			SubNetLocation = ""
			Isfound = $False
		}
	}
	
	$FoundAdNetIdObject = [pscustomobject]$AdSiteForAdress
	Return $FoundAdNetIdObject
	
}


#  -----------------    Functions to return collected info  ---------------------------------------

function Get-UserinfoFromDomain
# Returns table with userinfo from AD
{
	param
	(
		[parameter(Mandatory = $true)]
		[String]$UsernameToFind,
		[parameter(Mandatory = $true)]
		[String]$LdapSearchRoot
	)
	
	$IsObjectFound = $false
	
	$ResultTable = New-Object System.Data.DataTable
	$col1 = New-Object System.Data.DataColumn("Beskrivelse")
	$col2 = New-Object System.Data.DataColumn("Innhold")
	$ResultTable.columns.Add($col1)
	$ResultTable.columns.Add($col2)
	
	$AdsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$UsernameToFind))"
	#$AdsiSearcher.PropertiesToLoad.AddRange(('name'))
	$AdsiSearcher.searchRoot = [ADSI]$LdapSearchRoot
	$AdsiSearchList = $AdsiSearcher.FindAll()
	
	ForEach ($AdsiSearchItem in $AdsiSearchList)
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Login ID"
		$row["Innhold"] = $($AdsiSearchItem.properties.samaccountname)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Navn"
		$row["Innhold"] = $($AdsiSearchItem.properties.name)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Unikt Navn"
		$row["Innhold"] = $($AdsiSearchItem.properties.cn)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Visningsnavn"
		$row["Innhold"] = $($AdsiSearchItem.properties.displayname)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Ansattnummer"
		$row["Innhold"] = $($AdsiSearchItem.properties.employeeid)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Foretak"
		$row["Innhold"] = $($AdsiSearchItem.properties.company)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Avdeling"
		$row["Innhold"] = $($AdsiSearchItem.properties.department)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Tittel"
		$row["Innhold"] = $($AdsiSearchItem.properties.title)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Rapporterer til:"
		$row["Innhold"] = $($AdsiSearchItem.properties.manager -split ",")[0] -replace "CN=", ""
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "E-Mail"
		$row["Innhold"] = $($AdsiSearchItem.properties.mail)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Hjemmekatalog"
		$row["Innhold"] = $($AdsiSearchItem.properties.homedirectory)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Hjemmedisk"
		$row["Innhold"] = $($AdsiSearchItem.properties.homedrive)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Siste login"
		$row["Innhold"] = ConvertTo-Date $AdsiSearchItem.Properties.Item("lastLogon")[0]
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Konto utløper"
		$row["Innhold"] = ConvertTo-Date $AdsiSearchItem.Properties.Item("accountexpires")[0]
		$ResultTable.rows.Add($row)
	}
	$ExportTable = New-Object System.Data.DataTable
	$ExportTable = $ResultTable
	Return, $ExportTable
}


function DetectCurrentNetwork
{
	$Global:NetworkCategory_Private_Found = $false
	$Global:NetworkCategory_Public_Found = $false
	$Global:NetworkCategory_Domain_Found = $false
	$Global:VpnIpAdress = ""
	$Global:VpnNetProfileName = ""
	$Global:IsOnVPN = $False
	$Global:DnsList = @()
	#$Global:PublicIp = ""
	$NetProfilesList = Get-NetConnectionProfile
	$NetIpConfigurationList = Get-NetIPConfiguration
	foreach ($NetProfileItem in $NetProfilesList)
	{
		switch ($($NetProfileItem.NetworkCategory))
		{
			"Private"                { $Global:NetworkCategory_Private_Found = $true }
			"Public"                 { $Global:NetworkCategory_Public_Found = $true }
			"DomainAuthenticated"    { $Global:NetworkCategory_Domain_Found = $true }
		}
		
		if ((($NetProfileItem.NetworkCategory -eq 'Private') -or ($NetProfileItem.NetworkCategory -eq 'Public')) -and (($NetProfileItem.IPv4Connectivity -eq 'LocalNetwork') -or ($NetProfileItem.IPv4Connectivity -eq 'Internet')))
		{
			#	$Global:PublicIp = (Invoke-WebRequest ifconfig.me/ip -UseBasicParsing).Content.Trim()
			
		}
		
		if ($NetProfileItem.NetworkCategory -eq 'DomainAuthenticated')
		{
			#	$Global:VpnIpAdress = $(Get-NetIPAddress -InterfaceAlias $($NetProfileItem.InterfaceAlias) -AddressFamily IPv4).IPv4Address
			$Global:VpnNetProfileName = $(Get-NetIPConfiguration -AllCompartments -InterfaceAlias $($NetProfileItem.InterfaceAlias)).NetProfile.Name
			
			foreach ($NetIPConfigurationItem in $NetIPConfigurationList)
			{
				if ($NetIPConfigurationItem.InterfaceAlias -eq $NetProfileItem.InterfaceAlias)
				{
					#		$Global:VpnNetProfileName = $($NetIPConfigurationItem.InterfaceAlias).NetProfile.Name
					$Global:VpnIpAdress = $($NetIPConfigurationItem.IPv4Address).IPv4Address
					$Global:VpnGW = $($NetIPConfigurationItem.IPv4DefaultGateway).NextHop
					
					foreach ($FoundDnsItemList in Get-DnsClientServerAddress -InterfaceAlias $NetProfileItem.InterfaceAlias)
					{
						foreach ($FoundDnsItem in $FoundDnsItemList.ServerAddresses)
						{
							$Global:DnsList += $($FoundDnsItem)
						}
					}
					
					
				}
			}
		}
	}
	
	if (($Global:NetworkCategory_Private_Found -or $Global:NetworkCategory_Public_Found) -and $Global:NetworkCategory_Domain_Found)
	{
		$Global:IsOnVPN = $true
	}
	
}

function Get-WifiNetworks
{
	$networks = netsh wlan sh net mode=bssid | % {
		if ($_ -match '^SSID (\d+) : (.*)$')
		{
			$current = @{
				Index = $matches[1].trim()
				SSID  = $matches[2].trim()
			}
			$current
		}
		else
		{
			if ($_ -match '^\s+(.*)\s+:\s+(.*)\s*$')
			{
				$current[$matches[1].trim()] = $matches[2].trim()
			}
		}
	}
	$networks | % { [pscustomobject]$_ }
}


Function GetNetCOnnectionType
{
	#Get Connection Type
	$Global:WirelessConnected = $null
	$Global:WiredConnected = $null
	#$Global:VPNConnected = $null
	
	# Detecting PowerShell version, and call the best cmdlets
	if ($PSVersionTable.PSVersion.Major -gt 2)
	{
		# Using Get-CimInstance for PowerShell version 3.0 and higher
		$WirelessAdapters = Get-CimInstance -Namespace "root\WMI" -Class MSNdis_PhysicalMediumType -Filter 'NdisPhysicalMediumType = 9'
		$WiredAdapters = Get-CimInstance -Namespace "root\WMI" -Class MSNdis_PhysicalMediumType -Filter "NdisPhysicalMediumType = 0 and `
            (NOT InstanceName like '%pangp%') and `
            (NOT InstanceName like '%cisco%') and `
            (NOT InstanceName like '%juniper%') and `
            (NOT InstanceName like '%vpn%') and `
            (NOT InstanceName like 'Hyper-V%') and `
            (NOT InstanceName like 'VMware%') and `
            (NOT InstanceName like 'VirtualBox Host-Only%')"
		$ConnectedAdapters = Get-CimInstance -Class win32_NetworkAdapter -Filter `
											 'NetConnectionStatus = 2'
		$VPNAdapters = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter `
									   "Description like '%pangp%' `
            or Description like '%cisco%'  `
            or Description like '%juniper%' `
            or Description like '%vpn%'"
	}
	else
	{
		# Needed this script to work on PowerShell 2.0 (don't ask)
		$WirelessAdapters = Get-WmiObject -Namespace "root\WMI" -Class MSNdis_PhysicalMediumType -Filter `
										  'NdisPhysicalMediumType = 9'
		$WiredAdapters = Get-WmiObject -Namespace "root\WMI" -Class MSNdis_PhysicalMediumType -Filter `
									   "NdisPhysicalMediumType = 0 and `
            (NOT InstanceName like '%pangp%') and `
            (NOT InstanceName like '%cisco%') and `
            (NOT InstanceName like '%juniper%') and `
            (NOT InstanceName like '%vpn%') and `
            (NOT InstanceName like 'Hyper-V%') and `
            (NOT InstanceName like 'VMware%') and `
            (NOT InstanceName like 'VirtualBox Host-Only%')"
		$ConnectedAdapters = Get-WmiObject -Class win32_NetworkAdapter -Filter `
										   'NetConnectionStatus = 2'
		$VPNAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter `
									 "Description like '%pangp%' `
            or Description like '%cisco%'  `
            or Description like '%juniper%' `
            or Description like '%vpn%'"
	}
	
	Foreach ($Adapter in $ConnectedAdapters)
	{
		If ($WirelessAdapters.InstanceName -contains $Adapter.Name)
		{
			$Global:WirelessConnected = $true
		}
	}
	
	Foreach ($Adapter in $ConnectedAdapters)
	{
		If ($WiredAdapters.InstanceName -contains $Adapter.Name)
		{
			$Global:WiredConnected = $true
		}
	}
	
	If (($Global:WirelessConnected -ne $true) -and ($Global:WiredConnected -eq $true)) { $ConnectionType = "Kabel" }
	If (($Global:WirelessConnected -eq $true) -and ($Global:WiredConnected -eq $true)) { $ConnectionType = "Kabel og Trådløs" }
	If (($Global:WirelessConnected -eq $true) -and ($Global:WiredConnected -ne $true)) { $ConnectionType = "Trådløs" }
	
	return $ConnectionType
}


function SetGlobalVariables_User
{
	$Global:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	$Global:UserName = $Global:CurrentUser.split("\")[1]
	$Global:UserDomainShort = $Global:CurrentUser.split("\")[0]
	if ($Global:AdReachAble)
	{
		$Global:UserDomainLdap = GetLdapFromDomainShortName $Global:UserDomainShort
		$Global:UserLdap = GetLdapPath -ObjectType "User" -ObjectName $Global:UserName -AdsiPathString $Global:UserDomainLdap
		$Global:UserForetak = Get-ForetakFromLdap $Global:UserLdap
	}
}

function SetGlobalVariables_Machine
{
	$Global:MachineName = (Get-WmiObject Win32_ComputerSystem).Name
	$Global:MachineDomainFQDN = (Get-WmiObject Win32_ComputerSystem).Domain
	if ($Global:AdReachAble)
	{
		$Global:MachineDomainShort = ([ADSI]"LDAP://$Global:MachineDomainFQDN").dc
		$Global:MachineDomainLdap = GetLdapFromDomainShortName $Global:MachineDomainShort
		$Global:MachineLdap = GetLdapPath -ObjectType "Machine" -ObjectName $Global:MachineName -AdsiPathString $Global:MachineDomainLdap
		$Global:MachineForetak = Get-ForetakFromLdap $Global:MachineLdap
	}	
}

#  -----------------    Functions to update GUI  ---------------------------------------

function UpdateStartInfo
{
	Get-Job | Remove-Job
	
	[System.Windows.Forms.Application]::DoEvents()

if (Test-ComputerSecureChannel)
	{
		$Global:AdReachAble = $True		
	}
	else
	{
		$Global:AdReachAble = $False
		
		# Hide UserTabPage
		$Global:savedTab1 = $tabcontrol1.TabPages[$tabpage_UserInf]
		$tabcontrol1.TabPages.Remove($tabpage_UserInf)
		#$tabcontrol1.TabPages.Add($Global:savedTab1)
		
		$btn_Machine_GroupList.Visible = $False		
	}
	
	# User
	$StatusLabel.text = "Starter innhenting av info -> Bruker"
	SetGlobalVariables_User
	$labelUserId.Text = $Global:UserName
	$labelUserDomain.Text = $Global:UserDomainShort
	$labelUsrForetak.Text = $Global:UserForetak
	
	# Machine
	$StatusLabel.text = "Starter innhenting av info -> Maskin"
	SetGlobalVariables_Machine
	$labelMachineName.Text = $Global:MachineName
	#$labelMachineDomain.text = $Global:MachineDomainShort
	$labelMachineDomain.text = $Global:MachineDomainFQDN
	$labelMachineForetak.Text = $Global:MachineForetak
	
	[System.Windows.Forms.Application]::DoEvents()
	$StatusLabel.text = "Starter innhenting av info -> Sjekker AD-Forbindelse"
	if ($Global:AdReachAble)
	{
		$labelAdConn.Text = "OK"
		$Global:UserAdInfo = Get-UserinfoFromDomain -UsernameToFind $Global:UserName -LdapSearchRoot $Global:UserDomainLdap
		$UsersFullNameLabel.Text = ($Global:UserAdInfo | Where-Object { $_.Beskrivelse -eq "navn" }).Innhold
		$labelMachineDomain.text = $Global:MachineDomainShort
		$labelMachineForetak.Text = $Global:MachineForetak
	}
	else
	{
		$labelAdConn.Text = "Nei"		
		$labelMachineDomain.text = $Global:MachineDomainFQDN
		$labelMachineForetak.Text = "Mangler forbindelse"
	}
	[System.Windows.Forms.Application]::DoEvents()
	StartBackgroundJobs2
	
	#   ***************    Network   ************
	$StatusLabel.text = "Starter innhenting av info -> Detekterer nettverk"
	
	[System.Windows.Forms.Application]::DoEvents()
	DetectCurrentNetwork
	
	if ($Global:IsOnVPN)
	{ $VpnStatusLabel.Text = $Global:VpnNetProfileName }
	else
	{ $VpnStatusLabel.Text = 'Nei' }
	
	$Global:NetTypeStatus = GetNetCOnnectionType
	
	if ($Global:WirelessConnected)
	{
		$ActiveSSID = netsh wlan show interfaces | select-string SSID
		$Global:ActiveSSIDName = $($ActiveSSID[0] -split ":")[1].Trim()
		
		$NetTypeLabel.Text = "$Global:NetTypeStatus $Global:ActiveSSIDName"
		
		
		$WiFiTrackbar.visible = $True
		$WiFigroupbox.visible = $True
		
	}
	else
	{
		$NetTypeLabel.Text = $Global:NetTypeStatus
		$WiFiTrackbar.visible = $False		
		$WiFigroupbox.visible = $False
	}
	[System.Windows.Forms.Application]::DoEvents()
	$nwtimer.Start()
	$nwtimer.Interval = 2000
	$nwtimer.add_Tick($nwtimer_Tick)
	
	$Global:ipaddress = ([System.Net.DNS]::GetHostAddresses($labelMachineName.Text) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | select-object IPAddressToString)[0].IPAddressToString
	
	if ($Global:IsOnVPN)
	{ $Global:AdSubFromIp = GetAdSubnetInfo -Ip4Adress $Global:VpnIpAdress }
	else
	{ $Global:AdSubFromIp = GetAdSubnetInfo -Ip4Adress $Global:ipaddress }
	
	$IpAdressLabel.Text = $($Global:ipaddress)
	$SiteLabel.Text = $Global:AdSubFromIp.AdSiteName
	$LokasjonLabel.Text = $Global:AdSubFromIp.SubNetLocation
	[System.Windows.Forms.Application]::DoEvents()
	#   ***************    Machine   ************
	$StatusLabel.text = "Starter innhenting av info -> Info om maskin"
	$StartupLabel.text = $(Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime).LastBootUpTime.ToString('dd/MM--hh:mm')
	
	[System.Windows.Forms.Application]::DoEvents()
	# GetPendingReboot
	$RebootPendingStatus = GetPendingReboot
	
	if ($RebootPendingStatus)
	{
		$PendingRebootLabel.text = "Ja"
	}
	else
	{
		$PendingRebootLabel.text = "Nei"
	}
	
	#$StatusLabel.text = "Starter innhenting av info -> Sjekker kjøremiljø"
	Switch ($env:SESSIONNAME.ToUpper().Substring(0, 3))
	{
		"CON"   { $Global:RunEnvironment = "Console" }
		"Console"   { $Global:RunEnvironment = "Console" }
		"RDP"   { $Global:RunEnvironment = "Remote Desktop(RDP)" }
		"ICA"   { $Global:RunEnvironment = "XenApp/Citrix" }
	}
	$SessionEnvlabel.Text = $Global:RunEnvironment
	
	#   ***************    Operatingsystem   ************
	
	$StatusLabel.text = "Starter innhenting av info -> Operativsystem"
	
	$CurrentBuild = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
	$OsDescription = (Get-WMIObject win32_operatingsystem).Caption
	$OsVersionNr = (Get-WMIObject win32_operatingsystem).Version
	$UBR = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	If ($OsVersionNr -like '10.*')
	{
		$Win10DisplayVersion = ""
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "DisplayVersion")
		{
			$Win10DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
		}
		$Win10ReleaseId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
		
		if ($Win10DisplayVersion -ne "")
		{
			$OSVersion = "$Win10DisplayVersion ($CurrentBuild.$UBR)"
		}
		else
		{
			$OSVersion = "$Win10ReleaseId ($CurrentBuild.$UBR)"
		}	
	}
	else
	{
		$Win7CSDVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CSDVersion).CSDVersion
		$Win7CSDCSDBuildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CSDBuildNumber).CSDBuildNumber
		$OSVersion = "$Win7CSDVersion ($CurrentBuild $Win7CSDCSDBuildNumber)"
	}
	
	$labelOScaption.Text = $OsDescription
	$labelOsVersion.Text = $OSVersion
	$labelOsBits.Text = (Get-WMIObject win32_operatingsystem).OSArchitecture
	
	$StatusLabel.text = "Klar"
}



function GetGeneralNetworkInfo
{
	$ResultTable = New-Object System.Data.DataTable
	$col1 = New-Object System.Data.DataColumn("Beskrivelse")
	$col2 = New-Object System.Data.DataColumn("Innhold")
	$col3 = New-Object System.Data.DataColumn("Ping-Status")
	$ResultTable.columns.Add($col1)
	$ResultTable.columns.Add($col2)
	$ResultTable.columns.Add($col3)
	
	if ($Global:IsOnVPN)
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Tilkoblet VPN:"
		$row["Innhold"] = $Global:VpnNetProfileName
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "IP-Adresse:"
		$row["Innhold"] = $Global:VpnIpAdress
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
	}
	else
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Tilkoblet VPN:"
		$row["Innhold"] = "Nei"
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "IP-Adresse:"
		$row["Innhold"] = $Global:ipaddress
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
	}
	if ($Global:AdReachAble)
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Subnett:"
		$row["Innhold"] = $Global:AdSubFromIp.sn
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "AD-Nett ID:"
		$row["Innhold"] = $Global:AdSubFromIp.AdCidr
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "AD-Site navn:"
		$row["Innhold"] = $Global:AdSubFromIp.AdSiteName
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Subnett beskrivelse:"
		$row["Innhold"] = $Global:AdSubFromIp.SubNetDescription
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Subnett lokasjon:"
		$row["Innhold"] = $Global:AdSubFromIp.SubNetLocation
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
			
	}
	
	foreach ($DnsSrv in $Global:DnsList)
	{
		if ($(Test-Connection -computername $($DnsSrv) -Quiet)) { $PingStatus = "ok" } else { $PingStatus = "feilet" }
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "DNS Server:"
		$row["Innhold"] = $DnsSrv
		$row["Ping-Status"] = $PingStatus
		$ResultTable.rows.Add($row)
	}
	# DHCP server
	$interface = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.GetIPProperties() | Select-Object -ExpandProperty DhcpServerAddresses }
	$FoundDhcpServerList = $($interface.GetIPProperties().DhcpServerAddresses).IPAddressToString
	foreach ($FoundDhcpServer in $FoundDhcpServerList)
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "DHCP Server:"
		$row["Innhold"] = $FoundDhcpServer
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
	}
	
	try {
		$SccmSiteMP = $(Get-CIMInstance -ClassName SMS_LookupMP -NameSpace root\ccm).Name
	}
	catch
	{
		$SccmSiteMP = "Ukjent"
	}
	if ($SccmSiteMP -ne "Ukjent")
	{
		foreach ($SccmSiteMPsrv in $SccmSiteMP)
		{
			if ($(Test-Connection -computername $($SccmSiteMP) -Quiet)) { $PingStatus = "ok" }
			else { $PingStatus = "feilet" }
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "SCCM Management Point:"
			$row["Innhold"] = $SccmSiteMPsrv
			$row["Ping-Status"] = $PingStatus
			$ResultTable.rows.Add($row)
		}		
	}
	else
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "SCCM Management Point:"
		$row["Innhold"] = "Ukjent"
		$row["Ping-Status"] = "N.A."
		$ResultTable.rows.Add($row)
	}
	
	
	
	
	
	$ExportTable = New-Object System.Data.DataTable
	$ExportTable = $ResultTable
	Return, $ExportTable
	
}


function GetGeneralOSinfo
{
	$ResultTable = New-Object System.Data.DataTable
	$col1 = New-Object System.Data.DataColumn("Beskrivelse")
	$col2 = New-Object System.Data.DataColumn("Innhold")
	$ResultTable.columns.Add($col1)
	$ResultTable.columns.Add($col2)
	
	
	#$OsDescription = (Get-WMIObject win32_operatingsystem).Caption
	$win32operatingsystem = Get-WMIObject win32_operatingsystem
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "Maskin-navn:"
	$row["Innhold"] = $win32operatingsystem.CSName
	$ResultTable.rows.Add($row)
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "OS Navn:"
	$row["Innhold"] = $win32operatingsystem.Caption
	$ResultTable.rows.Add($row)
	
	If ($win32operatingsystem.Caption -like '*Windows 10*')
	{
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Versjon beskrivelse:"
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "DisplayVersion")
		{
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
		}
		else
		{
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
		}
		$ResultTable.rows.Add($row)
	}
	
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "Versjon nummer:"
	$row["Innhold"] = $win32operatingsystem.Version
	$ResultTable.rows.Add($row)
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "Buildnr:"
	$row["Innhold"] = $win32operatingsystem.BuildNumber
	$ResultTable.rows.Add($row)
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "Installasjonsdato:"
	$row["Innhold"] = (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate)
	$ResultTable.rows.Add($row)
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "Maskin startet:"
	#$row["Innhold"] = $win32operatingsystem.LastBootUpTime
	$row["Innhold"] = (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
	$ResultTable.rows.Add($row)
	
	$row = $ResultTable.NewRow()
	$row["Beskrivelse"] = "OS Arkitektur:"
	$row["Innhold"] = $win32operatingsystem.OSArchitecture
	$ResultTable.rows.Add($row)
	
	If ($win32operatingsystem.Caption -like '*Windows 10*')
	{
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Value "Deployed")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD Deployed:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name Deployed).Deployed
			$ResultTable.rows.Add($row)			
		}
		
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Value "Task Sequence Name")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD Task Sequence Name:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name 'Task Sequence Name').'Task Sequence Name'
			$ResultTable.rows.Add($row)
		}
		
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Value "Task Sequence Initializer Name")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD TS Initializer Name:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name 'Task Sequence Initializer Name').'Task Sequence Initializer Name'
			$ResultTable.rows.Add($row)
		}
		
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Value "Client Type")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD Client Type:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name 'Client Type').'Client Type'
			$ResultTable.rows.Add($row)
		}
		
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Value "Deployment Status")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD Deployment Status:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name 'Deployment Status').'Deployment Status'
			$ResultTable.rows.Add($row)
		}
		
		if (Test-RegistryValue -key "HKLM:\SOFTWARE\Sykehuspartner\OSD\Branding" -Value "Deployment Status")
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "OSD BuildVariables:"
			$row["Innhold"] = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Sykehuspartner\OSD" -Name 'BuildVariables').'BuildVariables'
			$ResultTable.rows.Add($row)
		}
		
	}
	
	$ExportTable = New-Object System.Data.DataTable
	$ExportTable = $ResultTable
	Return, $ExportTable
	
}


Function GetOsHotfixList
{
	$Session = New-Object -ComObject "Microsoft.Update.Session"
	$Searcher = $Session.CreateUpdateSearcher()
	$historyCount = $Searcher.GetTotalHistoryCount()
	
	$UpdateHistory = $Searcher.QueryHistory(0, $historyCount)
	$KBs = @()
	
	foreach ($Update in $UpdateHistory)
	{
		[regex]::match($Update.Title, '(KB[0-9]{6,7})').value | Where-Object { $_ -ne "" } | foreach {
			$KB = New-Object -TypeName PSObject
			$KB | Add-Member -MemberType NoteProperty -Name KB -Value $_
			$KB | Add-Member -MemberType NoteProperty -Name Title -Value $Update.Title
			$KB | Add-Member -MemberType NoteProperty -Name Description -Value $Update.Description
			$KB | Add-Member -MemberType NoteProperty -Name Date -Value $Update.Date
			$KBs += $KB
		}
	}
	#$KBs | Select KB, Date, Title, Description
	Return $KBs
}

function Test-RegistryKey
{
	[OutputType('bool')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Key
	)
	
	$ErrorActionPreference = 'Stop'
	
	if (Get-Item -Path $Key -ErrorAction Ignore)
	{
		$true
	}
}

function Test-RegistryValue
{
	[OutputType('bool')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Key,
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Value
	)
	$ErrorActionPreference = 'Stop'
	if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore)
	{
		$true
	}
}

function Test-RegistryValueNotNull
{
	[OutputType('bool')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Key,
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Value
	)
	
	$ErrorActionPreference = 'Stop'
	
	if (($regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) -and $regVal.($Value))
	{
		$true
	}
}

$RebootTests = @(
	{ Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
	{ Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress' }
	{ Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
	{ Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending' }
	{ Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' }
	{ Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' }
	{ Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations2' }
#	{
#		# Added test to check first if key exists, using "ErrorAction ignore" will incorrectly return $true
#		'HKLM:\SOFTWARE\Microsoft\Updates' | Where-Object { test-path $_ -PathType Container } | ForEach-Object {
#			(Get-ItemProperty -Path $_ -Name 'UpdateExeVolatile' | Select-Object -ExpandProperty UpdateExeVolatile) -ne 0
#		}
#	}
	{ Test-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Value 'DVDRebootSignal' }
	{ Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps' }
	{ Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'JoinDomain' }
	{ Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'AvoidSpnSet' }
	{
		# Added test to check first if keys exists, if not each group will return $Null
		# May need to evaluate what it means if one or both of these keys do not exist
		('HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' | Where-Object { test-path $_ } | %{ (Get-ItemProperty -Path $_).ComputerName }) -ne
		('HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' | Where-Object { Test-Path $_ } | %{ (Get-ItemProperty -Path $_).ComputerName })
	}
	{
		# Added test to check first if key exists
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' | Where-Object {
			(Test-Path $_) -and (Get-ChildItem -Path $_)
		} | ForEach-Object { $true }
	}
)

function GetPendingReboot
{
	$PendingReboot = $False
	foreach ($test in $RebootTests)
	{
		if (& $test)
		{
			#Write-Host $test
			$PendingReboot = $true
			break
		}
	}
	return $PendingReboot
}



function Win32ReliabilityRecords()
{
	if ($Global:FoundReliabilityRecords.count -eq 0)
	{
		$ReliabilityRecords = Get-CIMInstance -ClassName Win32_ReliabilityRecords -NameSpace root\cimv2 | Select-Object InsertionStrings, Productname, Message, Sourcename, Timegenerated | Sort-Object -Property Timegenerated -Descending
	}
	else
	{
		$ReliabilityRecords = $Global:FoundReliabilityRecords
	}
	
	return $ReliabilityRecords
}

function GetPnpDevices()
{
	if ($Global:FoundPnpDevices.count -eq 0)
	{
		$PnpDevices = Get-WmiObject Win32_PNPEntity | Select-Object Name, Status, Description, Manufacturer, PNPClass, Present, Service | Sort-Object -Property PNPClass
	}
	else
	{
		$PnpDevices = $Global:FoundPnpDevices
	}
	
	Return $PnpDevices
}

function GetInstalledSw
{
	if ($Global:FoundInstalledSw.count -eq 0)
	{
		$win32product = Get-CimInstance -ClassName win32_product -NameSpace root\cimv2 | Select-Object Name, Vendor, Version, InstallDate | Sort-Object -Property InstallDate -Descending
	}
	else
	{
		$win32product = $Global:FoundInstalledSw
	}
	
	return $win32product
	
}


function UpdateWifiStatus
{
	if ($Global:WirelessConnected)
	{
		$ActiveSSID = netsh wlan show interfaces | select-string SSID
		$Global:ActiveSSIDName = $($ActiveSSID[0] -split ":")[1].Trim()
		
		foreach ($Network in $(Get-WifiNetworks))
		{
			if ($Network.SSID -eq $Global:ActiveSSIDName)
			{
				$WirelessStatusStr = $Network.Signal
			}
		}
		$WiFiTrackbar.value = $WirelessStatusStr -replace "%", ""
		#if ($tabcontrol1.SelectedIndex -eq 0)
		#{
			
		#}
	}
}



#  --------------------------     Job handling   -------------------------------------------------------


function Check-Jobs
{
	$JobCounter = 0
	While (get-job -HasMoreData $true)
	{
		foreach ($JobItem in $Global:JobArray)
		{
			$JobCounter++
			if (($(Get-Variable -Name "$($JobItem.VarName)" -ValueOnly) -eq "") -and ((get-job -Name "$($JobItem.JobName)" -ChildJobState Running).State -eq 'Completed'))
			{
				
				switch ($JobItem.JobName)
				{
					"GetInstalledSw"       	{
						$Global:FoundInstalledSw = Receive-Job -Name "$($JobItem.JobName)"
					}
					
					"ReliabilityRecords"  	{
						$Global:FoundReliabilityRecords = Receive-Job -Name "$($JobItem.JobName)"						
					}
					
					"PnpDevices"       		{
						$Global:FoundPnpDevices = Receive-Job -Name "$($JobItem.JobName)"
					}
					
					"MachineHwTable"       	{
						$Global:FoundMachineHwTable = Receive-Job -Name "$($JobItem.JobName)"
					}
					
					"UserGroupList"       	{
						$Global:FoundUserGroupList = Receive-Job -Name "$($JobItem.JobName)"
					}
					
					Default { }
				}
			}
		}
		
	}
	if ($JobCounter -ne 0)
	{ $JobActive.text = "Bakrunnsjobber aktive" }
	else
	{
		$JobActive.text = ""
		$nwtimer.stop()
		$WaitLabel.enabled = $False
		$WaitLabel.visible = $False
		
	}
}


$InstalledSoftwareBlock = {
	#$InstalledSw = GetInstalledSw
	$InstalledSw = Get-CimInstance -ClassName win32_product -NameSpace root\cimv2 | Select-Object Name, Vendor, Version, InstallDate | Sort-Object -Property InstallDate -Descending
	return $InstalledSw
}

$Win32ReliabilityBlock = {
	$ReliabilityRecords = Get-CIMInstance -ClassName Win32_ReliabilityRecords -NameSpace root\cimv2 | Select-Object InsertionStrings, Productname, Message, Sourcename, Timegenerated | Sort-Object -Property Timegenerated -Descending
	return $ReliabilityRecords
}

$PnpDevicesBlock = {
	#$InstalledSw = GetInstalledSw
	$PnpDevices = Get-WmiObject Win32_PNPEntity | Select-Object Name, Status, Description, Manufacturer, PNPClass, Present, Service | Sort-Object -Property PNPClass
	Return $PnpDevices
}


function InitBlock
{
	$Global:GetMachineHwTable = {
		$ResultTable = New-Object System.Data.DataTable
		$col1 = New-Object System.Data.DataColumn("Beskrivelse")
		$col2 = New-Object System.Data.DataColumn("Innhold")
		$ResultTable.columns.Add($col1)
		$ResultTable.columns.Add($col2)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Maskin-navn:"
		$row["Innhold"] = $((Get-WmiObject Win32_ComputerSystem).Name)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Produsent:"
		$row["Innhold"] = $((Get-WmiObject Win32_ComputerSystem).Manufacturer)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Modell:"
		$row["Innhold"] = $((Get-WmiObject Win32_ComputerSystem).Model)
		$ResultTable.rows.Add($row)
		
		$MemInGb = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach { "{0:N2}" -f ([math]::round(($_.Sum / 1GB), 0)) }
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Minne (GigaByte):"
		$row["Innhold"] = $MemInGb
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Serienr:"
		$row["Innhold"] = $((Get-WmiObject Win32_Bios).SerialNumber)
		$ResultTable.rows.Add($row)
		
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Bios Versjon:"
		$row["Innhold"] = $((Get-WmiObject Win32_Bios).SMBIOSBIOSVersion)
		$ResultTable.rows.Add($row)
		
		$HddList = Get-WmiObject Win32_DiskDrive
		foreach ($HddItem in $HddList)
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "Disk:"
			$row["Innhold"] = $($HddItem.model)
			$ResultTable.rows.Add($row)
		}
		
		$VideoControllers = Get-WmiObject Win32_VideoController
		foreach ($Controller in $VideoControllers)
		{
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "Skjermkort Modell:"
			$row["Innhold"] = $($Controller.Caption)
			$ResultTable.rows.Add($row)
			
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "Skjermkort Minne (Gb):"
			$row["Innhold"] = [math]::round($($Controller.AdapterRAM) /1Gb, 0)
			$ResultTable.rows.Add($row)
		}
		
		$MonitorList = Get-WmiObject Win32_DesktopMonitor
		foreach ($MonitorItem in $MonitorList)
		{
			$MonitorDescription = "$($MonitorItem.MonitorManufacturer)  $($MonitorItem.Description)"
			
			$row = $ResultTable.NewRow()
			$row["Beskrivelse"] = "Monitor:"
			$row["Innhold"] = $MonitorDescription
			$ResultTable.rows.Add($row)
			
		}
		
		$OkFan = 0
		$FailFan = 0
		$FanList = Get-WmiObject Win32_Fan
		foreach ($FanItem in $FanList)
		{
			if ($($FanItem.Status) -eq "OK")
			{ $OkFan++ }
			else
			{ $FailFan++ }
		}
		$row = $ResultTable.NewRow()
		$row["Beskrivelse"] = "Vifter:"
		If (($OkFan -gt 0) -or ($FailFan -gt 0))
		{
			$row["Innhold"] = "$OkFan Vifter er OK -- $FailFan Vifter har feilet"
		}
		else
		{
			$row["Innhold"] = "Ingen detektert"
		}
		$ResultTable.rows.Add($row)
		
		
		$LogicalDiskList = Get-WmiObject Win32_LogicalDisk
		foreach ($LogicalDiskItem in $LogicalDiskList)
		{
			if ($($LogicalDiskItem.DeviceID) -eq "C:")
			{
				$row = $ResultTable.NewRow()
				$row["Beskrivelse"] = "Ledig plass på C: (Gb):"
				$row["Innhold"] = [math]::round($($LogicalDiskItem.FreeSpace) /1Gb, 0)
				$ResultTable.rows.Add($row)
			}
		}
		
		$UsbDeviceList = Get-WmiObject Win32_USBDevice
		foreach ($UsbDeviceItem in $UsbDeviceList)
		{
			if ($UsbDeviceItem.Description -eq "Disk drive")
			{
				$row = $ResultTable.NewRow()
				$row["Beskrivelse"] = "USB Disk:"
				$row["Innhold"] = $UsbDeviceItem.Caption
				$ResultTable.rows.Add($row)
			}
		}
		
		$ExportTable = New-Object System.Data.DataTable
		$ExportTable = $ResultTable
		Return, $ExportTable
	}
	
	
	
	$Global:InstalledSoftwareBlock = {
		#$InstalledSw = GetInstalledSw
		$InstalledSw = Get-CimInstance -ClassName win32_product -NameSpace root\cimv2 | Select-Object Name, Vendor, Version, InstallDate | Sort-Object -Property InstallDate -Descending
		return $InstalledSw
	}
	
	$Global:Win32ReliabilityBlock = {
		$ReliabilityRecords = Get-CIMInstance -ClassName Win32_ReliabilityRecords -NameSpace root\cimv2 | Select-Object InsertionStrings, Productname, Message, Sourcename, Timegenerated | Sort-Object -Property Timegenerated -Descending
		return $ReliabilityRecords
	}
	
	$Global:PnpDevicesBlock = {
		#$InstalledSw = GetInstalledSw
		$PnpDevices = Get-WmiObject Win32_PNPEntity | Select-Object Name, Status, Description, Manufacturer, PNPClass, Present, Service | Sort-Object -Property PNPClass
		Return $PnpDevices
	}
	
}

Function InitBlockWithAD	
{
	$Global:NestedMemberOfList = {
		
		param (
			[String[]]$ObjectType,
			[String[]]$ObjectName,
			[String[]]$AdsiPathString)
		
		
		Function GetNameFromADSPath
		{
			param (
				[Parameter(Mandatory = $true)]
				[String[]]$ADSPathString
			)
			$NameToReturn = ""
			$AdsSearcher = [adsisearcher]"(&(objectCategory=Group)(objectClass=Group)(distinguishedName=$ADSPathString))"
			$AdsSearcher.PropertiesToLoad.AddRange(('name'))
			#$AdsSearcher.searchRoot    =   [ADSI]$AdsiPathForDomain
			$AdsSearcherList = $AdsSearcher.FindAll()
			foreach ($AdsSearcherItem in $AdsSearcherList)
			{
				$NameToReturn = $AdsSearcherItem.Properties.name
			}
			Return $NameToReturn
		}
		
		function GetAdsiPathForCurrentDomain
		{
			$Root = [ADSI]"LDAP://RootDSE"
			$GetAdsiPathStr = 'LDAP://' + $Root.rootDomainNamingContext
			return $GetAdsiPathStr
		}
		
		If ($AdsiPathString -eq $null)
		{ $AdsiPathString = GetAdsiPathForCurrentDomain }
		
		Switch ($ObjectType)
		{
			"Machine"   { $AdsiSearcher = [adsisearcher]"(&(objectCategory=computer)(cn=$ObjectName))" }
			"User"      { $AdsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$ObjectName))" }
			"Group"     { $AdsiSearcher = [adsisearcher]"(&(objectCategory=Group)(objectClass=Group)(cn=$ObjectName))" }
		}
		
		$AdsiSearcher.PropertiesToLoad.AddRange(('name', 'memberof'))
		$AdsiSearcher.searchRoot = [ADSI]$AdsiPathString[0]
		$AdsiSearchList = $AdsiSearcher.FindAll()
		$ActiveGroupName = ''
		foreach ($GroupItem in $AdsiSearchList.properties.memberof)
		{
			$GroupArray += @([PsCustomObject]@{ Navn = $ActiveGroupName; DN = $GroupItem; Medlemskap = "Direkte"; Executed = 0 })
		}
		
		$NestedRemains = 1
		while ($NestedRemains -eq 1)
		{
			$NestedRemains = 0
			foreach ($GroupArrayItem in $GroupArray)
			{
				if ($GroupArrayItem.Executed -eq 0)
				{
					$GroupDN = $GroupArrayItem.DN
					$AdsiSubSearcher = [adsisearcher]"(&(objectCategory=Group)(objectClass=Group)(distinguishedName=$GroupDN))"
					#	$AdsiSubSearcher.PropertiesToLoad.AddRange(('name', 'memberof'))
					$AdsiSubSearcher.PropertiesToLoad.AddRange('memberof')
					$AdsiSubSearcher.searchRoot = [ADSI]$AdsiPathString[0]
					$AdsiSubSearchList = $AdsiSubSearcher.FindAll()
					foreach ($GroupSubItem in $AdsiSubSearchList.properties.memberof)
					{
						$NestedRemains = 1
						if ($GroupArray.DN -notcontains $GroupSubItem)
						{
							$GroupArray += @([PsCustomObject]@{ Navn = $ActiveGroupName; DN = $GroupSubItem; Medlemskap = "Inndirekte"; Executed = 0 })
						}
					}
					$GroupArrayItem.Executed = 1
				}
			}
		}
		
		if ($GroupArray)
		{
			$GroupArray | foreach-object {
				$_.Navn = GetNameFromADSPath $_.DN
			}
			$GroupArray = $GroupArray | Sort-Object  Medlemskap, Navn -Unique
		}
		else
		{
			$GroupArray += @([PsCustomObject]@{ Navn = "Ingen medlememskap"; DN = $GroupSubItem; Medlemskap = "Direkte"; Executed = 0 })
		}
		
		return ,$GroupArray
	}
}


Function StartBackgroundJobs2
{
	InitBlock
	
	$Global:FoundInstalledSw = ""
	$InstalledSoftwareBlock2 = $Global:InstalledSoftwareBlock
	$JobParameterArray = [Collections.ArrayList] @($InstalledSoftwareBlock2)
	Start-Job -Scriptblock { Param ([string]$InnerSB) Invoke-Expression $InnerSB } -ArgumentList $JobParameterArray -Name 'GetInstalledSw'
	$Global:JobArray += @([PsCustomObject]@{ BlockName = "$InstalledSoftwareBlock2"; JobName = "GetInstalledSw"; VarName = 'FoundInstalledSw' })
	
	$Global:FoundReliabilityRecords = ""
	$Win32ReliabilityBlock2 = $Global:Win32ReliabilityBlock
	$JobParameterArray = [Collections.ArrayList] @($Win32ReliabilityBlock2)
	Start-Job -Scriptblock { Param ([string]$InnerSB) Invoke-Expression $InnerSB } -ArgumentList $JobParameterArray -Name 'ReliabilityRecords'
	$Global:JobArray += @([PsCustomObject]@{ BlockName = "$Win32ReliabilityBlock2"; JobName = "ReliabilityRecords"; VarName = 'FoundReliabilityRecords' })
		
	$Global:FoundPnpDevices = ""
	$PnpDevicesBlock2 = $Global:PnpDevicesBlock
	$JobParameterArray = [Collections.ArrayList] @($PnpDevicesBlock2)
	Start-Job -Scriptblock { Param ([string]$InnerSB) Invoke-Expression $InnerSB } -ArgumentList $JobParameterArray -Name 'PnpDevices'
	$Global:JobArray += @([PsCustomObject]@{ BlockName = "$InstalledSoftwareBlock2"; JobName = "PnpDevices"; VarName = 'FoundPnpDevices' })
	
	$Global:FoundMachineHwTable = ""
	$GetMachineHwTable2 = $Global:GetMachineHwTable
	$JobParameterArray = [Collections.ArrayList] @($GetMachineHwTable2)
	Start-Job -Scriptblock { Param ([string]$InnerSB) Invoke-Expression $InnerSB } -ArgumentList $JobParameterArray -Name 'MachineHwTable'
	$Global:JobArray += @([PsCustomObject]@{ BlockName = "$GetMachineHwTable2"; JobName = "MachineHwTable"; VarName = 'FoundMachineHwTable' })
	
	if ($Global:AdReachAble)
	{
		InitBlockWithAD
		
		$Global:FoundUserGroupList = ""
		#$Global:FoundUserGroupList = ""
		$NestedMemberOfList2 = $Global:NestedMemberOfList
		
		#$JobParameterArray = [Collections.ArrayList] @($NestedMemberOfList2, 'User', $Global:UserName, $Global:UserDomainLdap)
		$JobParameterArray2 = [Collections.ArrayList] @('User', $Global:UserName, $Global:UserDomainLdap)
		#Start-Job -Scriptblock { Param ([string]$InnerSB) Invoke-Expression $InnerSB, 'User', $Global:UserName, $Global:UserDomainLdap } -ArgumentList $JobParameterArray -Name 'UserGroupList'
		Start-Job -Scriptblock $NestedMemberOfList2 -ArgumentList $JobParameterArray2 -Name 'UserGroupList'
		$Global:JobArray += @([PsCustomObject]@{ BlockName = "$NestedMemberOfList2"; JobName = "UserGroupList"; VarName = 'FoundUserGroupList' })
		
	
	}
	
	
}

