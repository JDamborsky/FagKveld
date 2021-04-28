function Get-AdsiPathForCurrentDomain
{
	$Root = [ADSI]"LDAP://RootDSE"
	$GetAdsiPathStr = 'LDAP://' + $Root.rootDomainNamingContext
	return $GetAdsiPathStr
}

function Get-MachineInfoFromAD
{
	param (
		[string]$ClientNameToFind)
	
	$IsObjectFound = $false
	$operatingsystemversion = ''
	$operatingsystem = ''
	$lastLogon = ''
	$LLDate = ''
	$MemberOf = ''
	$MachineLdap = ''
	
	
	# Build for ADSI Query
	$AdsiPathForDomain = Get-AdsiPathForCurrentDomain
	$searcher = [adsisearcher]"(&(objectCategory=computer)(cn=$ClientNameToFind))"
	$searcher.searchRoot = [ADSI]$AdsiPathForDomain
	$searcher.PropertiesToLoad.Add('operatingsystemversion')
	$searcher.PropertiesToLoad.Add('operatingsystem')
	$searcher.PropertiesToLoad.Add('lastlogon')
	$searcher.PropertiesToLoad.Add('memberof')
	$searcher.PropertiesToLoad.Add('distinguishedname')
	$searcher.PropertiesToLoad.Add('useraccountcontrol')
	$searcher.PropertiesToLoad.Add('pwdLastSet')
	try
	{
		$MachineItemList = $searcher.FindAll()
	}
	catch
	{
		$IsObjectFound = $false
		Write-Host "Not Found in AD"
	}
	
	foreach ($MachineItem in $MachineItemList)
	{
		$IsObjectFound = $true
		$IsObjectEnabled = $true
		$MachineLdap = $MachineItem.Path
		$operatingsystemversion = $MachineItem.Properties.Item('operatingsystemversion')
		$operatingsystem = $MachineItem.Properties.Item('operatingsystem')
		
		$LL = $MachineItem.Properties.Item("lastLogon")[0]
		If (-Not $LL) { $LL = 0 }
		$LLDate = [DateTime]$LL
		$lastLogon = $LLDate.AddYears(1600).ToLocalTime()
		$LL = $MachineItem.Properties.Item("pwdLastSet")[0]
		If (-Not $LL) { $LL = 0 }
		$LLDate = [DateTime]$LL
		$pwdLastSet = $LLDate.AddYears(1600).ToLocalTime()
		
		if ([string]$MachineItem.properties.useraccountcontrol -band 2)
		{
			$IsObjectEnabled = $False
			$IsObjectEnabledbit = 0
		}
		else
		{
			$IsObjectEnabled = $true
			$IsObjectEnabledbit = 1
		}
		
		$MemberOfArray = $MachineItem.Properties.Item('memberof')
		
	}
	
	# Build a string of all Group-Names
	$memberof = ''
	foreach ($MemberOfItem in $MemberOfArray)
	{
		$MemberOfItemArray = $MemberOfItem -split ','
		$MemberOfGroup = $MemberOfItemArray[0] -replace 'CN='
		$memberof += "$MemberOfGroup;"
	}
	
	if ($memberof.Length -gt 0)
	{
		$memberof = $memberof.Substring(0, $memberof.Length - 1)
	}
	
	# Build a PsCustomObject to return
	
	$tmpHashtable = @{
		MachineName = "$ClientNameToFind"
		IsObjectFound = $IsObjectFound
		MachineLdap = "$MachineLdap"
		operatingsystem = "$operatingsystem"
		operatingsystemversion = "$operatingsystemversion"
		lastLogon   = "$lastLogon"
		#memberofList              = "$memberof"
		#memberofArray             = "$MemberOfArray" 
		IsObjectEnabled = $IsObjectEnabled
		pwdLastSet  = "$pwdLastSet"
	}
	
	
	#  Convert PsCustomObject to DataTable
	$ResultTable = New-Object System.Data.DataTable
	#Headdings
	foreach ($Item in $tmpHashtable.keys)
	{
		$col = New-Object System.Data.DataColumn("$Item")
		$ResultTable.columns.Add($col)
	}
	#Values
	$row = $ResultTable.NewRow()
	$ColCounter = 0
	foreach ($ValItem in $tmpHashtable.Values)
	{
		$RowName = $ResultTable.columns[$ColCounter].ColumnName
		$row["$RowName"] = $ValItem
		$ColCounter++
	}
	$ResultTable.rows.Add($row)
	
	
	# Choose output ......
	#Return [pscustomobject]$tmpHashtable
	Return [System.Data.DataTable]$ResultTable	
	
}

