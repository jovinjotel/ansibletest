function dNew-ADComputerAcct {
	<# .Description
		Function to create a computer object in Active Directory, handling the SamAccountName length if the given computer name is longer than 15 characters
		Relies on Quest AD cmdlets being installed and the PSSnapin available
	#>
	param(
		## Name of new computer object to create
		[parameter(Mandatory=$true)][string]$Name,
		## Path to OU in which to make computer object
		[parameter(Mandatory=$true)][string]$OUPath,
		## Privileged domain account (if not using current user) to use for creating new computer object
		[System.Management.Automation.PSCredential]$Credential,
		## Domain on which to create computer account, or explicit AD domain controller; will be used for AD domain controller or AD LDS server to which to connect
		#   expected in format "xx.lilly.com" or "somedc01.yy.lilly.com"
		[parameter(Mandatory=$true)][string]$Service
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
	## common params used for each QAD call
	$hshCommonParams = @{Service = $Service}
	if ($PSBoundParameters.ContainsKey("Credential")) {$hshCommonParams["Credential"] = $Credential}

	## check for existence of specified OU
	$hshParamsForGetQadObject = @{Identity = $OUPath; DontUseDefaultIncludedProperties = $true; Type = "OrganizationalUnit"}
	## if OU doesn't exist, throw message; else, try to make new computer object
	if (-not (Get-QADObject @hshParamsForGetQadObject @hshCommonParams)) {Throw "$strLogEntry_ToAdd OU '$OUPath' not found via service '$Service'. Does it exist?"}
	else {
		## make computer object in AD in the given OU, if it does not already exist in AD
		if (Get-QADComputer -Name $Name @hshCommonParams) {"$strLogEntry_ToAdd computer object '$Name' already exists"}
		else {
			## for the SamAccountName, if computer name is longer than 15 char, truncate to 15 (which is the default behavior displayed by ADUC)
			$strTruncatedComputerName = $Name.Substring(0,([math]::min(15,$Name.Length))).ToUpper()
			## param values to create new computer object
			$hshNewComputerParams = @{
				ParentContainer = $OUPath
				Name = $Name.ToUpper()
				SamAccountName = "${strTruncatedComputerName}`$"
			} ## end params hashtable
			## return the results of trying to create new computer object
			New-QADComputer @hshNewComputerParams @hshCommonParams
		} ## end else
	} ## end else
} ## end fn


function dRemove-ADComputerAcct {
	<# .Description
		Function to delete a computer object in Active Directory.  Uses on Quest AD cmdlets
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), dHandle-ErrorCatch()
		.Outputs
		Boolean:  did the AD Computer object removal appear to succeed?
	#>
	param(
		## computer host name
		[parameter(Mandatory=$true)][string]$ComputerName_str,
		## privileged domain account (if not using current user)
		[System.Management.Automation.PSCredential]$PrivilegedDomainAcct_cred,
		## domain on which to create computer account; will be used for AD domain controller or AD LDS server to which to connect
		#   expected in format "xx.lilly.com"
		[parameter(Mandatory=$true)][string]$Domain_str
	) ## end param

	## params/values for connecting to given domain/LDAP service for QADCmdlets
	$hshConnectQADServiceParamsAndValues = @{"Service" = $Domain_str}
	if ($PrivilegedDomainAcct_cred -ne $null) {$hshConnectQADServiceParamsAndValues["Credential"] = $PrivilegedDomainAcct_cred}
	## connect to given AD domain, saving connection object for later, explicit use on further *-QAD* cmdlets
	#   this connection is reportedly the default connection used in later calls (until the connection is ended closed either explicitly or by establishing a new connection), but using it here for the sake of explicitness (so that subsequent operations are less [not?] affected by incomplete directory replication)
	$oArsADConn = Connect-QADService @hshConnectQADServiceParamsAndValues
	## if the connection attempt did not succeed (no connection object returned, or the returned object is not of the expected type); touch of overlap -- if $null, then -isnot of given type anyway, but, just for being sure
	if (($oArsADConn -eq $null) -or ($oArsADConn -isnot [Quest.ActiveRoles.ArsPowerShellSnapIn.Data.ArsADConnection])) {$Private:bComputerObjDeleteSucceeded = $false; dWrite-LogEntry "[Problem] attempt to connect to domain controller in '$Domain_str' via QAD cmdlet did not result in a connection.  Valid domain, proper credentials?" -foreground Red}
	## else, connected OK -- will proceed with trying to delete computer object
	else {
		dWrite-LogEntry -Entry "Nice -- established connection to domain '$Domain_str' (path '$($oArsADConn.RootDSE.Path)')" -foregroundColor DarkGreen
		## the SamAccountName that would result from a computer with name submitted as param
		$strSupposedComputerSamAcctName = "$ComputerName_str`$"

		## get computer objects that have SamAccountName of <computerName$> in given domain (should be just one item)
		$oComputerObjectToDelete = Get-QADComputer -SamAccountName $strSupposedComputerSamAcctName -Connection $oArsADConn -DontUseDefaultIncludedProperties
		$intNumMatchingComputerObjs = ($oComputerObjectToDelete | Measure-Object).Count
		## if only one object returned, and it is an ArsComputerObject
		if ( ($intNumMatchingComputerObjs -eq 1) -and ($oComputerObjectToDelete -is [Quest.ActiveRoles.ArsPowerShellSnapIn.Data.ArsComputerObject]) ) {
			## get the SamAccountName of the object being handled here
			$strThisObjSamAcctName = $oComputerObjectToDelete.SamAccountName
			## try to delete computer object
			dWrite-LogEntry "Good:  double-check of Computer objects in domain '$Domain_str' with SamAccountName '$strSupposedComputerSamAcctName' resulted in exactly one (1) item"
			dWrite-LogEntry "Attempting to forcibly delete Computer object '$strThisObjSamAcctName' (GUID '$($oComputerObjectToDelete.GUID)') from domain '$Domain_str'"
			try {Remove-QADObject -Identity $oComputerObjectToDelete.GUID -Connection $oArsADConn -DeleteTree -Confirm:$false -Force -ErrorAction:Stop}
			catch {dHandle-ErrorCatch -MessageToConvey "[Error] encountered an error when issuing Remove command on computer object with SamAccountName '$strThisObjSamAcctName'" -ExitAltogether:$true} ## end catch

			## may need to add a bit of a pause here, if it comes to be that the deleted object does not report as deleted upon immediate, subsequent query; should be handled, though, since re-using connection should send query to same AD server that processed the delete request
			## does Get-QADComputer of entity with the computer name that passed in (the computer object to be deleted from AD) return $null? (signifying that the delete succeeded (or that no entity of that SamAccountName existed to start with))
			$Private:bComputerObjDeleteSucceeded = $null -eq (Get-QADComputer -SamAccountName $strSupposedComputerSamAcctName -Connection $oArsADConn -DontUseDefaultIncludedProperties -ErrorAction:SilentlyContinue)
			if ($Private:bComputerObjDeleteSucceeded -eq $true) {dWrite-LogEntry -Entry "Successful delete of computer object '$ComputerName_str' from '$Domain_str'" -Foreground DarkGreen}
			else {dWrite-LogEntry -Entry "[Problem] Delete of computer object '$ComputerName_str' from '$Domain_str' failed" -Foreground Red}
		} ## end if
		## else, write log entry
		else {$Private:bComputerObjDeleteSucceeded = $false; dWrite-LogEntry "[Problem] check for computer objects with SamAccountName '$strSupposedComputerSamAcctName' in domain '$Domain_str' either did not yield exactly one (1) item, or that one item was not a ComputerObject (returned '$intNumMatchingComputerObjs' items)" -foreground Red}

		dWrite-LogEntry -Entry "closing AD connection to '$($oArsADConn.RootDSE.Path)'"
		Disconnect-QADService -Connection $oArsADConn
	} ## end else

	return $Private:bComputerObjDeleteSucceeded
} ## end fn


function dWrite-LogEntry {
	<# .Description
		Function to write to a log file
		Checks if logging is enabled first (relies on global variable "$bDoLog"); uses global var "$strScriptCWD" for folder (and expects subfolder "logs" there) by default; uses default log filename from global variable $strLogFilename if present. And, if $bDoConsoleOutput is $true, this will also write output to console
	#>
	param(
		## item to add to log; not necessarily a string (might be an object)
		$entry,
		## switch:  do not prepend date/time to entry if switch is specified
		[switch]$noPrepend_sw,
		## path where logfile resides; uses global var "$strScriptCWD" if present (else, will result in writing to root of current PSDrive)
		[string]$logPath_str = "$strScriptCWD\logs",
		## logfile filename (use default from global variable $strLogFilename, if set)
		[string]$logFilename_str = $(if ($strLogFilename -ne $null) {$strLogFilename} else {"defaultLogfile.log"}),
		## foreground color for console output
		[ConsoleColor]$foregroundColorOutput_ConsoleColor = "DarkGray"
	) ## end param

	## if there is going to be output of some sort, create the string to prepend to the entry (if any)
	if (($bDoLog -eq $true) -or ($bDoConsoleOutput -eq $true)) {$strPrependToEntry = $(if ($noPrepend_sw -eq $true) {""} else {"[$(Get-Date -Format 'yyyy.MMM.dd HH:mm:ss')] "})}

	if ($bDoLog -eq $true) {Add-Content -Path $logPath_str\$logFilename_str "$strPrependToEntry$entry" -WhatIf:$false} ## end if

	## if global $bDoConsoleOutput is true, output entry to console
	if ($bDoConsoleOutput -eq $true) {Write-Host "$strPrependToEntry$entry" -ForegroundColor $foregroundColorOutput_ConsoleColor}
} ## end fn

# Author: 	Hal Rottenberg <hal@halr9000.com>
# Url:		http://halr9000.com/article/tag/lib-authentication.ps1
# Purpose:	These functions allow one to easily save network credentials to disk in a relatively
#			secure manner.  The resulting on-disk credential file can only [1] be decrypted
#			by the same user account which performed the encryption.  For more details, see
#			the help files for ConvertFrom-SecureString and ConvertTo-SecureString as well as
#			MSDN pages about Windows Data Protection API.
#			[1]: So far as I know today.  Next week I'm sure a script kiddie will break it.
#
# Usage:	Export-PSCredential [-Credential <PSCredential object>] [-Path <file to export>]
#			Export-PSCredential [-Credential <username>] [-Path <file to export>]
#			If Credential is not specififed, user is prompted by Get-Credential cmdlet.
#			If a username is specified, then Get-Credential will prompt for password.
#			If the Path is not specififed, it will default to "./credentials.enc.xml".
#			Output: FileInfo object referring to saved credentials
#
#			Import-PSCredential [-Path <file to import>]
#
#			If not specififed, Path is "./credentials.enc.xml".
#			Output: PSCredential object

function hExport-PSCredential {
	<#	.Description
		Function to save (export) credentials to disk.  The resulting on-disk credential file can only be imported/decrypted by the same user account which performed the export/encryption
	#>
	param ( $Credential = (Get-Credential), $Path = "credentials.enc.xml" )

	# Look at the object type of the $Credential parameter to determine how to handle it
	switch ( $Credential.GetType().Name ) {
		# It is a credential, so continue
		PSCredential		{ continue }
		# It is a string, so use that as the username and prompt for the password
		String				{ $Credential = Get-Credential -credential $Credential }
		# In all other caess, throw an error and exit
		default				{ Throw "You must specify a credential object to export to disk." }
	}

	# Create temporary object to be serialized to disk
	$export = "" | Select-Object Username, EncryptedPassword

	# Give object a type name which can be identified later
	$export.PSObject.TypeNames.Insert(0,'ExportedPSCredential')

	$export.Username = $Credential.Username

	# Encrypt SecureString password using Data Protection API
	# Only the current user account can decrypt this cipher
	$export.EncryptedPassword = $Credential.Password | ConvertFrom-SecureString

	# Export using the Export-Clixml cmdlet
	$export | Export-Clixml $Path
	Write-Host -foregroundcolor Green "Credentials saved to: " -noNewLine

	# Return FileInfo object referring to saved credentials
	Get-Item $Path
} ## end fn

function hImport-PSCredential {
	<#	.Description
		Function to import credentials from a file of previously exported credentials.  The on-disk credential file can only be imported/decrypted by the same user account which performed the export/encryption
	#>
	param ( $Path = "credentials.enc.xml" )

	# Import credential file
	$import = Import-Clixml $Path

	# Test for valid import
	if ( !$import.UserName -or !$import.EncryptedPassword ) {Throw "Input is not a valid ExportedPSCredential object, exiting."}
	$Username = $import.Username

	# Decrypt the password and store as a SecureString object for safekeeping
	$SecurePass = $import.EncryptedPassword | ConvertTo-SecureString

	# Build the new credential object
	$Credential = New-Object System.Management.Automation.PSCredential $Username, $SecurePass
	Write-Output $Credential
} ## end fn


function dAdd-PSSnapin {
	<#	.Description
		Function to add PSSnapin(s) if not already loaded, and to provide a bit of feedback about the PSSnapin loaded -- amount of time taken, PSSnapin name/version
		Leverages other helper functions dGet-TimespanString and dWrite-LogEntry
	#>
	param([parameter(Mandatory=$true)][string[]]$PSSnapinName_arr)
	$PSSnapinName_arr | Foreach-Object {
		if ((Get-PSSnapin $_ -ErrorAction SilentlyContinue)) {dWrite-LogEntry "PSSnapin '$_' already added"} ## end if
		else {
			## add the snapin, check for how long it takes
			$tspTmp = Measure-Command {$oPSSnapinInfo = Add-PSSnapin $_ -PassThru}
			dWrite-LogEntry $("added Snapin '{0}' (version '{1}'). Time taken to do so: '{2}'" -f $oPSSnapinInfo.Name, $oPSSnapinInfo.Version.ToString(), $(dGet-TimespanString $tspTmp -outputUnit auto)) -foreground DarkGreen
		} ## end else
	} ## end foreach-object
} ## end function


function dImport-Module {
	<#	.Description
		Function to import PSModule(s) if not already imported, and to provide a bit of feedback about the module load -- amount of time taken, Module name/version
		Leverages other helper functions dGet-TimespanString and dWrite-LogEntry
	#>
	param(
		## name of the PSModule to import
		[parameter(Mandatory=$true)][string[]]$Name,
		## path in which to look for PSModule (parent folder of the actual module folder); if none specified, just rely on Env:\PSModulePath
		[string]$PSModulePath
	)
	$Name | Foreach-Object {
		$strThisModuleName = $_
		if (Get-Module -Name $strThisModuleName) {dWrite-LogEntry "PSModule '$strThisModuleName' already loaded"} ## end if
		else {
			$strModuleToImport = if ([String]::IsNullOrEmpty($PSModulePath)) {$strThisModuleName} else {$PSModulePath,$strThisModuleName -join "\"}
			## import module, check for how long it takes
			$tspTmp = Measure-Command {$arrPSModuleInfo = Import-Module -Name $strModuleToImport -PassThru}
			$oThisPSModuleInfo = $arrPSModuleInfo | Where-Object {$_.Name -eq $strThisModuleName}
			dWrite-LogEntry $("imported module '{0}' (version '{1}'). Time taken to do so: '{2}'" -f $oThisPSModuleInfo.Name, $oThisPSModuleInfo.Version.ToString(), $(dGet-TimespanString $tspTmp -outputUnit auto)) -foreground DarkGreen
		} ## end else
	} ## end foreach-object
} ## end function


function dImport-Cred {
	<#	.Description
		Function to import PSCredential from XML file with encrypted PSCredential, with some error checking around the process
		Leverages other helper functions hImport-PSCredential and dWrite-LogEntry
		.Outputs
		PSCredential or $null (if issue importing)
	#>
	param(
		## filespec for the XML file containing the encrypted PSCredentials
		[parameter(Mandatory=$true)][string]$CredXmlFilespec_str,
		## brief description of the credential being imported (for use with output/logging); will have the "for " prepended for consumption by this function
		[string]$CredDescription_str
	) ## end param

	$strCredDesc = if ($CredDescription_str -ne $null) {"for '$($CredDescription_str.Trim())' "} else {""}
	## if the credentials XML file exists, continue
	if (Test-Path $CredXmlFilespec_str) {
		## import previously exported credential
		$credImported = hImport-PSCredential $CredXmlFilespec_str

		## log results of cred import (at this point, $credImported is either a PSCredential object or $null)
		if ($credImported -is [System.Management.Automation.PSCredential]) {dWrite-LogEntry "Imported credential ${strCredDesc}(UserName '$($credImported.UserName)')" -foreground DarkGreen}
		else {dWrite-LogEntry "[Problem] Credential import of '$CredXmlFilespec_str' ${strCredDesc}did not result in a PSCredential object!" -foreground Yellow} ## end else
	} ## end if
	## else, log it and do something
    else {
    	$credImported = $null
		dWrite-LogEntry "[Problem] XML file for credential import not found at '$CredXmlFilespec_str'" -foreground Yellow
    } ## end else

	## return the result of the credential import (either PSCredential or $null)
    return $credImported
} ## end function


## from the Invoke-VIEventMonitor function at http://www.lucd.info/2010/10/08/nearly-real-time-monitoring/
## uses custom function dGet-TimespanString, and uses dWrite-LogEntry instead of Write-Host; if using this monitoring function elsewhere, need to define that function, or switch to use Write-Host
function dInvoke-VICustomizationEventMonitor {
	<#	.Description
		Function to monitor vSphere OSCustomization events, gather matching events, and determine info about success/failure
		.Example
		Invoke-VIEventMonitor -Finish (Get-Date).AddMinutes(5) -Pause 5 -Entity $myVM0
		.Outputs
		System.Boolean as to whether OSCustomization succeeded before monitoring finished (did VMware.Vim.CustomizationSucceeded occur)
	#>

	param(
		## Specify the vSphere object for which you want to see events. The function will also show all events for the children of the entity. If this parameter is not used, the function will display the events for all the vSphere objects
		[VMware.VimAutomation.ViCore.Impl.V1.Inventory.InventoryItemImpl]$Entity = $null,
		## The datetime back to which to go for events for monitoring. If not specified, then, "events are collected from the earliest time in the database"
		[DateTime]$Start,
		## The datetime when the monitoring has to stop. The default is 2 minutes from the start of the monitoring
		[DateTime]$Finish = (Get-Date).AddMinutes(2),
		## The time (in seconds) between two successive reads from the collector. The default is 2 seconds
		[int]$pauseSec_int = 2,
		## Switch -- if this is present, show the details of each event observed
		[switch]$ShowEventDetail,
		## datetime formatting string to use for logging/output messages, if desired
		[string]$DatetimeFormat = "ddd dd MMM yyyy, HH:mm:ss"
	) ## end param

	process {
		## number of new events to get in each iteration
		Set-Variable -Name ViewSize -Value 1000 -Option ReadOnly

		## get EventManager .Net view object, to be used for creating events collector
		$eventMgr = Get-View 'EventManager'
		$specEventFilter = New-Object -Type VMware.Vim.EventFilterSpec -Property @{
			disableFullMessage = $false
			time = New-Object -Type VMware.Vim.EventFilterSpecByTime -Property @{
				beginTime = if ($PSBoundParameters.ContainsKey("Start")) {$Start} else {$null}
				endTime = $Finish
			} ## end new-object
		} ## end new-object
		## if entity was specified as a param to this function, add its MoRef to the eventFilter spec
		if($Entity){
			$specEventFilter.entity = New-Object -Type VMware.Vim.EventFilterSpecByEntity -Property @{
				entity = $Entity.Extensiondata.MoRef
				recursion = "all"
			} ## end new-object
		} ## end if

		## create the events collector .Net view object
		$viewEventsCollector = Get-View ($eventMgr.CreateCollectorForEvents($specEventFilter))

		## bool -- has the CustomizationStartedEvent been observed yet?
		$bCustHasBegun = $false

		dWrite-LogEntry ("OSCust events monitoring:  will consider events back to '{0}'" -f $(if ($PSBoundParameters.ContainsKey("Start")) {$Start.ToString($DatetimeFormat)} else {"the earliest time in the events database"}))
		dWrite-LogEntry "Starting monitoring for OSCustomization events.  Ending at '$($Finish.ToString($DatetimeFormat))', and using '$pauseSec_int' second pause interval"
		## while it is not yet the endTime for the monitoring, and the OSCustomization has not ended (either succeeded or failed), continue to monitor events
		while (((Get-Date) -lt $specEventFilter.time.endTime) -and (-not $bCustIsOver)) {
			$arrNewEvents = $viewEventsCollector.ReadNextEvents($ViewSize)
			## write out the FullFormattedMessage for each new event
			if ($ShowEventDetail) {$arrNewEvents | Foreach-Object {Write-Verbose -Verbose $_.CreatedTime $_.GetType().Name $_.FullFormattedMessage}} ## end if
			## if customization has not begun, check for a CustomizationStartedEvent
			if (-not $bCustHasBegun) {
				if (($arrNewEvents | Where-Object {$_ -is [VMware.Vim.CustomizationStartedEvent]} | Measure-Object).Count -gt 0) {
					## grab this "cust started" event (should be but one, but getting "most recent" to be sure)
					$oCustStartedEvent = $arrNewEvents | Where-Object {$_ -is [VMware.Vim.CustomizationStartedEvent]} | Sort-Object CreatedTime | Select-Object -Last 1
					dWrite-LogEntry "OS customization has begun - started at '$($oCustStartedEvent.CreatedTime.ToLocalTime().ToString($DatetimeFormat))'" -foreground DarkGreen
					$bCustHasBegun = $true; $dteCustBegan = $oCustStartedEvent.CreatedTime.ToLocalTime()
				}
			}
			## if customization has begun, check for success/failure events
			if ($bCustHasBegun) {
				if (($arrNewEvents | Where-Object {$_ -is [VMware.Vim.CustomizationFailed]} | Measure-Object).Count -gt 0) {dWrite-LogEntry "OS customization failed." -foreground red; $bCustIsOver = $true; $bCustFailed = $true; $dteCustStopped = Get-Date}
				else {
					if (($arrNewEvents | Where-Object {$_ -is [VMware.Vim.CustomizationSucceeded]} | Measure-Object).Count -gt 0) {
						## grab this "cust succeeded" event (should be but one, but getting "most recent" to be sure)
						$oCustSucceededEvent = $arrNewEvents | Where-Object {$_ -is [VMware.Vim.CustomizationSucceeded]} | Sort-Object CreatedTime | Select-Object -Last 1
						dWrite-LogEntry "OS customization succeeded!! Event from '$($oCustSucceededEvent.CreatedTime.ToLocalTime().ToString($DatetimeFormat))'" -foreground DarkGreen
						$bCustIsOver = $true; $bCustSucceeded = $true; $dteCustStopped = $oCustSucceededEvent.CreatedTime.ToLocalTime()
					}
				}
			} ## end if

			if (-not $bCustIsOver) {Start-Sleep -Seconds $pauseSec_int}
		} ## end while

		## cleanup
		$viewEventsCollector.DestroyCollector()

		## return informational object
		New-Object -Type PSObject -Property @{
			CustIsOver = $bCustIsOver
			dteCustBegan = $dteCustBegan
			dteCustStopped = $dteCustStopped
			OSCustomizationSucceeded = $(if ($bCustSucceeded) {$true} else {$false})
		} ## end new-object
	} ## end process
} ## end fn


function dExit-Gracefully {
	<#  .Description
		Function to clean up things before exit -- disconnect from vCenter server (if connected), write some log entries, stop the transcript.
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), $vcConnectedVCenter, dGet-TimespanString(), $dteScriptStart, $WhatIf_sw, $strLogFileClosingEntry, $hshThisRunInfo, dWrite-ObjectToTableString(), $hshCfgItems
	#>
	param (
		## message to add to logging before exiting
		[string]$ExitMessage_str
	) ## end param
	## if an exit message was specified, write it to log file
	if ($ExitMessage_str) {dWrite-LogEntry $ExitMessage_str}
	if ($vcConnectedVCenter.IsConnected -eq $true) {
		dWrite-LogEntry "disconnecting from vCenter '$($vcConnectedVCenter.Name)'"
		Disconnect-VIServer -Server $vcConnectedVCenter -Confirm:$false
	} else {dWrite-LogEntry "not connected to vCenter -- not attempting to disconnect"}
	$tspScriptRunDuration = (Get-Date).Subtract($dteScriptStart); if ($hshThisRunInfo) {$hshThisRunInfo['tspThisRun'] = $tspScriptRunDuration}
	dWrite-LogEntry $("script run duration: '{0}'" -f (dGet-TimespanString $tspScriptRunDuration -outputUnit auto))
	if ($WhatIf_sw -eq $true) {dWrite-LogEntry "This ran in WhatIf mode -- no VM actions were taken" -foreground White}
	dWrite-LogEntry "some general info about this run:$(dWrite-ObjectToTableString -Object $hshThisRunInfo)"
	$hshThisRunInfo | ConvertTo-Json -Depth 10 | Set-Content -Encoding Ascii -Path ($strStatsJsonOutputFilespec = "{0}\{1}_{2}_{3}.json" -f $hshCfgItems["strStatsDirFilespec"], $hshThisRunInfo["VMName"], $hshThisRunInfo["VMAction"], (Get-Date -Format FileDateTime))
	dWrite-LogEntry "Wrote stats info at '$strStatsJsonOutputFilespec'"
	if ($strLogFileClosingEntry -ne $null) {dWrite-LogEntry $strLogFileClosingEntry -foreground DarkGreen}	## write a closing entry to the log file, if the given variable is not null (variable should be defined in some parent scope)
	## stop recording the PowerShell session actions
	Stop-Transcript
	exit
} ## end fn


function dSend-StatusToURL {
	<#	.Description
		Function to send a status (and, optionally, a message) to the given URL
	#>
	param (
		## URL to which to send info; assumes that the URI is ready to have data posted to it
		[parameter(Mandatory=$true)][System.Uri]$Uri,
		## Status name to send
		[parameter(Mandatory=$true)][ValidateSet("Accepted", "Working", "Complete", "Error", "5", "6", "7")][string]$Status,
		## Message to send, if any
		[string]$Message
	) ## end param

	## intercept/"heist" from Mar 2022 to send errors and the likes to the status listener in old Lilly Cloud, regardless of the StatusUrl provided by the caller of this vmDeploy invocation:
	<# the psuedo code for the logic
		$oStatuUrlToUse = if ($Status -in (ack, working, complete)) {received StatusURL}
		else {
			if ($Uri -notmatch </cgi-bin/status.pl listener URL pattern>) {vmD-env-specific TOLC status.pl destination, with "id=####&status=" at end, adding later in the normal dSend-Status code the message querystring param}
			else {received StatusURL}
		}
	#>
	## if this is an (accepted, working, complete) status, or the URI is already the "old" status listener URL, just use the $Uri passed in
	$oBaseStatusUri_fromHeist = if (($Status -in ("Accepted", "Working", "Complete")) -or ($Uri.AbsoluteUri -match [System.Text.RegularExpressions.Regex]::Escape("/cgi-bin/status.pl?id="))) {$Uri}
	# else, the status is not ack/working/complete, and the status URI is LCS-style like "https://cloud.lilly.com/api/status/vm-deploy?id=8546" (is not the status.pl listeren style), override the "$Uri with some specified "old Lilly Cloud" URL
	else {
		## vmD-env-specific TOLC status.pl destination, with "id=####&status=" at end, adding later in the normal dSend-StatusToUrl function code the message querystring param
		#  this gets the Id value from the LCS-style statusURL: '.Query.Trim("?").Split("&") | ConvertFrom-StringData' gets some hashtables, and the rest gets the .Id key's value
		[System.Uri]($strStatusUrlOverrideForErrorMessages -f ($Uri.Query.Trim("?").Split("&") | ConvertFrom-StringData | Where-Object {$_.ContainsKey("Id")}).Id)
	}

	## is this the Old Style status (used by LillyCloud)?
	$bIsOldStatusStyle = $oBaseStatusUri_fromHeist.AbsoluteUri -match [System.Text.RegularExpressions.Regex]::Escape("/cgi-bin/status.pl?id=")

	## contents to use for the body of the get/post
	$hshContentsForBody = [ordered]@{}

	## method to use, and URI to use
	$strMethodForWebRequest, $oUriToUse = $(if ($bIsOldStatusStyle) {
			"Get"
			## Old Style: base URI plus the status integer
			$intStatusToUse = if ($Status -as [int]) {$Status} else {$hshCfgItems["hshOldStatusUpdateStates"][$Status]}
			## hackeroni at request of support team, seemingly to enable the "sweet" design of having no dev endpoints, only production, so needing to differntiate from where status update came
			$strVMDEnvironmentDisplay = if ($bIsRunningInProd) {"prod"} else {"non-prod"}
			if ($PSBoundParameters.ContainsKey("Message")) {if (-not ("System.Web.HttpUtility" -as [type])) {Add-Type -AssemblyName System.Web}; $strUriQueryStringToAdd = "&message=$([System.Web.HttpUtility]::UrlEncode($Message))"}
			"$oBaseStatusUri_fromHeist$intStatusToUse${strUriQueryStringToAdd}&env=$strVMDEnvironmentDisplay"
		}
		else {
			$hshContentsForBody["status"] = $Status
			## if there is a message to pass, add it to the body contents object
			if ($PSBoundParameters.ContainsKey("Message")) {$hshContentsForBody["message"] = $Message}
			"Post"
			$oBaseStatusUri_fromHeist
		} ## end else
	) ## end subexpression

	$hshParamForInvokeRestMethod = @{
		Uri = $oUriToUse
		Method = $strMethodForWebRequest
		Body = $(if ($hshContentsForBody.Count -gt 0) {$hshContentsForBody | ConvertTo-Json -Compress})
		ContentType = "application/json"
		Verbose = $true
	} ## end hsh
	dWrite-LogEntry "Using Uri value of: '$($hshParamForInvokeRestMethod.Uri)'"
	dWrite-LogEntry "Using Body value of: '$($hshParamForInvokeRestMethod.Body)'"

	if ($WhatIf_sw -eq $true) {
		dWrite-LogEntry "Would send status info to this URL: '$oUriToUse' (but, in WhatIf mode now)"
	} ## end if
	else {
		## Invoke the given REST method
		$oIRMResponse = Invoke-RestMethod @hshParamForInvokeRestMethod
		if ($bIsOldStatusStyle) {dWrite-LogEntry "Response from status URL: '$(($oIRMResponse.html.body | Out-String).TrimEnd())'"} else {dWrite-LogEntry "Response from status URL (as JSON): '$($oIRMResponse | ConvertTo-Json -Compress)'"}
	} ## end else
} ## end fn


function dCheck-Tools {
	<#	.Description
		Function to check a VM for VMware Tools status -- whether or not they are running.  Debug output also returns a bit more info about the tools state (running/installed/etc.)
		.Output
		String or Boolean (depending on the switch[es] specified. Using just "-booleanOutput_sw" switch causes only Boolean output
	#>
	param (
		## the name of the VM to check
		[parameter(ParameterSetName="ByVMName")][string]$VMNameWhoseToolsToCheck_str,
		## the ID of the VM to check
		[parameter(ParameterSetName="ByVMId")][string]$VMIdWhoseToolsToCheck_str,
		## switch indicating whether or not to return boolean output
		[switch]$booleanOutput_sw,
		## switch indicating whether or not to output debug info
		[switch]$debugInfo_sw
	) ## end param

	$viewVMToCheckForTools = Switch ($PsCmdlet.ParameterSetName) {
		"ByVMName" {Get-View -ViewType VirtualMachine -Property Name,Guest -Filter @{"Name" = "^${VMNameWhoseToolsToCheck_str}$"}; break}
		"ByVMId" {Get-View -Id $VMIdWhoseToolsToCheck_str -Property Name,Guest; break}
	} ## end switch

	if ($debugInfo_sw -eq $true) {dWrite-LogEntry $("Guest Tools info for '$($viewVMToCheckForTools.Name)':  Status(depr) = '{0}', RunningStatus = '{1}', VersionStatus2 = '{2}'" -f $viewVMToCheckForTools.Guest.ToolsStatus, $viewVMToCheckForTools.Guest.ToolsRunningStatus, $viewVMToCheckForTools.Guest.ToolsVersionStatus2)}

	## true if either ToolsRunningStatus -eq "guestToolsRunning" or "toolsOk","toolsOld" -contains ToolsStatus ("ToolsStatus" property is deprecated as API v5.1)
	$bToolsAreRunning = if (($viewVMToCheckForTools.Guest.ToolsRunningStatus -eq "guestToolsRunning") -or ("toolsOk","toolsOld" -contains $viewVMToCheckForTools.Guest.ToolsStatus)) {$true} else {$false}

	if ($booleanOutput_sw -eq $true) {return $bToolsAreRunning} ## end if
	else {$strFGColor = if ($bToolsAreRunning) {"DarkGreen"} else {"Yellow"}; dWrite-LogEntry -Foreground $strFGColor "VMware Tools running?  '$bToolsAreRunning'"}
} ## end fn


function dCheck-GuestOperationsAgent {
	<#	.Description
		Function to check a VM for Guest Operations agent status -- whether or not it is "ready.  Debug output also returns a bit more info about the Guest Operations agent state (ready/notready/etc.)
		.Output
		String or Boolean (depending on the switch[es] specified. Using just "-BooleanOutput" switch causes only Boolean output
	#>
	param (
		## The VM to check
		[parameter(Mandatory = $true)][VMware.VimAutomation.Types.VirtualMachine]$VM,
		## Switch indicating whether or not to return boolean-only output
		[switch]$BooleanOutput,
		## Switch indicating whether or not to output debug info
		[switch]$DebugInfo
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

	## update the View data for this property for the VM, so as to know the current value
	$VM.ExtensionData.UpdateViewData("Guest.GuestOperationsReady")

	if ($DebugInfo -eq $true) {dWrite-LogEntry $("$strLogEntry_ToAdd Guest Operations agent info for '$($VM.Name)': GuestOperationsReady = '$($VM.ExtensionData.Guest.GuestOperationsReady)'")}

	## GuestOperationsReady property is a boolean, but need not be set (http://pubs.vmware.com/vsphere-55/index.jsp#com.vmware.wssdk.apiref.doc/vim.vm.GuestInfo.html#guestOperationsReady)
	$bGuestOperationsAgentReady = $true -eq $VM.ExtensionData.Guest.GuestOperationsReady

	if ($BooleanOutput -eq $true) {return $bGuestOperationsAgentReady} ## end if
	else {$strFGColor = if ($bGuestOperationsAgentReady) {"DarkGreen"} else {"Yellow"}; dWrite-LogEntry -Foreground $strFGColor "$strLogEntry_ToAdd Guest Operations agent ready? '$bGuestOperationsAgentReady'"}
} ## end fn


function Wait-VMDVMGuestOperationsAgent {
	<#	.Description
		Function to wait for the Guest Operations agent to be "ready" for a VM.  Waits for given amount of time.
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), dGet-TimespanString()
		.Outputs
		PSObject with boolean:  did VM's Guest Operations agent reach "ready" state in given time period?, and timespan:  total wait timespan
	#>
	param (
		## The VM object for which to check/wait on the Guest Operations agent
		[parameter(Mandatory=$true)][VMware.VimAutomation.Types.VirtualMachine]$VM,
		## Number of minutes to wait for Guest Operations agent ot be ready; defaults to 5
		[float]$Minutes = 5,
		## Amount of time (in seconds) to wait between each check/update
		[int]$PauseSec = 15,
		## Datetime formatting string to use for logging/output messages, if desired
		[string]$DatetimeFormat = "ddd dd MMM yyyy, HH:mm:ss"
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

	## datetime of when starting the wait
	$dteStartWaitForGuestOpsAgent = Get-Date
	## datetime of when to stop the wait for the Guest Ops agent to be ready
	$dteEndWaitForGuestOpsAgent = $dteStartWaitForGuestOpsAgent.AddMinutes($Minutes)
	## "minute" or "minutes", depending on value of $Minutes; for proper output
	$strMinuteOrMinutes = "minute{0}" -f $(if (1 -ne $Minutes) {"s"})
	dWrite-LogEntry "$strLogEntry_ToAdd Starting monitoring for Guest Operations agent readiness.  Waiting up to '$Minutes' $strMinuteOrMinutes, ending at '$($dteEndWaitForGuestOpsAgent.ToString($DatetimeFormat))', and using '$PauseSec' second pause interval"
	## wait for the Guest Operations agent to be ready
	while ( (-not $($bGuestOpsAgentReachedReadyState = dCheck-GuestOperationsAgent -VM $VM -BooleanOutput; $bGuestOpsAgentReachedReadyState)) -and ((Get-Date) -lt $dteEndWaitForGuestOpsAgent)) {
		Start-Sleep -Seconds $PauseSec
	} ## end while

	$tspTotalWaitForGuestOpsAgent = (Get-Date).Subtract($dteStartWaitForGuestOpsAgent)
	if ($bGuestOpsAgentReachedReadyState) {
		dWrite-LogEntry $("$strLogEntry_ToAdd Oh, good -- VM Guest Operations agent reached ready state after waiting just '{0}'" -f $(dGet-TimespanString -TimeSpan $tspTotalWaitForGuestOpsAgent -outputUnit auto)) -foreground DarkGreen
	} ## end if
	else {dWrite-LogEntry "$strLogEntry_ToAdd [Warning] VM Guest Operations agent not ready after waiting '$Minutes' $strMinuteOrMinutes. Current GuestOperationsReady value: '$($VM.ExtensionData.UpdateViewData("Guest.GuestOperationsReady"); $VM.ExtensionData.Guest.GuestOperationsReady)'" -foreground Yellow} ## end else

	return (New-Object -Type PSObject -Property ([ordered]@{
		GuestOpsAgentReachedReadyState = $bGuestOpsAgentReachedReadyState
		TimeWaited = $tspTotalWaitForGuestOpsAgent
	}))
} ## end function


function dHandle-ErrorCatch {
	<#	.Description
		Function to take action when in the Catch script block of a Try/Catch statement. The pipeline object at this time will be the error object returned from the Try script block.  Use this function inside of the Catch script block
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), $_ (error object via the pipeline), $WhatIf_sw, $StatusUrl_str, dSend-StatusToURL(), $hshCfgItems, dExit-Gracefully
	#>
	param (
		## message to convey/relay to logs and Status URL if any
		[string]$MessageToConvey_str,
		## Switch:  is this in the WhatIf section of the execution? (if yes, the function will write warning and continue with WhatIf run, instead of updating Status URL and exiting gracefully)
		[switch]$InWhatIfSection_sw,
		## Switch:  send error message to StatusUrl? $true by default
		[switch]$SendStatusToUrl = $true,
		## Switch:  consider this a terminating error, and, so, exit gracefully? $false by default
		[switch]$ExitAltogether = $false
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

	## grab the message to be conveyed; will be appended to in certain cases
	$strMsgToConvey = $MessageToConvey_str

	$_	## pass the error through to the output (outputs full error, not just the .ToString() value of it; full error is used in troubleshooting)
	## write a log entry with the string representation of the error, too
	$strMsg_TheCaughtError = "The Message from the caught error: '$($_.Exception.Message.Trim())'`nThe caught error type: '$($_.Exception.GetType().FullName)'"
	## fi there is an InnerException, add a bit more info
	if ($null -ne $_.Exception.InnerException) {
		$strMsg_TheCaughtError += "`nThe Exception's InnerException type: '$($_.Exception.InnerException.GetType().FullName)'"
		## if there is a MethodFault on the inner exception, include some info about that
		if ($null -ne $_.Exception.InnerException.MethodFault) {$strMsg_TheCaughtError += "`nThe InnerException's MethodFault type: '$($_.Exception.InnerException.MethodFault.GetType().FullName)'"}
		else {$strMsg_TheCaughtError += "`nNo MethodFault from which to get more info for this InnerException -- adding no more output here"}
	} ## end if
	else {$strMsg_TheCaughtError += "`nNo InnerException from which to get more info for this Exception -- adding no more output here"}
	dWrite-LogEntry $strMsg_TheCaughtError -foreground Red

	## if this function was called in a portion of the executing script where it is still "WhatIf" territory (before creation of anything), and the executing script is running in WhatIf mode, just output some logging info and continue
	if (($InWhatIfSection_sw -eq $true) -and ($WhatIf_sw -eq $true)) {dWrite-LogEntry "$strMsgToConvey.  Would not continue if this was not a WhatIf run" -foreground Red}
	## else, this is not a WhatIf run; update status (if specified to do so) and exit
	else {
		## append a bit more to the message; still in WhatIf section of executing script (before any VM creation activities have taken place), but this is not a WhatIf run
		if ($InWhatIfSection_sw) {$strMsgToConvey += ".  Will not take action"}
		if ($StatusUrl_str -and $SendStatusToUrl) {
			Try {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message "$strMsgToConvey -- $strMsg_TheCaughtError"}
			catch {dWrite-LogEntry "$strLogEntry_ToAdd Issue trying to send message to provided Status URL '$StatusUrl_str'. Valid/reachable destination? Continuing (and, the error is shown below): `n${_}" -foreground Red}
		}
		if ($ExitAltogether) {
			## exit from the deployment script
			dExit-Gracefully $strMsgToConvey
		} ## end if
		## else, just write out the message that was specified to be conveyed
		else {dWrite-LogEntry $strMsgToConvey}
	} ## end else
} ## end function


function Send-CaughtStorageErrorInfo {
	<#	.Description
		Function to write some info out, usually when in the Catch script block of a Try/Catch statement, in storage-provisioning related code
		Existing variables/functions from parent scope used here:  dWrite-LogEntry()
	#>
	param (
		## message to convey/relay to logs
		[string]$MessageToConvey,
		## Hashtable or object with information to write to logs (say, information about the progress made during this execution)
		[PSObject]$InformationTable,
		## Error object, if any
		[PSObject]$ErrorObject
	) ## end param

	if (-not [String]::IsNullOrEmpty($MessageToConvey)) {dWrite-LogEntry $MessageToConvey}
	## write a log entry with the string representation of the error
	if ($PsBoundParameters.ContainsKey("ErrorObject")) {dWrite-LogEntry "The caught error: '$ErrorObject'" -Foreground Red}
	## write "run info" for this run so far
	if ($PsBoundParameters.ContainsKey("InformationTable")) {dWrite-LogEntry "some general info about this run:$(dWrite-ObjectToTableString -Object $InformationTable)"}
} ## end function


function dGet-TimespanString {
	<#	.Description
		Function to return a nice time span string for logging/output
		Existing variables/functions from parent scope used here:  none
	#>
	param (
		## timespan for which to get/give some output
		[parameter(Mandatory=$true)][System.TimeSpan]$TimeSpan_tsp,
		## display output in hours, minutes, seconds, or auto-select?  valid values:  'hr', 'min', 'sec', 'auto'; default value is "auto"
		[string][ValidateSet('hours','minutes','seconds','auto')]$outputUnit_str = "auto",
		## number of decimal places to which to round the value; default value is 2
		[int]$numDecimalPlaces_int = 2
	) ## end param

	if ($outputUnit_str -eq "auto") {
		$strUnitPropertyName,$strUnitLabel = &{Switch ($TimeSpan_tsp.TotalSeconds) {
			## if less than 100 seconds, use the TotalSeconds property
			{$_ -lt 100} {"TotalSeconds", "seconds"; break}
			## if more than 100 seconds, but less than 90 minutes, use the TotalMinutes property
			{($_ -ge 100) -and ($_ -lt 5400)} {"TotalMinutes", "minutes"; break}
			## else, default to TotalHours
			default {"TotalHours", "hours"}
		}} ## end subexpression
	} ## end if
	else {
		$strUnitPropertyName = "Total${outputUnit_str}"
		$strUnitLabel = $outputUnit_str
	} ## end else

	return "{0:n$numDecimalPlaces_int} $strUnitLabel" -f [Math]::Round($TimeSpan_tsp.$strUnitPropertyName, $numDecimalPlaces_int)
} ## end function


function dGet-GcrsVM {
	<#	.Description
		Function to get particular VM(s) by VM object name that also has the given GCRS Request ID in its notes field, or that has given Config.Uuid value.  For RequestID, this assumes that the RequestID is held in the Annotation property of the VM as created by vmDeploy as requested by GCRS
		.Outputs
		VirtualMachineImpl or $null
	#>
	[CmdletBinding()]
	param (
		## name of VM object to retrieve
		[parameter(Mandatory=$true)][string]$VMObjName_str,
		## GCRS Request ID of VM (as found in the Notes property of VMs)
		[parameter(Mandatory=$true,ParameterSetName="ByGcrsReqId")][alias("ReqId")][int]$GCRSReqId_int,
		## GCRS Request ID of VM (as found in the Notes property of VMs)
		[parameter(Mandatory=$true,ParameterSetName="ByVmUUID")][System.Guid]$UUID
	) ## end param

	process {
		$hshParamsForGetView = @{
			ViewType = "VirtualMachine"
			Property = "Name","Config.Annotation"
			Filter = @{"Name" = "^${VMObjName_str}$"}
		} ## end hashtable
		## using Get-View -- far faster than using Get-VM with VM name (about 6-8x faster than Get-VM in 4000+ VM environment -- ~2s vs. ~16s)
		#   and, this is using Where-Object with the Config.Annotation -match comparison instead of having that in the Get-View filter, as the former is about 3x faster (gets VMs matching the name, then, of those, the ones w/ Config.Annotation that matches)
		$arrMatchingVMViews = Switch ($PsCmdlet.ParameterSetName) {
			"ByGcrsReqId" {Get-View @hshParamsForGetView | Where-Object {$_.Config.Annotation -match "^.+\nrequest id:[\s]?${GCRSReqId_int}\n"}}
			"ByVmUUID" {$hshParamsForGetView["Filter"]["Config.Uuid"] = $UUID.Guid; Get-View @hshParamsForGetView}
		} ## end switch
		return $(if ($arrMatchingVMViews -eq $null) {$null} else {$arrMatchingVMViews | Foreach-Object {Get-VM -Id $_.MoRef}})
	} ## end process
} ## end function


function dWait-VMPowerstate {
	<#	.Description
		Function to wait for a VM to enter the given power state.  Waits for given amount of time.
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), dGet-TimespanString()
		.Outputs
		boolean:  did VM reach specified power state in given time period?
	#>
	param (
		## the VM object for which to check/wait on the powerstate
		[parameter(Mandatory=$true)]$VM_obj,
		## the powerstate to wait for; currently valid values for this enum:  PoweredOff, PoweredOn, Suspended
		[parameter(Mandatory=$true)][ValidateSet('PoweredOff','PoweredOn','Suspended')][string]$PowerState_str,
		## the number of minutes to wait for given powerstate; defaults to 5
		[float]$WaitMinutes_flt = 5,
		## amount of time (in seconds) to wait between each powerstate check/update
		[int]$pauseSec_int = 2,
		## datetime formatting string to use for logging/output messages, if desired
		[string]$datetimeFormat_str = "ddd dd MMM yyyy, HH:mm:ss"
	) ## end param

	## datetime of when starting the wait
	$dteStartWaitForPowerstate = Get-Date
	## datetime of when to stop the wait for the given VM powerstate
	$dteEndWaitForPowerstate = $dteStartWaitForPowerstate.AddMinutes($WaitMinutes_flt)
	## "minute" or "minutes", depending on value of $WaitMinutes_flt; for proper output
	$strMinuteOrMinutes = "minute{0}" -f $(if (1 -ne $WaitMinutes_flt) {"s"})
	dWrite-LogEntry "Starting monitoring for powerstate to go to '$PowerState_str'.  Waiting '$WaitMinutes_flt' $strMinuteOrMinutes, ending at '$($dteEndWaitForPowerstate.ToString($datetimeFormat_str))', and using '$pauseSec_int' second pause interval"
	## wait for the guest OS shutdown
	while ( ($VM_obj.ExtensionData.Runtime.PowerState -ne $PowerState_str) -and ((Get-Date) -lt $dteEndWaitForPowerstate) ) {
		Start-Sleep -Seconds $pauseSec_int
		## update the View data for the Runtime.PowerState property of the VM
		$VM_obj.ExtensionData.UpdateViewData("Runtime.PowerState")
	} ## end while

	$bDesiredPowerstateReached = if ($VM_obj.ExtensionData.Runtime.PowerState -eq $PowerState_str) {
		dWrite-LogEntry $("Oh, good -- VM power state reached '$PowerState_str' after just '{0}'" -f $(dGet-TimespanString -TimeSpan ((Get-Date).Subtract($dteStartWaitForPowerstate)) -outputUnit auto)) -foreground DarkGreen
		$true} ## end if
	else {dWrite-LogEntry "[Warning] VM did not reach power state '$PowerState_str' after waiting '$WaitMinutes_flt' $strMinuteOrMinutes. Current VM power state: '$($VM_obj.ExtensionData.Runtime.PowerState)'" -foreground Yellow
		$false} ## end else

	return $bDesiredPowerstateReached
} ## end function


function dStop-VM {
	<#	.Description
		Function to stop a VM non-gracefully (power-off, not a shutdown). Runs synchronously.
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), dHandle-ErrorCatch()
		.Outputs
		Zero or more powered-off VirtualMachine objects, or a graceful
	#>
	param (
		## the VM object for which to check/wait on the powerstate
		[parameter(Mandatory=$true)]$VM_obj
	) ## end param

	dWrite-LogEntry -Entry "Stopping VM '$($VM_obj.Name)' (ID '$($VM_obj.Id)')"
	try {$script:vmPoweredOff = Stop-VM -VM $VM_obj -Confirm:$false -ErrorAction:Stop}
	catch {
		## error message to pass on to the Catch handler
		$strMsgErrorStoppingVM = "[Error] encountered an error trying to issue Stop (powerOff) command to VM '$($VM_obj.Name)'"
		dHandle-ErrorCatch -MessageToConvey $strMsgErrorStoppingVM -ExitAltogether:$true
	} ## end catch

	return $script:vmPoweredOff
} ## end function


function dRemove-VM {
	<#	.Description
		Function to remove a VM, deleting from disk.  Assumes that VM is already poweredOff
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(), dHandle-ErrorCatch()
		.Outputs
		Boolean:  did Remove succeed (only one entity found to start with, and does entity by Id of given VM no longer exist after Remove-VM call)?
	#>
	param (
		## the VM object for which to check/wait on the powerstate
		[parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM_obj
	) ## end param

	## double-check:  Get-View of entities with this object's MoRef
	$intNumMatchingEntities = (Get-View -Property Name -Id $VM_obj.Id -ErrorAction:SilentlyContinue | Measure-Object).Count
	## if exactly one (1) entity is found with this object's ID (MoRef), good; else, do not try to delete item (either 0 or 2+ items returned)
	if ($intNumMatchingEntities -eq 1) {
		dWrite-LogEntry "Good:  double-check of entities matching '$($VM_obj.Id)' resulted in exactly one (1) item"
		dWrite-LogEntry "Deleting VM '$($VM_obj.Name)' (ID '$($VM_obj.Id)')"
		try {Remove-VM -VM $VM_obj -DeleteFromDisk -Confirm:$false -ErrorAction:Stop}
		catch {
			## error message to pass on to the Catch handler
			$strMsgErrorDeletingVM = "[Error] encountered an error when issuing Remove command on VM '$($VM_obj.Name)'"
			dHandle-ErrorCatch -MessageToConvey $strMsgErrorDeletingVM -ExitAltogether:$true
		} ## end catch

		## does Get-View of entity with the ID of the VM that was passed in (the VM to be deleted from disk) return $null? (signifying that delete succeeded (or that no entity of that ID existed to start with))
		$Private:bVMDeleteSucceeded = $null -eq (Get-View -Property Name -Id $VM_obj.Id -ErrorAction:SilentlyContinue)
	} ## end if
	else {$Private:bVMDeleteSucceeded = $false; dWrite-LogEntry "[Problem] double-check of entities matching '$($VM_obj.Id)' did not yield exactly one (1) item (returned '$intNumMatchingEntities' items)"}

	return $Private:bVMDeleteSucceeded
} ## end function


function Get-TemplateToUse_VCLocAware {
<#	.Description
	Function to get a template of given name, with preference being the given cluster
		-if no matching template in entire vCenter, error
		-if matching template found on host in given cluster, return that template
		-if none in given cluster, if cluster is in an inventory folder (other than default "host" inventory folder), check other clusters in this cluster's parent inventory folder
		-if none in given cluster's parent inventory folder, check in cluster's virtual datacenter
		-if none in cluster's virtual datacenter, check in default virtual datacenter specified (or config'd)
		-if none in default virtual datacenter specified, return random template of all the matching templates in this vCenter
	Requires (in parent script) adding default datacenter for each template in a vCenter (or all templates?)
	Uses external function dWrite-LogEntry(); Jan 2014
	.Outputs
	One or more TemplateImpl, or error if none found matching given template name or if invalid default datacenter given
#>
	param(
		## Complete name of template to retrieve (no wildcarding)
		[parameter(Mandatory=$true)][string]$TemplateName,

		## Cluster in which to look for template (cluster object)
		[parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.Cluster]$Cluster,

		## Default datacenter in which the source template resides (to return in case there is no matching template in this cluster/datacenter)
		[parameter(Mandatory=$true)][string]$DatacenterOfDefaultTemplate
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

	## get all the templates that match given name
	$arrTemplatesMatchingName = Get-Template -Name $TemplateName -ErrorAction:SilentlyContinue
	## if no matching templates based on name, return last error, which should be the "Template with name 'mehh' was not found using the specified filter..." error
	if (($arrTemplatesMatchingName | Measure-Object).Count -eq 0) {dWrite-LogEntry "[Problem] $strLogEntry_ToAdd no templates of name '$TemplateName' found"; Throw $Error[0]}

	## name of specified cluster in which to look for template
	$strNameOfSpecifiedClusterInWhichToLook = $Cluster.Name
	## for given cases, if true, output the corresponding values and break out of the Switch statement
	$oTemplateToUse,$strTemplateSelectionMsg = Switch ($true) {
		## if one of the matching templates is on a host in the cluster in which to look, great -- use it
		#   using "New-Variable" in the expression portion so as to be able to specify "parent scope" ("1"), so that variable is accessible by the corresponding scriptblock for this case; by default, "The expression is evaluated in its own scope"; did not use "script" scope, as that perists outside of just the function
		#   using .ExtensionData.Runtime.Host instead of .HostId as the latter does not seem to be a member available to PowerShell v2 template objects (bug in VMware PSSnapin?)
		{New-Variable -Name oTemplateInThisCluster -Scope 1 -Value ($arrTemplatesMatchingName | Where-Object {$Cluster.ExtensionData.Host -contains $_.ExtensionData.Runtime.Host})
		$oTemplateInThisCluster} {
			$oTemplateInThisCluster,"nice, found template in specified destination cluster ('$strNameOfSpecifiedClusterInWhichToLook')"; break} ## end case

		## if cluster is in an inventory folder (other than default inventory folder named "host"), check other clusters in this cluster's inventory folder for the template
		{
			if ($Cluster.ParentFolder.Name -ne "host") {
				$arrMoRefsOfHostsInThisClusterInventoryFolder = Get-View -ViewType HostSystem -Property Name -SearchRoot (Get-Folder -Id $Cluster.ParentId).Id | Foreach-Object {$_.MoRef}
				New-Variable -Name oTemplateInThisClusterInventoryFolder -Scope 1 -Value ($arrTemplatesMatchingName | Where-Object {$arrMoRefsOfHostsInThisClusterInventoryFolder -contains $_.ExtensionData.Runtime.Host})
				$oTemplateInThisClusterInventoryFolder
			}
		} {
			$oTemplateInThisClusterInventoryFolder,"ok, no template in destination cluster ('$strNameOfSpecifiedClusterInWhichToLook'), but found one in different cluster in destination cluster's parent inventory folder ('$($Cluster.ParentFolder)')"
			break
		} ## end case

		## if one of the matching templates is on a host in the datacenter of the cluster in which to look, great -- use it
		{$arrMoRefsOfHostsInThisDCenter = Get-View -ViewType HostSystem -Property Name -SearchRoot (Get-Datacenter -Cluster $Cluster).Id | Foreach-Object {$_.MoRef}
		New-Variable -Name oTemplateInThisDCenter -Scope 1 -Value ($arrTemplatesMatchingName | Where-Object {$arrMoRefsOfHostsInThisDCenter -contains $_.ExtensionData.Runtime.Host})
		$oTemplateInThisDCenter} {
			$oTemplateInThisDCenter,"ok, no template in destination cluster ('$strNameOfSpecifiedClusterInWhichToLook'), but found one in different cluster in same destination vDatacenter"
			break} ## end case

		## if one of the matching templates is in the default datacenter specified, great -- use it
		{$oDefaultDCenter = Get-DataCenter -Name $DatacenterOfDefaultTemplate -ErrorAction:SilentlyContinue
		if (-not $oDefaultDCenter) {dWrite-LogEntry "[Problem] $strLogEntry_ToAdd no default datacenter of name '$DatacenterOfDefaultTemplate' found"; Throw $Error[0]}
		New-Variable -Name oTemplateInDefaultDCenter -Scope 1 -Value ($arrTemplatesMatchingName | Where-Object {(Get-View -ViewType HostSystem -Property Name -SearchRoot $oDefaultDCenter.Id | Foreach-Object {$_.MoRef}) -contains  $_.ExtensionData.Runtime.Host})
		$oTemplateInDefaultDCenter} {
			$oTemplateInDefaultDCenter,"ok, no template in destination cluster ('$strNameOfSpecifiedClusterInWhichToLook') or its vDatacenter, but found one in default vDatacenter '$DatacenterOfDefaultTemplate'"
			break} ## end case

		## if none of the above, use a random one of the template(s) that did match by name
		default {($arrTemplatesMatchingName | Get-Random),"alright, no template in destination cluster ('$strNameOfSpecifiedClusterInWhichToLook'), its vDatacenter, or in default vDatacenter; using one of the templates found by given name"}
	} ## end switch

	## write a log entry, return the template object that shall be used
	dWrite-LogEntry "$strLogEntry_ToAdd $strTemplateSelectionMsg"
	## return template to use (possibly multiple if templates exist of given name in given (cluster|siblingClusterPerInventoryFolder|sameDCenter|defaultDCenter))
	return $oTemplateToUse
} ## end function


function dWrite-ObjectToTableString {
	<#	.Description
		Function to write an object (like, say, a hashtable) out to a log-friendly string, trimming the whitespace off of the end of each line
	#>
	param (
		[parameter(Mandatory=$true)][PSObject]$ObjectToStringify,
		## Switch: wrap values in table output? Default is $true
		[Switch]$Wrap = $true
	)
	$hshParamsForFormatTable = @{AutoSize = $true; Wrap = $Wrap}
	## temporarily set the FormatEnumerationLimit preference variable (and, currently must change this pref var in global scope as reported across the interweb) to allow for enumerating all values in a property
	$intOrigFormatEnumLimit = $global:FormatEnumerationLimit; $global:FormatEnumerationLimit = -1
	$strToReturn = ( ($ObjectToStringify | Format-Table @hshParamsForFormatTable | Out-String -Stream | Foreach-Object {$_.TrimEnd()} | Where-Object {-not [System.String]::IsNullOrEmpty($_)}) ).TrimEnd() -join "`n"
	$global:FormatEnumerationLimit = $intOrigFormatEnumLimit
	return "`n${strToReturn}`n"
} ## end function


## functions for getting ADSubnet and related info
function ConvertTo-DecimalIP {
	<#  .Description
		Function to convert a Decimal IP address into a 32-bit unsigned integer. Takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
		Helper for other network "math" functions. Originally from http://www.indented.co.uk/2010/01/23/powershell-subnet-math/
		.Outputs
		System.UInt32
	#>
	[CmdletBinding()]
	param(
		## An IP Address to convert
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][Net.IPAddress]$IPAddress
	)

	process {
		$i = 3; $DecimalIP = 0;
		$IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }
		return [UInt32]$DecimalIP
	} ## end process
} ## end fn


function ConvertTo-DottedDecimalIP {
	<#  .Description
		Function to return a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.  Uses a regular expression match on the input string to convert to an IP address
		Originally from http://www.indented.co.uk/2010/01/23/powershell-subnet-math/
		.Outputs
		String
	#>
	[CmdletBinding()]
	param(
		## A string representation of an IP address from either UInt32 or dotted binary
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][String]$IPAddress_str
	)

	process {
		Switch -RegEx ($IPAddress_str) {
			"([01]{8}.){3}[01]{8}" {return [String]::Join('.', $( $IPAddress_str.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))}
			"\d" {
				$intIPAddress = [UInt32]$IPAddress_str
				## get the IP octets for the address
				$arrDottedIpOctets = $( For ($i = 3; $i -gt -1; $i--) {
					$intRemainder = $intIPAddress % [Math]::Pow(256, $i)
					($intIPAddress - $intRemainder) / [Math]::Pow(256, $i)
					$intIPAddress = $intRemainder
				} )
				return [String]::Join('.', $arrDottedIpOctets)
			} ## end case
			default {Write-Error "Cannot convert this format"}
		} ## end switch
	} ## end process
} ## end fn


function Get-SNMathNetworkAddress {
	<#  .Description
		Function that takes an IP address and subnet mask then calculates the network address for the range.  Returns the network address for the subnet by performing a bitwise AND operation against the decimal forms of the IP address and subnet mask. This function expects both the IP address and subnet mask in dotted decimal format
		Existing variables/functions from parent scope used here:  ConvertTo-DottedDecimalIP(), ConvertTo-DecimalIP(); Originally from http://www.indented.co.uk/2010/01/23/powershell-subnet-math/
		.Outputs
		Net.IpAddress
	#>
	[CmdletBinding()]
	param(
		## Any IP address within the network range
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][Net.IPAddress]$IPAddress,
		## The subnet mask for the network
		[Parameter(Mandatory = $true, Position = 1)][Alias("Mask")][Net.IPAddress]$SubnetMask
	)

	process {return [Net.IpAddress](ConvertTo-DottedDecimalIP ((ConvertTo-DecimalIP $IPAddress) -band (ConvertTo-DecimalIP $SubnetMask)))}
} ## end fn


function ConvertTo-MaskPrefixLength {
	<#  .Description
		Function to get the length of a subnet mask. Accepts any IPv4 address as input, however the output value only makes sense when using a subnet mask
		.Outputs
		Int
	#>
	[CmdletBinding()]
	param(
		## A subnet mask to convert into mask prefix length
		[Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)][Alias("Mask")][Net.IPAddress]$SubnetMask
	)

	process {
		## get the address bytes, and convert them to binary; then, remove zeroes and whitespace, leaving just the ones (which should all be at the start of the binary number, as they are the masking bits, assuming that a legit subnet mask was passed)
		$strBits = "$( $SubnetMask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2) } )" -replace '[\s0]'
		return $strBits.Length
	} ## end process
} ## end fn


function Get-ADSSSubnet {
	<#	.Description
		Function to get an AD Subnet object (as defined in AD Sites and Services) by name (or, get all Subnets), and do so for the forest of the named domain (or, the forest of the default domain per the local computer if no DomainName is provided)
		Existing variables/functions from parent scope used here:  dWrite-LogEntry()
		.Outputs
		Zero or more System.DirectoryServices.ActiveDirectory.ActiveDirectorySubnet objects
	#>
	[CmdletBinding(DefaultParameterSetName="UseCurrentUser")]
	Param (
		## Name of subnet to retrieve, like "10.0.0.0/16". Accepts wildcards
		[ValidateNotNullOrEmpty()][string[]]$Name,
		## Name of the domain whose forest to check for subnet objects. If none specified, uses default domain per local computer (and, assumes "current user")
		[Parameter(Mandatory=$false, ParameterSetName="UseCurrentUser")][Parameter(Mandatory=$true, ParameterSetName="WithCredential")][string]$DomainInForest,
		## Credential to use when communicating with given domain and its forest (if none specified, this function queries as the current user)
		[Parameter(Mandatory=$true, ParameterSetName="WithCredential")][System.Management.Automation.PSCredential]$Credential
	)

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

		## make domain context constructor arguments (contextType, name, username, password)
		$arrArgsForGetContext_domain = @("Domain")
		if ($PSBoundParameters.ContainsKey("DomainInForest")) {$arrArgsForGetContext_domain += $DomainInForest}
		if ($PSBoundParameters.ContainsKey("Credential")) {$arrArgsForGetContext_domain += $Credential.UserName, $Credential.GetNetworkCredential().Password}
		## create the new domain DirectoryContext object, with which to get the domain object
		$oDomDirectoryContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($arrArgsForGetContext_domain)
		## get the domain object using the given domain DirectoryContext
		$oADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($oDomDirectoryContext)
	} ## end begin

	process {
		## for the day that multiple calls to Get-ADSSSubnet are expect (say, when "walking" up a line of network names to see if a "real" network is defined within some larger Subnet in AD), may need to employ the FindByName() method like below, if that is faster than getting all subnets and then doing a Where-Object:
		# $script:oForestDirContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest") ## use "forest name" (from $oDom.Forest.Name), and username/password if $Credential is specified, of course
		# $arrNamesOfSubnetsToGet | Foreach-Object {Write-Verbose "getting subnet '$_'"; [System.DirectoryServices.ActiveDirectory.ActiveDirectorySubnet]::FindByName($script:oForestDirContext, $_)}

		dWrite-LogEntry "$strLogEntry_ToAdd checking for Subnets in forest '$($oADDomain.Forest.Name)' (forest of domain '$($oADDomain.Name.ToLower())')"
		$arrAllSubnetsForForestOfThisDom = $oADDomain.Forest.Sites | Foreach-Object {$_.Subnets}
		## if $Name was specified, return just Subnet objects where their name is like the given name
		if ($PSBoundParameters.ContainsKey("Name")) {
			$Name | Foreach-Object {$strThisSubnetName = $_; $arrAllSubnetsForForestOfThisDom | Where-Object {$_.Name -like $strThisSubnetName}}
		}
		## else, just return them all
		else {$arrAllSubnetsForForestOfThisDom}
    } ## end process
} ## end fn


function Get-ADDCInfoForADSiteAndDomain {
	<#	.Description
		Function to get a domain controller for the given domain and at an AD Site, as determined by the AD Subnet in which the given guest IP/subnet resides.  If more than one DC is available for the site, just gets a random one of them whose name to return
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(); Apr 2014
		.Outputs
		PSCustomObject with info about the domain, domain controller, AD site, and address of the network used in determining the AD Subnet for which to look
	#>
	param (
		## the IP address of the guest OS, with which to determine the network address, the AD Subnet, and the AD site
		[parameter(Mandatory=$true)][ValidateScript({[bool][System.Net.IPAddress]::Parse($_)})]$GuestIPAddress_str,
		## the subnet mask of the guest OS, with which to determine the network address, the AD Subnet, and the AD site
		[parameter(Mandatory=$true)][ValidateScript({[bool][System.Net.IPAddress]::Parse($_)})]$GuestSubnetMask_str,
		## the name of the AD domain for which to look for services in the determined AD site
		[parameter(Mandatory=$true)][string]$DomainName_str,
		## Credential to use when communicating with given domain and its forest (if none specified, this function queries as the current user)
		[System.Management.Automation.PSCredential]$Credential
	) ## end param

	## string to add to log messages written by this function; function name in square brackets
	$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"

	## get address of the network for given IP address and subnet mask (for example, the network address of an IP/subnet of 40.150.77.74, 255.255.0.0 is 40.150.0.0)
	$oAddressForNetworkOfThisVMIP = Get-SNMathNetworkAddress -IPAddress $GuestIPAddress_str -SubnetMask $GuestSubnetMask_str
	## get mask prefix length from subnet mask (for example, the prefix length of subnet mask 255.255.0.0 is 16)
	$intMaskPrefixLengthOfThisVMSubnet = ConvertTo-MaskPrefixLength -SubnetMask $GuestSubnetMask_str
	## the CIDR notation of this network (which is what is used for Subnet names in AD Sites and Services)
	$strThisNetworkCidrAddr = "{0}/{1}" -f $oAddressForNetworkOfThisVMIP.ToString(), $intMaskPrefixLengthOfThisVMSubnet
	## get ADSubnet for given network address/MaskLength; should be a single item
	$hshParamsForGetADSSSubnet = @{Name = $strThisNetworkCidrAddr; DomainInForest = $DomainName_str}
	if ($PSBoundParameters.ContainsKey("Credential")) {$hshParamsForGetADSSSubnet["Credential"] = $Credential}
	$oADSubnet = Get-ADSSSubnet @hshParamsForGetADSSSubnet
	## get the domain controller in the specific site to use, if a corresponding Subnet is found, and the corresponding Site has a DC that services the given domain; else, use the domain itself
	$strDomOrDCToUse =
		## if there is one or more AD Subnet by this name
		if ($oADSubnet) {
			## if just one Subnet returned (should be, if any)
			if (($oADSubnet | Measure-Object).Count -eq 1) {
				dWrite-LogEntry "$strLogEntry_ToAdd one AD Subnet found matching name '$strThisNetworkCidrAddr'" -Foreground DarkGreen
				## see if this Site services the desired domain; that is, if there is a System.DirectoryServices.ActiveDirectory.Domain of desired dom name; store such a domain in a variable for later use
				$oADDomainForThisDom = $oADSubnet.Site.Domains | Where-Object {$_.Name -eq "$DomainName_str"}
				if ($oADDomainForThisDom) {
					## this Subnet's Site serves the given domain; yay
					dWrite-LogEntry "$strLogEntry_ToAdd great, this AD Subnet's AD Site ('$($oADSubnet.Site.Name)') deals with domain '$DomainName_str'" -Foreground DarkGreen
					$arrDomControllersForThisDomAtThisSite = $oADSubnet.Site.Servers | Where-Object {$_.Domain.Name -eq "$DomainName_str"}
					$intNumDCsForThisDomAtThisSite = ($arrDomControllersForThisDomAtThisSite | Measure-Object).Count
					## if there is at least one AD Server in this AD Site that serves the given AD Domain, super!
					if ($intNumDCsForThisDomAtThisSite -gt 0) {
						dWrite-LogEntry $("$strLogEntry_ToAdd excellent, AD site '{0}' has services for domain '{1}'. '$intNumDCsForThisDomAtThisSite' AD DC{2} in this site for this domain" -f $oADSubnet.Site.Name, $oADDomainForThisDom.Name, $(if ($intNumDCsForThisDomAtThisSite -ne 1) {'s'})) -Foreground DarkGreen
						## return name of one of the DomainControllers for this Site & domain
						($arrDomControllersForThisDomAtThisSite | Get-Random).Name
						$bFoundASpecificDCToUse = $true	## define a boolean to be used in determining if a specific DC was found for use
					} ## end if
					## else, no AD Server with property Domain.Name matching given domain name found in this AD Site -- will just use default domain name
					else {
						## did not find a suitable AD Server in this AD Site; return default domain service
						dWrite-LogEntry "$strLogEntry_ToAdd the AD Site '$($oADSubnet.Site.Name)' supposedly serves domain '$DomainName_str' (per its .Domains property), but none of the servers in the site have .Domain.Name property matching this domain name (something awry in AD?). Returning default of the domain '$DomainName_str'"; $DomainName_str
					} ## end else
				} ## end if
				else {
					## the site returned does not service the given domain; return default domain service
					dWrite-LogEntry "$strLogEntry_ToAdd the AD Site '$($oADSubnet.Site.Name)' does not have a domain controller for domain '$DomainName_str'. Returning default of the domain '$DomainName_str'"; $DomainName_str
				} ## end else
			} ## end if
			else {
				## more than one Subnet returned for this Subnet name -- 'check into this'; meanwhile, return default domain service; should not ever hit this, unless something is up with D
				dWrite-LogEntry "$strLogEntry_ToAdd more than one AD Subnet returned for name '$strThisNetworkCidrAddr'. Returning default of the domain '$DomainName_str'"; $DomainName_str
			} ## end else
		} ## end if
		else {dWrite-LogEntry "$strLogEntry_ToAdd since no AD Subnet named '$strThisNetworkCidrAddr' found, returning default of the domain '$DomainName_str'"; $DomainName_str}
	## then, return up to the caller the domain or domain controller to use
	if ($true -eq $bFoundASpecificDCToUse) {dWrite-LogEntry "$strLogEntry_ToAdd found DC '$strDomOrDCToUse' in AD site '$($oADSubnet.Site.Name)'" -Foreground DarkGreen}
	else {dWrite-LogEntry "$strLogEntry_ToAdd no specific DC found for network '$strThisNetworkCidrAddr'"}
	return New-Object -Type PSObject -Property @{
		Domain = $DomainName_str
		DomainControllerName = $(if ($true -eq $bFoundASpecificDCToUse) {$strDomOrDCToUse})
		ADSiteName = $oADSubnet.Site.Name
		NetworkAddressCidr = $strThisNetworkCidrAddr
		bFoundASpecificDCToUse = $(if ($true -eq $bFoundASpecificDCToUse) {$true} else {$false})
	} ## end new-object
} ## end function
## end of functions for getting ADSubnet and related info


function Get-StorageResourceToUse {
	<#	.Description
		Function to get a storage resource that is suitable to house a given amount of needed space
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(); Feb 2015
	#>
	[CmdletBinding(DefaultParameterSetName="Default")]
	param(
		## Name of storage resource (datatore or datastore cluster) to try to use
		[parameter(Mandatory=$true, ParameterSetName="ByStorageResourceName")][string]$Name,
		## Cluster in which this storage shall be used; used ClusterImpl as this object is already retrieved by the time this function is called. To generalize this function (if ever), should add OBN support here
		[VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl]$Cluster,
		## Size (GB) of freespace desired (including any "buffer" space to keep available)
		[parameter(Mandatory=$true, ParameterSetName="ByStorageResourceTier")][int]$SpaceNeededGB,
		## Regular Expression pattern of storage resources to exclude from consideration, if not specifying explicit name _to_ use via -Name
		[parameter(ParameterSetName="ByStorageResourceTier")][string]$StorageResourceNameToExclude,
		## Name of datastore cluster "tier" for which to look; like, "gold", "silver", etc.
		[parameter(ParameterSetName="ByStorageResourceTier")][string]$DSClusterTier
	)

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
		## tiers of storage to consider, in order of preference (for when trying to pick "most capable" datastore cluster tier if no tier was specified)
		$arrlTiersToConsider = [System.Collections.ArrayList]("gold","silver","bronze","brown")
	} ## end begin

	process {
		## if a datastore / datastore cluster name was passed, try to get such a storage entity
		if ($PsCmdlet.ParameterSetName -eq "ByStorageResourceName") {
			## try to get the datastore cluster of the name passed as a param
			$oStorageResourceToUse = Get-DatastoreCluster -Name $Name -ErrorAction:SilentlyContinue
			## if no datastore cluster, try to get the datastore of the name passed as a param
			if ($null -eq $oStorageResourceToUse) {$oStorageResourceToUse = Get-Datastore -Name $Name -RelatedObject $Cluster -ErrorAction:SilentlyContinue}
		} ## end if

		else {
			## if attempt to get the specified datastore did not return a datastore, or no specific datastore was passed, get one random datastore out of all available datastores that have _enough_ to serve the size needed
			if ($null -eq $oStorageResourceToUse) {
				## all the VMFS/vSAN datastores in this cluster
				$arrAllVmfsDStores_ThisCluster = Get-Datastore -Refresh -RelatedObject $Cluster | Where-Object {"VMFS","vSAN" -contains $_.Type}
				$arrAllDStoreClu_ThisCluster = Get-DatastoreCluster -Datastore $arrAllVmfsDStores_ThisCluster
				dWrite-LogEntry "$strLogEntry_ToAdd Num. datastore clusters in cluster '$($Cluster.Name)': '$(($arrAllDStoreClu_ThisCluster | Measure).Count)'"
				## try to get a datastore cluster to use (whose name does not match the "exclude" naming pattern, if any, and which has FreeSpaceGB -ge $SpaceNeededGB)
				$arrDStoreCluWEnoughFreeSpace_ThisCluster = $arrAllDStoreClu_ThisCluster | Where-Object {$(if ($PSBoundParameters.ContainsKey("StorageResourceNameToExclude")) {$_.Name -notmatch $StorageResourceNameToExclude} else {$true}) -and ($_.FreeSpaceGB -ge $SpaceNeededGB)}

				## if any datastore clusters found in this cluster (with sufficient freespace)
				if ($null -ne $arrDStoreCluWEnoughFreeSpace_ThisCluster) {
					## if a tier was specified, find if there are any matching datastore clusters with sufficient freespace; need to switch this up to Tags at some point, instead of relying on datastore cluster name
					if ($PSBoundParameters.ContainsKey("DSClusterTier")) {
						$arrTmp_ViableDStoreClu = $arrDStoreCluWEnoughFreeSpace_ThisCluster | Where-Object {$_.Name -match $DSClusterTier}
						if (($arrTmp_ViableDStoreClu | Measure-Object).Count -gt 0) {
							dWrite-LogEntry ("$strLogEntry_ToAdd Num. viable datastore clusters matching '$DSClusterTier': '$(($arrTmp_ViableDStoreClu | Measure-Object).Count)' ({0})" -f $(($arrTmp_ViableDStoreClu | Foreach-Object {"$($_.Name) has $([Math]::Round($_.FreeSpaceGB, 0))GB"}) -join ", "))
							$oStorageResourceToUse = $arrTmp_ViableDStoreClu | Get-Random
						} ## end if
						else {
							dWrite-LogEntry "$strLogEntry_ToAdd No viable datastore clusters matching tier '$DSClusterTier'"
						} ## end else
					} ## end if
					## else, go through the available datastore clusters and get the most capable
					else {
						## while the arraylist of tiers to consider still has more tiers, and a suitable storage resource has not been identified
						 while ($arrlTiersToConsider.Count -gt 0) {
							$strThisTierName = $arrlTiersToConsider[0]
							$arrTmp_ViableDStoreClu = $arrDStoreCluWEnoughFreeSpace_ThisCluster | Where-Object {$_.Name -match $strThisTierName}
							if ($null -ne $arrTmp_ViableDStoreClu) {
								dWrite-LogEntry ("$strLogEntry_ToAdd Num. viable datastore clusters (of tier '$strThisTierName', the highest viable found): '$(($arrTmp_ViableDStoreClu | Measure-Object).Count)' ({0})" -f $(($arrTmp_ViableDStoreClu | Foreach-Object {"$($_.Name) has $([Math]::Round($_.FreeSpaceGB, 0))GB"}) -join ", "))
								$oStorageResourceToUse = $arrTmp_ViableDStoreClu | Get-Random
								break
							} ## end if
							$arrlTiersToConsider.RemoveAt(0)
						} ## end while
					} ## end else
				} ## end if
				else {dWrite-LogEntry "$strLogEntry_ToAdd Zero eligible datastore clusters with enough freespace (${SpaceNeededGB}GB)"}

				## if did not find a datastore cluster to use (and a specific datastore cluster tier was not requested), get a datastore (though, if datastore cluster didn't suit the need, probably not a single dstore that will, unless not all dstores are in dstore clusters)
				if (($null -eq $oStorageResourceToUse) -and (-not $PSBoundParameters.ContainsKey("DSClusterTier"))) {
					## select the  datastores from this cluster  where the datastore has more freespace than specified (greater than or equal)
					$arrPotentialDStoresToUse = $arrAllVmfsDStores_ThisCluster | Where-Object {$(if ($PSBoundParameters.ContainsKey("StorageResourceNameToExclude")) {$_.Name -notmatch $StorageResourceNameToExclude} else {$true}) -and ($_.FreeSpaceGB -ge $SpaceNeededGB)}
					## get the count for the number of viable datastores
					$intNumViableDStores = ($arrPotentialDStoresToUse | Measure-Object).Count
					## write out some info about the available datastores (if any)
					dWrite-LogEntry $("$strLogEntry_ToAdd Num. viable datastores: '{0}'{1}" -f $intNumViableDStores, $(if ($intNumViableDStores -gt 0) { " ({0})" -f (($arrPotentialDStoresToUse | Foreach-Object {"$($_.Name) has $([Math]::Round($_.FreeSpaceGB, 0))GB"}) -join ", ") }))
					## get a random one of these potential datastores (if there are any)
					$oStorageResourceToUse = if ($intNumViableDStores -gt 0) {$arrPotentialDStoresToUse | Get-Random} else {$null}
				} ## end if
			} ## end if
		} ## end else

		## return the storage resource (possibly $null)
		return $oStorageResourceToUse
	} ## end process
} ## end function


function Invoke-VMDVMScript {
	<#	.Description
		Function to invoke a PowerShell script inside of a VM guest, asynchronously. Returns PID of process started if success in launching it, or error/exception received otherwise
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(); Apr 2015
	#>
	[CmdletBinding()]
	param(
		## VM in which to run given script
		[parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$VM,
		## Text of the script body to run
		[parameter(Mandatory=$true)][String]$ScriptText,
		## Type of Script to invoke -- PowerShell or BASH
		[ValidateSet("PowerShell", "BASH")]$ScriptType = "PowerShell",
		## Credential to use for accessing the guest OS
		[parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$GuestCredential
	)

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
		## make the GuestProgramSpec; due to the way that calling powershell.exe with -command, the double-quotes in the $ScriptText need escaped with backslashes here (the value to -command is not being used in PowerShell at invocation time, yet)
		#   the Arguments value ends up looking something like (no extra quotes in this example):  -noprofile -command "&{c:\build\someScript.ps1 N \"dom\user0,dom\user1\" N N }"
		$oGuestProgramSpec = if ($ScriptType -eq "PowerShell") {
			New-Object -TypeName VMware.Vim.GuestProgramSpec -Property @{
				ProgramPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
				Arguments = "-noprofile -command `"&{$($ScriptText.Replace('"','\"'))}`""
				WorkingDirectory = "C:\"
			}
		}
		## else, it's a BASH script
		else {
			New-Object -TypeName VMware.Vim.GuestProgramSpec -Property @{
				ProgramPath = "/bin/bash"
				Arguments = "--noprofile -c `"$($ScriptText.Replace('"','\"'))`""
				WorkingDirectory = "/tmp/"
			}
		}
		$oNamePassAuth = New-Object -TypeName VMware.Vim.NamePasswordAuthentication -Property @{
			InteractiveSession = $false
			Username = $GuestCredential.UserName
			Password = $GuestCredential.GetNetworkCredential().Password
		}
		dWrite-LogEntry "$strLogEntry_ToAdd Args string for command interpreter: '$($oGuestProgramSpec.Arguments)'"
		$oViewGuestOpsProcessMgr = Get-View GuestProcessManager-guestOperationsProcessManager
	} ## end begin

	process {
		$VM | ForEach-Object {
			$vmThisOne = $_
			return $oViewGuestOpsProcessMgr.StartProgramInGuest($vmThisOne.Id, $oNamePassAuth, $oGuestProgramSpec)
		} ## end foreach-object
	} ## end process
} ## end function


function Wait-VMDGuestProcess {
	<#	.Description
		Function to wait for a Process to end in a VM guest (as indicated by the GuestProcessInfo object having an EndTime value)
		Existing variables/functions from parent scope used here:  dWrite-LogEntry(); Apr 2015
	#>
	[CmdletBinding()]
	[OutputType([VMware.Vim.GuestProcessInfo])]
	param(
		## VM in which the process on which to wait is running
		[parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
		## Credential to use for accessing the guest OS
		[parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$GuestCredential,
		## PID of the process for which to wait (a Long, a.k.a. a System.Int64)
		[parameter(Mandatory=$true)][System.Int64]$GuestPID,
		## Interval (in seconds) between checks for given process; valid values are integers between 5 and 60
		[ValidateRange(5,60)][System.Int32]$IntervalSeconds = 15
	)

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
		$oNamePassAuth = New-Object -TypeName VMware.Vim.NamePasswordAuthentication -Property @{
			InteractiveSession = $false
			Username = $GuestCredential.UserName
			Password = $GuestCredential.GetNetworkCredential().Password
		}
		$oViewGuestOpsProcessMgr = Get-View GuestProcessManager-guestOperationsProcessManager
	} ## end begin

	process {
		$bProcessEnded = $false
		## while the process has not yet ended
		while (-not $bProcessEnded) {
			try {
				$oGuestProcessInfo = $oViewGuestOpsProcessMgr.ListProcessesInGuest($VM.Id, $oNamePassAuth, $GuestPID)
			} ## end try
			catch {dWrite-LogEntry "$strLogEntry_ToAdd had issue getting process with PID '$GuestPID' in VM '$($VM.Name)'. Will try again in '$IntervalSeconds' seconds. The error:`n$_"}
			## if such a process exists (or did recently if started by StartProgramInGuest() method of the guestOperationsProcessManager object)
			if (($oGuestProcessInfo | Measure-Object).Count -gt 0) {
				## if there is an endTime property that is a DateTime (when process is still running, this property should have a value of $null)
				if ($oGuestProcessInfo.endTime -is [System.DateTime]) {
					$bProcessEnded = $true
					return $oGuestProcessInfo
				} ## end if
				else {Write-Verbose "$strLogEntry_ToAdd Process '$GuestPID' still running. Starting sleep for '$IntervalSeconds' seconds"; Start-Sleep -Seconds $IntervalSeconds}
			} ## end if
			else {Throw "$strLogEntry_ToAdd No process of PID '$GuestPID' found in guest OS of VM '$($VM.Name)' (and, none started by StartProgramInGuest() with this PID in last five minutes)"}
		} ## end while
	} ## end process
} ## end function


function Start-VMDScriptBlockWithRetry {
	<#	.Description
		Function to attempt to invoke a ScriptBlock, and to retry up to a specified number of times such invocation in case of catching issue (and, optionally, only issue of particular types)
		Existing variables/functions from parent scope used here:  dWrite-LogEntry()
	#>
	param (
		## The scriptblock to invoke
		[parameter(Mandatory=$true)][System.Management.Automation.ScriptBlock]$ScriptBlock,
		## The body of the error message to convey if attempts to invoke ScriptBlock fail (also used if max number of attempts is met/exceeded)
		[string]$ErrorMessageBody,
		## Amount of time (in seconds) to wait between attempts
		[parameter(Mandatory=$true)][ValidateRange(1, [int]::MaxValue)][int]$WaitSeconds,
		## Maximum number times to attempt invoking the given ScriptBlock. At least one, up to 60.
		[parameter(Mandatory=$true)][ValidateRange(1,60)][int]$Attempts,
		## The names of the possible MethodFault types for which to attempt retry of ScriptBlock invocation. If none specified, will retry for any caught error
		[string[]]$MethodFaultType
	) ## end param

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
		dWrite-LogEntry ("$strLogEntry_ToAdd Invoking given ScriptBlock, and up to '$Attempts' time{0}, waiting '$WaitSeconds' second{1} between attempts" -f $(if ($Attempts -ne 1) {"s"}), $(if ($WaitSeconds -ne 1) {"s"}))
		## counter for the number of attempts to invoke the scriptblock
		$intNumInvokeScriptBlockAttempts = 0
	} ## end begin

	process {
		do {
			## try to run the script in the guest OS, with an ErrorAction of "Stop", so that there is a terminating error for "catch" to be able to handle; catch error, if any
			try {
				$intNumInvokeScriptBlockAttempts += 1
				## informational string for logging
				$strOnAttemptNumberInfo = "attempt $intNumInvokeScriptBlockAttempts of $Attempts"
				## actually invoke the ScriptBlock
				$oInvokeScriptblockOutput = & $ScriptBlock
				dWrite-LogEntry "$strLogEntry_ToAdd Successfully invoked ScriptBlock on $strOnAttemptNumberInfo"
				$bStopRetrying = $true
			} ## end try
			catch {
				$oThisErrorRecord = $_
				## the full typename of the InnerException's MethodFault (if any); else, $null
				$oThisInnerExceptionMethodFaultTypeName = if ($null -ne $oThisErrorRecord.Exception.InnerException.MethodFault) {$oThisErrorRecord.Exception.InnerException.MethodFault.GetType().FullName} else {$null}
				$strMsgErrorInvokingScriptBlock = "$strLogEntry_ToAdd Error (on $strOnAttemptNumberInfo)", $ErrorMessageBody -join ":  "
				## was this a suitable MethodFault type that warrants a retry?  If no MethodFaultType specified, will retry for any error type
				$bSuitableMethodFaultTypeToRetry = if ($PSBoundParameters.ContainsKey("MethodFaultType")) {$MethodFaultType -contains $oThisInnerExceptionMethodFaultTypeName} else {$true}
				dWrite-LogEntry "$strLogEntry_ToAdd Caught an error. MethodFault type '$oThisInnerExceptionMethodFaultTypeName' deemed suitable for ScriptBlock invocation retry?  '$bSuitableMethodFaultTypeToRetry'"
				## if the Try failed, and if either the number of attempts meets/exceeds the max number of tries allowed, or (if MethodFaultType specified), if the InnerException's MethodFault type is not one of the type names specified as being OK to retry the invocation attempt, stop retrying and exit altogether
				if (($intNumInvokeScriptBlockAttempts -ge $Attempts) -or (-not $bSuitableMethodFaultTypeToRetry)) {
					if (-not $bSuitableMethodFaultTypeToRetry) {dWrite-LogEntry "$strLogEntry_ToAdd InnerException MethodFault of type '$oThisInnerExceptionMethodFaultTypeName' is not one of the MethodFault types specified for retry of ScriptBlock invocation" -Foreground Red}
					## set the boolean (but, should not matter, as dHandle-ErrorCatch will gracefully exit)
					$bStopRetrying = $true
					dHandle-ErrorCatch -MessageToConvey $strMsgErrorInvokingScriptBlock -ExitAltogether:$true
				} ## end if
				## else, log some info, wait a bit, then will try again as do loop continues
				else {
					dHandle-ErrorCatch -MessageToConvey "${strMsgErrorInvokingScriptBlock}; will try again after a bit ($WaitSeconds seconds)" -ExitAltogether:$false -SendStatusToUrl:$false
					Start-Sleep -Seconds $WaitSeconds
				} ## end else
			} ## end catch
		} until ($bStopRetrying)
		return New-Object -Type PSObject -Property ([ordered]@{
			InvokeScriptblockOutput = $oInvokeScriptblockOutput
			NumInvocationAttempts = $intNumInvokeScriptBlockAttempts
		})
	} ## end process
} ## end fn


function Get-CredentialFilespec {
	<#	.Description
		Function to get the filespec for a credentials file based on pieces/parts of the file name
		Existing variables/functions from parent scope used here:  $null; Jun 2015
		.Example
		Get-CredentialFilespec -CredUsername matt -EncryptedBy mboren -ComputerName $env:COMPUTERNAME -Path c:\encryptedCredsDir
		returns path like:  c:\encryptedCredsDir\creds.matt.as_mboren_on_VM-SOMEPOOL-002.enc.xml
	#>
	[CmdletBinding()]
	Param(
		## The username of the user whose creds are stored in given file
		[parameter(Mandatory=$true)][string]$CredUsername,
		## The username of the user who encrypted/exported the credentials into the given file
		[parameter(Mandatory=$true)][string]$EncryptedBy,
		## The name ot the computer on which the credentials were encrypted
		[string]$ComputerName = $env:COMPUTERNAME,
		## The path where the encrypted credentials file(s) reside
		[parameter(Mandatory=$true)][string]$Path
	)

	begin {
		## string to add to log messages written by this function; function name in square brackets
		$strLogEntry_ToAdd = "[$($MyInvocation.MyCommand.Name)]"
	} ## end begin

	process {
		## build the filespec string that should correspond to the creds file per the given parameters
		#creds.lfd_bslash_devvmdeploy.as_V2X5333_on_vm-byod7dfc-002.enc.xml
		$strCredFilespec = "{0}\creds.${CredUsername}.as_${EncryptedBy}_on_${ComputerName}.enc.xml" -f $Path.TrimEnd("\")
		if (Test-Path $strCredFilespec) {$strCredFilespec} else {Throw "$strLogEntry_ToAdd Did not find credential file with filespec '$strCredFilespec'. Are filespec components correct?"}
	} ## end process
} ## end function


function Get-VersioningInformation {
	<#	.Description
		Get information about the given Git repository
	#>
	param(
		## The path to the working directory of the local repo of interest
		[ValidateScript({Test-Path -Path $_})][String]$Path
	)
	process {
		$bGitClientAccessible = $null -ne (Get-Command -Name git -ErrorAction:SilentlyContinue)
		$Path | Foreach-Object {
			$strThisPath = $_
			## if
			if ($bGitClientAccessible) {
				## the date and commit ID of the latest commit
				$oOtherCommitInfo = git -C $strThisPath log -1 --format="{Date:'%cd', CommitId:'%H'}" | ConvertFrom-Json
				## the name of the currently checked-out branch
				$strBranchName = git -C $strThisPath rev-parse --symbolic-full-name --abbrev-ref HEAD
				## the "get-url" for this repo
				# $strRemoteGetUrl_thisCommit = (git -C $strThisPath remote get-url origin), "commit", $oOtherCommitInfo.CommitId -join "/"
				New-Object -Type PSObject -Property ([ordered]@{
					Path = $strThisPath
					Branch = $strBranchName
					CommitId = $oOtherCommitInfo.CommitId
					CommitDate = $oOtherCommitInfo.Date
					# CommitUrl = $strRemoteGetUrl_thisCommit
				})
			} else {Write-Verbose "git client not found -- not getting version information"}
		} ## end foeach-object
	} ## end process
} ## end fn