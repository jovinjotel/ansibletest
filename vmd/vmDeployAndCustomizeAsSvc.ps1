<#	.Description
	Script for automated VM deployment/configuration and/or interaction with (or removal of) existing VM
#>
param(
	## Short name (no DNS suffix) of VM
	[parameter(Mandatory=$true)][alias('vmObjectName_str')][string]$vmShortName_str,
	## OS for VM; for Windows, this will decide the template from which to deploy, and for RHEL, the GuestID to use for the new VM.  This also determines the VIFolder into which to place the new VM.
	##  One of 'Win2022', 'Win2019', 'Win2016', 'Win2012R2', 'Win2012R2SQL', 'Win2008R2', 'Win2008R2_legacy', 'RHEL5_64', 'RHEL6_64', 'RHEL7_64', 'RHEL8_64' , 'RHEL9_64'
	[string][ValidateSet('Win2022', 'Win2019', 'Win2016', 'Win2012R2', 'Win2012R2SQL', 'Win2008R2', 'Win2008R2_legacy', 'RHEL5_64', 'RHEL6_64', 'RHEL7_64', 'RHEL8_64' , 'RHEL9_64')]$vmOS_str = "Win2019",
	## Memory size for the VM, in MB.  262144MB (256GB) or less (use in conjunction with vmNumCPU)
	[int][ValidateRange(0,256*1kb)]$vmMemoryMB_int = 2048,
	## Number of vCPUs for the VM (32 or fewer) (use in conjunction with vmMemoryMB)
	[int][ValidateRange(1,32)]$vmNumCPU_int = 1,
	## Brief description to set for new VM
	[string]$vmDescription_str,
	## Argument string for the post setup command that runs on a Windows machine once it is customized and up. Guest OS will be rebooted by the deployment process -- do _not_ include any reboots in the post setup command.  Example value: N "am\v6x2237-ds,am\someGroupName" N "am\v6x2237-ds"  "D=10,T=50"
	[string]$WinPostSetupArg_str,
	## Destination email address(es) to which to send the Windows installation verification results once the verification script is run. Can be a comma-separated string to specify more than one email recipient.
	[string]$WinVerifyEmailDest_str,

	## Switch; if present/true, specify that new VM should use DHCP for network configuration instead of explicit IP info
	[parameter(ParameterSetName="useDHCP")][switch]$useDHCP_switch,
	## vCenter in which to perform VM operations.
	[string][ValidateSet('bb.aa.lilly.com', 'cc.aa.lilly.com', 'dd.aa.lilly.com', 'ee.aa.lilly.com', 'jj.aa.lilly.com', 'ii.aa.lilly.com', 'hh.aa.lilly.com', 'kk.aa.lilly.com', 'll.aa.lilly.com', 'mm.aa.lilly.com', 'll.aa.lilly.com', 'nn.ab.lilly.com')]$vCenterName_str = "aa.bb.lilly.com",
	## VMware cluster in which to create VM
	[string]$cluster_str = "Bear",
	## VMware datastore to use (if $null, then use a datastore with suitable amount of free space)
	[string]$datastoreToUse_str,
	## VM guest network label (should not be case-SenSiTive)
	[string]$guestNetworkLabel_str = "VLAN200",
	## Kickstart (or boot-and-config) ISO to be attached to new, empty VM for purpose of installing/configuring guest OS from scratch. Of format "[datastoreName] folderName/ISOName.iso".  Example value:  "[UNIX-CUST-ISO] cloneasme.aa.lilly.com/cloneasme-boot.iso"
	[parameter(ParameterSetName="KickstartBuild")][string]$BootIsoDStorePath_str,
	## Separate param for disk sizes, via which to specify disk sizes
	# Not specifying primary disk size, or specifying "0" (or something less than the default size of the new VM (Linux) or of the template (Windows)) for primary disk size will leave the primary disk the same size as the the disk in the template (Win) or default size from config value (Linux)
	[int]$PrimaryDiskGB_int = 0,
	## Array (comma separated values) of sizes, in GB, of additional hard disks to add to new VM.  Not specifying any secondary disks (or specifying "0") will result in no secondary disk
	[int[]]$AddlDiskGB,
	## Active Directory domain for VM (domain to which to join VM if Windows, or domain name for guest's FQDN if Linux).
	[string]$domainName_str = "aa.lilly.com",
	## Name of organizational unit in AD in which to create the computer object if Windows; of either Fully Distinguished Name format Canonical Name format "<domain>/SomeOU/AnotherSubOU", as accepted by New-QADComputer.
	[string]$ADOUForComputerObject_str,
	## TimeZone code for Windows VM, as given at https://developer.vmware.com/docs/powercli/latest/vmware.vimautomation.core/commands/set-oscustomizationspec/#WindowsParameterSet. Need not zero-pad the front of the number (that is, 35 is acceptable for "Eastern (U.S. and Canada)"). If not specified, the default value configured for each environment is used. And, not used for Linux VM deployment
	[int]$TimeZone_int,

	## URL to which to send periodic status updates during the deployment process (optional). Will post to this URL to send the status, with a body objec that has "status" and "message" properties. Expects URL of format "'https://someserver.dom.com/api/status/vm-deploy?id=10"
	[string]$StatusUrl_str,

	## VM action to perform.  Valid values: deploy, query, shutdown, DeleteFromDisk, start
	[string][ValidateSet('deploy', 'query', 'shutdown', 'DeleteFromDisk', 'start')]$VMAction_str = "deploy",
	## Params for when taking action on existing VM (instead of deploying a new VM)
	## Request ID that corresponds to this VM (GCRS request ID)
	[parameter(ParameterSetName="ActOnExistingVM_ByGcrsReqId",Mandatory=$true)][int]$RequestId_int,
	## VMware UUID that corresponds to this VM ($vmView.Config.Uuid); of format of 32 hex digits with either four dashes (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) or no dashes (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
	[parameter(ParameterSetName="ActOnExistingVM_ByVsphereUUID",Mandatory=$true)][string]$VMUUID,

	## Params for specifying explicit IP info for the VM; used by template-based deployments (not Kickstart-based deployments):
	## IP address
	[parameter(Mandatory=$true,ParameterSetName="useStaticIP")][ValidateScript({[bool][System.Net.IPAddress]::Parse($_)})][string]$vmIP_str,
	## Subnet mask
	[parameter(Mandatory=$true,ParameterSetName="useStaticIP")][ValidateScript({[bool][System.Net.IPAddress]::Parse($_)})][string]$vmSubnet_str,
	## Default gateway
	[parameter(Mandatory=$true,ParameterSetName="useStaticIP")][ValidateScript({[bool][System.Net.IPAddress]::Parse($_)})][string]$vmGateway_str,
	## Optional:  Array of DNS server IPs, listed in order of preference (comma-separated values)
	[parameter(ParameterSetName="useStaticIP")][string[]]$DNSServerIPs_arr = (Write-Output 103.2.2.11 103.2.2.12),

	## Switch to allow for a "what if" run, without actually running a VM deployment/action
	[switch]$WhatIf_sw
) ## end param

## initialize some things
## get script's start time
$dteScriptStart = Get-Date
## get this script's current working dir (used for dot-sourcing supporting files, and as base-dir in which to look for "logs" dir, for writing logs via "dWrite-LogEntry" function)
$strScriptCWD = Split-Path -Parent $MyInvocation.MyCommand.Path
## lowercase version of the VM's short name
$strVMShortName_lowercase = $vmShortName_str.ToLower()
## string to use in log- and transcript filenames; allowed characters:  word characters and dashes; non-word characters and non-dashes are each replaced with an underscore
$strOutputFilesNormalizedVMNameValue = $strVMShortName_lowercase -replace "[^\w-]","_"
$strOutputFilesDescriptionSegment = if ($VMAction_str -eq "deploy") {"Creation"} else {"Action"}
## name of logfile to which to write log entries (dWrite-LogEntry uses this variable by default, if defined); should end up something like myMachine_vmCreation.log or someMachine_vmAction.log
$strLogFilename = "${strOutputFilesNormalizedVMNameValue}_vm${strOutputFilesDescriptionSegment}.log"
## string to use at the close of the log file, when exiting gracefully/intentionally
$strLogFileClosingEntry = "action for VM '$strVMShortName_lowercase' finished $("-" * 39)"


## start a transcript of this script run (and, if existing transcript file, append to it); should end up something like myMachine_vmCreation_transcript.txt or someMachine_vmAction_transcript.txt
Start-Transcript -Append:$true -Path "$strScriptCWD\logs\${strOutputFilesNormalizedVMNameValue}_vm${strOutputFilesDescriptionSegment}_transcript.txt"

## source the other PS file with config settings and whatnot (such as paths to credential files)
#   (this line assumes that the item to be sources is in same directory as this script itself)
. "$strScriptCWD\dConfigItemsSvc.ps1"
## source the other PS file with function definitions and whatnot (this line assumes that the item to be sources is in same directory as this script itself)
. "$strScriptCWD\supportingFunctionsSvc.ps1"

dWrite-LogEntry "$("-" * 40) action started for VM '$strVMShortName_lowercase' (started '$($dteScriptStart.ToString($hshCfgItems['strLongerDateTimeFormat']))')" -foreground DarkGreen
dWrite-LogEntry "vmDeploy version '$($hshCfgItems['strVmDeployVersion'])'"
dWrite-LogEntry "vmDeploy code commit info:$(dWrite-ObjectToTableString -Object (($oVmDeployInfo = Get-VersioningInformation -Path $PSScriptRoot) | Format-List -Property Branch, CommitId, CommitDate))"
if ($WhatIf_sw -eq $true) {dWrite-LogEntry "Running in WhatIf mode -- no VM actions being taken" -foreground White}
dWrite-LogEntry "PowerShell line being invoked:`n`t$($MyInvocation.Line)"
## write some info about the PowerShell process (including it's bit-ness)
dWrite-LogEntry $("PowerShell process ({0}-bit) running on computer '{1}' with instance PID '{2}'" -f $(switch ([System.IntPtr]::Size) {"4" {"32"; break}; "8" {"64"; break}; default {"undetermined"}}), ${env:COMPUTERNAME}, $PID)
dWrite-LogEntry "PSBoundParameters:$(dWrite-ObjectToTableString -Object $PSBoundParameters)"

## hashtable to hold info about this run, for later reporting
$hshThisRunInfo = [ordered]@{vmDeployInfo = $oVmDeployInfo | Select-Object -Property * -ExcludeProperty Path; VMAction = $VMAction_str; TargetVCenter = $vCenterName_str; VMName = $strVMShortName_lowercase}
if ($WhatIf_sw -eq $true) {$hshThisRunInfo["WhatIf"] = $true}

## if status URL was provided, send status update
if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["accepted"] -Message "vmDeploy script started"}

## set credentials filenames based on domain in use here
## get the "main" domain used for given domain -- the "main" domain being the on in which there are vmDeploy credentials for interacting with the given domain; like, aa.lilly.com, bb.lilly.com, or cc.lilly.com
$strDomForCredForThisDom = $hshCfgItems["hshADDomInfo"].Keys | Where-Object {$hshCfgItems["hshADDomInfo"].$_ -contains $domainName_str}
## if no matching domain in config, throw error, or just default to AM, or?
if (($strDomForCredForThisDom | Measure-Object).Count -ne 1) {
	$hshThisRunInfo["IsManagedADDomain"] = $false
	dWrite-LogEntry "[Warning] there was not exactly one main domain in the config that held requested domain '$domainName_str'. Will likely be unable to load proper credentials and whatnot" -ForegroundColor yellow
} ## end if
else {
	$hshThisRunInfo["IsManagedADDomain"] = $true
	## get the "short" (NetBIOS) name of the domain for creds (based on assumption that the first piece is the NetBIOS name)
	$strDomForCredForThisDom_shortName = $strDomForCredForThisDom.Split(".")[0]
	## format creds base filenames with the credential domain's short name; this "injects" the credentials domain's short name into the string that gives the XML creds filespec
	## user name in eventual creds is of format dom\user
	$strCredsXMLFileForADAccessShort = $strCredsXMLFileForADAccessShort_base -f $strDomForCredForThisDom_shortName
	## user name in eventual creds is of format user@dom.com
	$strCredsXMLFileForADAccessUPN = $strCredsXMLFileForADAccessUPN_base -f $strDomForCredForThisDom_shortName
} ## end else

## if action is to act on existing VM
if ($VMAction_str -ne "deploy") {
	## make sure that the vCenter specified is in the "allowed" list of vCenters in which non-deployment operations are authorized/desired
	if ($hshCfgItems["arrAllowedVCsForVMActions"] -contains $vCenterName_str) {dWrite-LogEntry "'$vCenterName_str' ok for VM actions other than deploy -- check" -foreground DarkGreen}
	else {
		$strMsgInvalidVCGiven = "[Problem] Hmm -- '$vCenterName_str' is not in the list of allowed vCenters for non-deployment VM actions. Not continuing."
		## if status URL was provided, send status update
		if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgInvalidVCGiven}
		dExit-Gracefully -ExitMessage $strMsgInvalidVCGiven}
} ## end if

## load desired list of snapins and modules:  requires Quest AD Cmdlets (for removing AD computer object), VMware PowerCLI cmdlets (core and VDS); add them if not already added
dAdd-PSSnapin -PSSnapinName Quest.ActiveRoles.ADManagement
dImport-Module -Name VMWare.VimAutomation.Core,VMware.VimAutomation.Vds

## connect to vCenter if not already connected (importing creds first), storing the returned vCenter server in a variable (to help reduce extraneous output, supposedly)
if (($global:DefaultVIServers | Where-Object {$_.Name -like "${vCenterName_str}*"} | Measure-Object).count -eq 0) {
	## import the credentials for vCenter access; will be $null if import failed
	$credVCAccess = dImport-Cred -CredXmlFilespec $strCredsXMLFileForVCAccess -CredDescription "vCenter access"
	#if ($credVCAccess -eq $null) {"should exit -- vCenter creds import failed"}	## Exit here altogether?

	## attempt to connect to given vCenter with given credentials
	if ($vCenterName_str -in $hshCfgItems.arrVCentersWithSelfSignedCerts) {
		dWrite-LogEntry "Hmm, vCenter '$vCenterName_str' is in the config list of vCenters with invalid certs. Setting PowerCLI for just this PowerShell session to ignore the invalid certificate"
		$oTmpPowerCLIConfigOutput = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false -Verbose
	} else {dWrite-LogEntry "Oh, good -- this vCenter should have a valid TLS certificate. Connecting now"}
	$hshThisRunInfo['tspVCConnect'] = $tspTmp = Measure-Command {$vcConnectedVCenter = Connect-VIServer -Server $vCenterName_str -Protocol https -Credential $credVCAccess}
	## if connection succeeded, log it; else, do something
	if ($vcConnectedVCenter.IsConnected -eq $true) {dWrite-LogEntry "no prior vC connection -- connected now with connection ID '$($vcConnectedVCenter.Id)'. Time taken to do so: '$(dGet-TimespanString $tspTmp -outputUnit auto)'" -foreground DarkGreen}
	else {
		## message for failed/no vCenter connection
		$strMsgNoVCenterConnection = "[Problem] no prior vC connection, and did not connect successfully (attempted to connect to '$vCenterName_str')"
		dWrite-LogEntry "$strMsgNoVCenterConnection. Time taken trying to connect: '$(dGet-TimespanString $tspTmp -outputUnit auto)'" -foreground Yellow
		## exit altogether if not able to connect to vCenter
		if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgNoVCenterConnection}
		dExit-Gracefully "Exiting: unable to connect to given vCenter"
	} ## end else
} ## end if


## check for action:  if not create/deploy, then run other "module-let" section to query or take action on existing VM
if ($VMAction_str -ne "deploy") {dWrite-LogEntry "time for '. $strScriptCWD\$($hshCfgItems['strFilename_ActOnVMSection'])'"; . "$strScriptCWD\$($hshCfgItems['strFilename_ActOnVMSection'])"}
## else, do a VM deployment (all code in this "else" is for VM deployment)
else {
	dWrite-LogEntry "starting a VM deployment"

	## VM properties being set, as explicitly specified by corresponding parameters
	#   $intPrimaryDiskGB      -GB of space to use for primary disk
	#   $intMemoryMB           -MB of memory
	#   $intNumCPU             -number of vCPUs
	$intPrimaryDiskGB = $PrimaryDiskGB_int
	$intMemoryMB = $vmMemoryMB_int; $intNumCPU = $vmNumCPU_int
	dWrite-LogEntry $("using memory size '{0}' MB and vCPU count '{1}'" -f $intMemoryMB, $intNumCPU)

	## based on which OS was specified, set a few things like folder into which to deploy VM, OSCustSpec to copy (the copy shall be used for further config later (networking settings, domain credentials))
	switch ($vmOS_str) {
		## for Windows OSes
		{"Win2008", "Win2008R2", "Win2008R2_legacy", "Win2012R2", "Win2012R2SQL", "Win2016", "Win2019", "Win2022" -contains $_} {
			$bIsWindows = $true
			## add vC-specific, Win OS-specific dest folder for VMs here, from new hshCfg item for given zone (to be created)
			## the name/pattern of the vSphere inventory folder location in which to create new VM
			$strVMFolderName = $hshCfgItems[$vCenterName_str]["WindowsVMFolderPattern"]
			break} ## end Windows-items case
		{"RHEL5_64", "RHEL6_64", "RHEL7_64", "RHEL8_64" , "RHEL9_64" -contains $_} {
			## the name/pattern of the vSphere inventory folder location in which to create new VM
			$strVMFolderName = $hshCfgItems[$vCenterName_str]["LinuxVMFolderPattern"]
			if ((-not $PSBoundParameters.ContainsKey("PrimaryDiskGB_int")) -or ($PrimaryDiskGB_int -eq 0)) {$intPrimaryDiskGB = $hshCfgItems["intPrimaryDiskSizeGB_RHEL"]} ## go with a default primary disk size for from-scratch linux machine if size was not specified
			$bIsWindows = $false
			break} ## end Linux-items case
	} ## end switch

	## determine if this build will be via Kickstart ISO; if not, set a few other variables
	$bToBeKickstarted = if ($PSCmdlet.ParameterSetName -eq "KickstartBuild") {
		## set the guest ID to the config'd value for strGuestID_<vmOS_Str>, for creating new VM object from scratch
		$strNewVMGuestId = $hshCfgItems["strGuestId_${vmOS_str}"]
		## return whether this is a KickstartBuild
		$true
	} ## end if
	else {
		## the name of the template to use for this vCenter and this OS-type; if there is not one explicitly config for this OS and vCenter, use the default template name config
		$strVMTemplateName = if ($null -ne $hshCfgItems[$vCenterName_str]."hshTemplateNames".$vmOS_str) {$hshCfgItems[$vCenterName_str]."hshTemplateNames".$vmOS_str} else {$hshCfgItems["hshDefaultTemplateNames"][$vmOS_str]}
		## name of the virtual datacenter in which to look for the default template to use, if no copy of template exists in destination cluster/vDCenter
		$strCfgDCenterForDefaultTemplateSource = $hshCfgItems[$vCenterName_str]["VDCenterForDefaultTemplate"]
		$strTmp_OSCSConfigItemOSName = if ($bIsWindows) {"Windows"} else {"Linux"}
		## name of OSCS to use as base for OSCS for this VM creation/customization; if there is not one explicitly defined in config, use default one from config
		$strBaseOSCSName = if ($null -ne $hshCfgItems[$vCenterName_str]["hshOSCSNames"].$vmOS_str) {$hshCfgItems[$vCenterName_str]["hshOSCSNames"].$vmOS_str} else {$hshCfgItems[$vCenterName_str]["hshOSCSNames"]["defaultOscs"][$strTmp_OSCSConfigItemOSName]}

		## return whether this is a KickstartBuild
		$false
	} ## end else

	dWrite-LogEntry "using Primary Disk size of '$intPrimaryDiskGB' GB (size of zero means use existing size of template (Win) or default size from config (Linux))"

	## check if number of additional disks specified in request is acceptable per max allowable additional disks count
	$intMaxAddlDisks_perCfg = if ($bIsWindows) {$hshCfgItems["maxAddlDiskCounts"]["Windows"]} else {$hshCfgItems["maxAddlDiskCounts"]["Linux"]}
	$hshThisRunInfo['NumAddlDiskRequested'] = $intNumAddlDisksRequested = ($AddlDiskGB | Measure-Object).Count
	if ($intNumAddlDisksRequested -gt $intMaxAddlDisks_perCfg) {
		$strMsgSubpiece = "request to add '$intNumAddlDisksRequested' additional disks is for more than max allowed of '$intMaxAddlDisks_perCfg' for '$(if ($bIsWindows) {'Windows'} else {'Linux'})' VM"
		if ($WhatIf_sw -eq $true) {dWrite-LogEntry "[Problem] ($strVMShortName_lowercase) Oh, no -- $strMsgSubpiece -- would not continue if this was not a WhatIf run" -foreground Red}
		## if this is not a WhatIf run, exit
		else {
			$strMsgTooManyAddlDisksRequested = "[Problem] ($strVMShortName_lowercase) $strMsgSubpiece. Will not create new VM."
			if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgTooManyAddlDisksRequested}
			dExit-Gracefully "Exiting: $strMsgTooManyAddlDisksRequested"
		} ## end if
	} ## end if
	else {dWrite-LogEntry "number of additional disks requested ($intNumAddlDisksRequested) is within the established limit ($intMaxAddlDisks_perCfg) for '$(if ($bIsWindows) {'Windows'} else {'Linux'})'; proceeding"}

	## check for existing VM by given name; if not -WhatIf, exit here!
	if (Get-VM $vmShortName_str -ErrorAction SilentlyContinue) {
		if ($WhatIf_sw -eq $true) {dWrite-LogEntry "[Problem] Oh, no -- VM by name of '$strVMShortName_lowercase' already exists -- would not continue if this was not a WhatIf run" -foreground Red}
		## if this is not a WhatIf run, exit
		else {
			$strMsgVMAlreadyExists = "[Problem] VM by name of '$strVMShortName_lowercase' already exists. Cannot create new VM."
			if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgVMAlreadyExists}
			dExit-Gracefully "Exiting: $strMsgVMAlreadyExists"
		} ## end if
	} ## end if
	else {dWrite-LogEntry "good, no VM by name of '$strVMShortName_lowercase' exists yet in vCenter '$vCenterName_str'"}


	#### create new AD computer acct if suitable
	if ($bIsWindows) {
		## import previously saved credentials access to AD to create computer object; username in form of domain\user, used for creating computer object in domain
		$credADAccessShort = dImport-Cred -CredXmlFilespec $strCredsXMLFileForADAccessShort -CredDescription "AD access, short format"
		#if ($credADAccessShort -eq $null) {"should exit -- AD creds import failed"}	## Exit here altogether?
		## username in form of user@domain.com, used for some AD interactions, and for OSCustomizationSpec (else, when adding Windows machine to the domain using "short" creds format, computer acct becomes disabled in AD -- per a VMware KB, and by observation)
		$credADAccessUPN = dImport-Cred -CredXmlFilespec $strCredsXMLFileForADAccessUPN -CredDescription "AD access, long format"
		#if ($credADAccessUPN -eq $null) {"should exit -- AD creds import failed"}	## Exit here altogether?

		## get the AD OU path in which to put computer object (if new object is needed)
		if ($PSBoundParameters.ContainsKey("ADOUForComputerObject_str")) {$strADOUForComputerObject = $ADOUForComputerObject_str; $strTmpOutput = "specified"} else {$strADOUForComputerObject = $hshCfgItems["hshADOUsForComputerObjs"][$domainName_str]; $strTmpOutput = "default (from config)"}
		dWrite-LogEntry "using '$strTmpOutput' AD OU path of '$strADOUForComputerObject' for the computer object"
		$hshThisRunInfo['DestADOUPath'] = $strADOUForComputerObject

		## get the object with info about the domain/domain controller via which to create a new computer object; tries to get an AD Subnet based on the address of the network in which the guest IP/subnet resides (if any such Subnet is defined in AD), then gets corresponding AD Site, and if that site has DCs for the given domain, returns info on one such DC
		$oADSiteAndDCInfoForNewGuest = Get-ADDCInfoForADSiteAndDomain -GuestIPAddress $vmIP_str -GuestSubnetMask $vmSubnet_str -DomainName $domainName_str -Credential $credADAccessUPN
		## and, make a variable with the AD DC- or domain name to use for creating the new AD computer acct; this is to be used in creating the new AD computer object, as the "service"
		$strADDControllerOrDomNameToUse =
			if ($true -eq $oADSiteAndDCInfoForNewGuest.bFoundASpecificDCToUse) {
				dWrite-LogEntry "terrific, found a site-specific AD DC to use (in AD site '$($oADSiteAndDCInfoForNewGuest.ADSiteName)')" -Foreground DarkGreen
				$hshThisRunInfo["ADSiteName"] = $oADSiteAndDCInfoForNewGuest.ADSiteName	## add some things to the info hashtable for later output
				$oADSiteAndDCInfoForNewGuest.DomainControllerName
			} ## end if
			else {
				dWrite-LogEntry "huh -- no site-specific AD DC found for this scenario. Will use the domain name '$domainName_str' as the AD service via which to make new AD computer object"
				$domainName_str
			} ## end else

		## create computer account in AD; function returns computer object on success
		if ($WhatIf_sw -ne $true) {
			dWrite-LogEntry "calling function to create AD computer account in domain '$domainName_str' via service '$strADDControllerOrDomNameToUse' for '$strVMShortName_lowercase' if it does not already exist"
			try {$oNewADComputerOut = dNew-ADComputerAcct -Name $strVMShortName_lowercase -OUPath $strADOUForComputerObject -Credential $credADAccessShort -Service $strADDControllerOrDomNameToUse}
			catch {
				## error message to pass on to the Catch handler, and, specify that this is still in the "whatIf" section of code where, if "-WhatIf" switch is specified, this is a "dry" run
				$strMsgErrorCreatingADComputerObj = "Error:  issue while trying to create new AD computer object '$strVMShortName_lowercase'"
				dHandle-ErrorCatch -MessageToConvey $strMsgErrorCreatingADComputerObj -InWhatIfSection:$true -ExitAltogether:$true
			} ## end catch
			if ($oNewADComputerOut -eq $null) {
				$strMsgErrorCreatingADComputerObj = "Error:  issue creating an AD computer object for '$strVMShortName_lowercase' via service '$strADDControllerOrDomNameToUse' (to create one if it does not already exist) -- no computer object returned"
				if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgErrorCreatingADComputerObj}
				## exit from the deployment script
				dExit-Gracefully $strMsgErrorCreatingADComputerObj
			} ## end if
			## else, the function returned either a computer object or a string saying that the computer object already exists
			else {
				dWrite-LogEntry $(if ($oNewADComputerOut.GetType().Name -eq "ArsComputerObject") {"new computer object: '{0}' (canonical name: '{1}')" -f $oNewADComputerOut.NTAccountName, $oNewADComputerOut.CanonicalName} else {"$oNewADComputerOut"}) -foreground DarkGreen
			} ## end else
		} ## end if
		else {dWrite-LogEntry "would create new computer account in domain '$domainName_str' via service '$strADDControllerOrDomNameToUse' for '$strVMShortName_lowercase' (if one does not already exist)"}
	} #### end new-adcomputeracct piece


	#### get destination cluster for this VM build; if none matching, exit
	## try to get the cluster in which the new VM is supposed to go; if invalid cluster name, catch the error and, if not "WhatIf", exit
	try {$clusDestinationCluster = Get-Cluster $cluster_str -ErrorAction:Stop}
	catch {
		## error message to pass on to the Catch handler, and, specify that this is still in the "whatIf" section of code where, if "-WhatIf" switch is specified, this is a "dry" run
		$strMsgErrorGettingCluster = "encountered an error while trying to get cluster by name of '$cluster_str'"
		dHandle-ErrorCatch -MessageToConvey $strMsgErrorGettingCluster -InWhatIfSection:$true -ExitAltogether:$true
	} ## end catch
	$oDestinationDatacenter = Get-Datacenter -Cluster $clusDestinationCluster
	$hshThisRunInfo['DestCluster'] = $clusDestinationCluster.Name
	$hshThisRunInfo['DestDatacenter'] = $oDestinationDatacenter.Name
	dWrite-LogEntry ("alright, cluster '{0}' found (in datacenter '{1}'), and will be used" -f $clusDestinationCluster.Name, $oDestinationDatacenter.Name)
	#### end destination cluster info grab


	## a connected VMHost in the given cluster, to use for things like getting specified virtual portgroup, getting a list of available datastores to use (works on the principal that all hosts in cluster see all of the same datastores)
	$arrViableVMHosts = Get-VMHost -Location $clusDestinationCluster | Where-Object {$_.ConnectionState -eq "Connected"}	## array of viable hosts in given cluster
	$vmhViableVMHost = $arrViableVMHosts | Get-Random
	$hshThisRunInfo['ViableVMHost'] = $vmhViableVMHost.Name

	#### get VM network for hosts in the destination cluster, based on the network label passed (try to get VDPortgroup first, then OpaqueNetwork (NSX-T), then standard virtual port group if no match)
	#    virtualPortGroup name is _not_ case sensitive here -- can get the distributed/opaqueNetwork/std PG object; for the opaqueNetwork/std, use the .Name property later (when setting Network Adapter on VM) to make sure that case is right
	## try to get the VDPortgroup first; if none, fall back to getting opaqueNetwork, then standard vPG, and catching issue this finds none
	try {$oVPortGrpFromClusterToUse = $vmhViableVMHost | Get-VDSwitch | Get-VDPortgroup -Name $guestNetworkLabel_str -ErrorAction:Stop}
	catch {
		dWrite-LogEntry "issue getting VDPortgroup of name '$guestNetworkLabel_str' in cluster '$($clusDestinationCluster.Name)'. Will try to get OpaqueNetwork (NSX-T-fronted). The string from the error: '$($_.ToString())'" -ForegroundColor Yellow

		## OpaqueNetworks live in the default "network" folder at the root of a virtual datacenter; so, need to use the target cluster's parent vDC as the SearchRoot, then make sure that the OpaqueNetwork found (if any) is available on the ESXi hosts in the target cluster
		$oMatchingOpaqueNetwork = Get-View -ViewType OpaqueNetwork -Filter @{Name = "^${guestNetworkLabel_str}$"} -SearchRoot $oDestinationDatacenter.Id -Property Name, Host
		if ($null -ne $oMatchingOpaqueNetwork) {
			## check to see if the OpaqueNetwork is configured on VMHosts in the target cluster; do so by comparing the destination cluster host IDs with the host IDs in the OpaqueNetwork
			$arrComparisonOutObjects = Compare-Object -ReferenceObject ($clusDestinationCluster | Get-VMHost).Id -DifferenceObject $oMatchingOpaqueNetwork.Host -IncludeEqual
			## if there is at least one VMHost with the OpaqueNetwork configured, try to use the given OpaqueNetwork for the eventual VM NetworkAdapter configuration
			if (($arrComparisonOutObjects | Where-Object {$_.SideIndicator -eq "=="} | Measure-Object).Count -gt 0) {
				$oVPortGrpFromClusterToUse = $oMatchingOpaqueNetwork
				## if the OpaqueNetwork is not configured for all VMHosts in the cluster, write a warning to that effect
				if (($arrComparisonOutObjects | Where-Object {$_.SideIndicator -eq "=="} | Measure-Object).Count -lt ($clusDestinationCluster.ExtensionData.Host | Measure-Object).Count) {
					Write-Warning ("vSphere configuration inconsistency: OpaqueNetwork '{0}' is present on some VMHosts in target cluster '{1}', but not on _all_ of the VMHosts in the cluster. Virtualization team should rectify this for the sake of consistency" -f $oVPortGrpFromClusterToUse.Name, $clusDestinationCluster.Name)
				} ## end if
			} ## end if
		} ## end if
		else {
			dWrite-LogEntry ("issue getting OpaqueNetwork of name '$guestNetworkLabel_str' in cluster '{0}'. Will try to get Standard portgroup" -f $clusDestinationCluster.Name) -ForegroundColor Yellow
		} ## end else
	} ## end catch

	if ($null -eq $oVPortGrpFromClusterToUse) {
		dWrite-LogEntry "Got neither a VDPortgroup nor an OpaqueNetwork (NSX-T-fronted) network of name '$guestNetworkLabel_str' in cluster '$($clusDestinationCluster.Name)'. Will try to get standard vPortgroup" -ForegroundColor Yellow
		try {$oVPortGrpFromClusterToUse = $vmhViableVMHost | Get-VirtualPortGroup -Name $guestNetworkLabel_str -Standard -ErrorAction:Stop}
		catch {
			## error message to pass on to the Catch handler, and, specify that this is still in the "whatIf" section of code where, if "-WhatIf" switch is specified, this is a "dry" run
			$strMsgErrorGettingVPortGrp = "encountered an error trying to get standard virtualPortGroup by name of '$guestNetworkLabel_str' in cluster '$($clusDestinationCluster.Name)', and found no matching VDPortgroup, either"
			dHandle-ErrorCatch -MessageToConvey $strMsgErrorGettingVPortGrp -InWhatIfSection:$true -ExitAltogether:$true
		} ## end catch
	} ## end if
	else {
		dWrite-LogEntry "alright, VM Network '$($oVPortGrpFromClusterToUse.Name)' found (property from actual virtual PortGroup of type shortname '$($oVPortGrpFromClusterToUse.GetType().Name)'), and will be used for the new VM's NIC"
		$hshThisRunInfo['VMNetworkFound'] = $oVPortGrpFromClusterToUse.Name
	} ## end else
	#### end of getting VM network piece


	#### VMFolder selection piece -- should get one (1) folder at the root of the datacenter for the given cluster, that matches either "*Windows" or "*Linux" wildcard folder name (gets the root, default "vm" folder in the datacenter, and then tries to get a direct subfolder matching the wildcard folder name)
	$oRootVMFolderInDatacenter = $oDestinationDatacenter | Get-Folder -Type VM -Name vm -NoRecursion
	$oVMFolderToUse = $oRootVMFolderInDatacenter | Get-Folder -Type VM -NoRecursion $strVMFolderName -ErrorAction:SilentlyContinue
	## if no folder named <given config'd name>, use the default "vm" inventory folder at the root of the datacenter
	if ($oVMFolderToUse -eq $null) {
		$oVMFolderToUse = $oRootVMFolderInDatacenter
		dWrite-LogEntry "using default 'vm' folder at root of virtual datacenter in which cluster '$cluster_str' resides (no VMFolder matching specified name '$strVMFolderName')"
	} ## end if
	else {dWrite-LogEntry "good, VMFolder matching name of '$strVMFolderName' exists in virtual datacenter containing cluster '$cluster_str'. Name of VMFolder to use: '$($oVMFolderToUse.Name)'"}
	#### end VMFolder selection piece


	#### template selection piece; if not making VM via KickStart, should get one or more template returned; could be multiple if more than one template of given name exists in particular datacenter (only gets that far if destination cluster does not contain template by given name)
	if (-not $bToBeKickstarted) {
		try {$arrTemplatesToUse = Get-TemplateToUse_VCLocAware -TemplateName $strVMTemplateName -Cluster $clusDestinationCluster -DatacenterOfDefaultTemplate $strCfgDCenterForDefaultTemplateSource}
		catch {
			## error message to pass on to the Catch handler, and, specify that this is still in the "whatIf" section of code where, if "-WhatIf" switch is specified, this is a "dry" run
			$strMsgErrorGettingTemplate = "[Error] failed trying to get template by name of '$strVMTemplateName' in cluster '$($clusDestinationCluster.Name)' (or in datacenter configured for default template, '$strCfgDCenterForDefaultTemplateSource')"
			dHandle-ErrorCatch -MessageToConvey $strMsgErrorGettingTemplate -InWhatIfSection:$true -ExitAltogether:$true
		} ## end catch
		$intNumTemplatesReturned = ($arrTemplatesToUse | Measure-Object).Count
		dWrite-LogEntry $("'$intNumTemplatesReturned' template{0} returned" -f $(if ($intNumTemplatesReturned -ne 1) {"s"}))
		## set var for template to use; is the first (or only) one of the templates returned from the selection piece
		$oTemplateToUse = $arrTemplatesToUse | Select-Object -First 1
		## update a couple of ViewData items, for outputting info about the template
		$oTemplateToUse.ExtensionData.UpdateViewData("Runtime.Host.Name","Runtime.Host.Parent.Name")
		dWrite-LogEntry $("great, template '{0}' found (on VMHost '{1}', whose parent is '{2}')" -f $oTemplateToUse.Name, $oTemplateToUse.ExtensionData.Runtime.LinkedView.Host.Name, $oTemplateToUse.ExtensionData.Runtime.LinkedView.Host.LinkedView.Parent.Name)
		$hshThisRunInfo['TemplateCluster'] = $oTemplateToUse.ExtensionData.Runtime.LinkedView.Host.LinkedView.Parent.Name
	} ## end if
	#### end template selection piece


	#### datastore selection piece
	## get VM-to-be's required storage info (amt that will be required to power-on this new VM (the sum of its primary- and additional disks, and its memory (for VM swap file for VMware)))
	## size that disk would be by default, if the PrimaryDiskGB param is not passed
	$intDefaultDisk0SizeGB = if ($bToBeKickstarted) {
			$hshCfgItems["intPrimaryDiskSizeGB_RHEL"]}
		else {
			## else, get the size of the primary disk in the template to be used, based on the standard that first hard-disk in the template is the primary disk
			($oTemplateToUse | Get-HardDisk -Name "Hard disk 1").CapacityGB
		} # end else
	## the calculated primary disk GB -- which is the Max between the intDefaultDisk0SizeGB and the specified (by param PrimaryDiskGB_int) primary disk size
	$intNewVMSizeCalc_primaryDiskGB = [Math]::Max($intDefaultDisk0SizeGB, $intPrimaryDiskGB)
	## total diskspace in GB that will be required to power-on this new VM (the sum of its primary- and additional disks, and its memory (for VM swap file for VMware))
	$hshThisRunInfo['TotalGBRequired'] = $intVMTotalStorageRequirementGB = $intNewVMSizeCalc_primaryDiskGB + ($AddlDiskGB | Measure-Object -Sum).Sum + $intMemoryMB/1KB

	dWrite-LogEntry $("Total storage required by new VM (including memory): '{0}GB';  intPrimaryDiskGB value: '{1}';  size that new VM's primary disk will be: '{2}GB' (max of specified and defaults)" -f $intVMTotalStorageRequirementGB, $intPrimaryDiskGB, $intNewVMSizeCalc_primaryDiskGB)

	## if a datastore/datastore cluster name was passed
	if ($PSBoundParameters.ContainsKey("datastoreToUse_str")) {
		## try to get the datastore/datastore cluster of the name passed as a param
		$dstToUse = Get-StorageResourceToUse -Name $datastoreToUse_str -Cluster $clusDestinationCluster
	} ## end if
	## if attempt to get the specified datastore/datastore cluster did not return a winner, or no specific datastore was passed, get one random datastore cluster/datastore out of all available for this cluster that have _enough_ storage + X GB after provision
	if ($null -eq $dstToUse) {
		$dstToUse = Get-StorageResourceToUse -Cluster $clusDestinationCluster -SpaceNeededGB ($intVMTotalStorageRequirementGB + $hshCfgItems["intDatastoreMinSpaceToLeaveAfterDeploy_GB"]) -StorageResourceNameToExclude $hshCfgItems["strDatastoreNamesToNotUse_RegEx"]
	} ## end if

	if ($dstToUse) {
		## string for info in logging
		$strTmpDStoreDesc = if ($dstToUse.Name -eq $datastoreToUse_str) {"explicitly specified"} else {"with sufficient freespace"}
		$strTmpOutput = "using storage resource ${strTmpDStoreDesc}: '{0}';  FreeSpaceGB: '{1:n1}';  {2}" -f $dstToUse.Name, $dstToUse.FreeSpaceGB, $(if ($bToBeKickstarted) {"guestId: '$strNewVMGuestId'"} else {"template: '$($oTemplateToUse.Name)'"})
		dWrite-LogEntry $strTmpOutput
	} ## end if
	else {
		## log some stuff
		$strMsgNoDStoresWithSufficientSpace = "no datastore clusters / datastores with $intVMTotalStorageRequirementGB + $($hshCfgItems['intDatastoreMinSpaceToLeaveAfterDeploy_GB']) GB available in cluster '$cluster_str' (requested VM size + min amt of space to leave on datastore)"
		dWrite-LogEntry $strMsgNoDStoresWithSufficientSpace -foreground Yellow
		## if this is a -WhatIf run, just log a message
		if ($WhatIf_sw -eq $true) {dWrite-LogEntry "this VM deployment would have needed to try to provision storage and create datastores in order to be able to succeed" -foreground Yellow}
		## else, try to provision storage from storage array and create datastore on new LUN
		else {
			try {
				$hshThisRunInfo['TryToCreateLun'] = $true
				dWrite-LogEntry "no suitable storage resource found -- attempting to provision storage from storage array, create new datastore for use for this new VM"
				dWrite-LogEntry "time for '& $strScriptCWD\$($hshCfgItems['strFilename_NewDStoreForCluster'])'"
				$oReturnFromStorageProvisionEffort = & "$strScriptCWD\$($hshCfgItems['strFilename_NewDStoreForCluster'])" -vCenter $vCenterName_str -Cluster $clusDestinationCluster.Name -StorageResourceNameToIgnore $hshCfgItems["strDatastoreNamesToNotUse_RegEx"]
				dWrite-LogEntry "item returned from storage provisioning effort: name '$($oReturnFromStorageProvisionEffort.Name)', type '$($oReturnFromStorageProvisionEffort.GetType().Name)'"
			}
			## attempt to provision storage threw some error; catch and take appropriate action
			catch {
				$strMsgInsufficientDStoreSpaceAndAutoStorageProvIssue = "[Problem] not enough datastore freespace in cluster '$cluster_str', and storage provisioning attempt returned an error: '$_'"
				if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgInsufficientDStoreSpaceAndAutoStorageProvIssue}
				## "handle" the error catch -- log info, gracefully exit (but, no StatusUrl update, as already sent)
				dHandle-ErrorCatch -MessageToConvey $strMsgInsufficientDStoreSpaceAndAutoStorageProvIssue -InWhatIfSection:$true -SendStatusToUrl:$false -ExitAltogether:$true
			}
			## if provisioning storage from storage array did not return usable datastore, send error message to status listener if requested, and exit gracefully
			if ($null -eq $oReturnFromStorageProvisionEffort) {
				if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgNoDStoresWithSufficientSpace}
				dExit-Gracefully "not enough freespace on any datastore in cluster '$cluster_str'"
			}
			else {$dstToUse = $oReturnFromStorageProvisionEffort; $hshThisRunInfo['createdNewLun'] = $true}
		} ## end else
	} ## end else
	$hshThisRunInfo['destStorageRes'] = $dstToUse.Name
	#### end datastore selection piece


	#### check that given datastore for boot ISO is available in destination cluster if kickstarting the new VM
	## if this new VM is to be made from a Kickstart CD ISO
	if ($bToBeKickstarted -eq $true) {
		## do prep things for kickstart-based new VM
		$strISODStoreName, $strISORelPath = $BootIsoDStorePath_str.Split("]") | Foreach-Object {$_.Trim("[ ")}

		## check that given datastore is mounted by the available hosts in destination cluster
		try {$dstKickstartIsoDatastore = Get-Datastore -RelatedObject $arrViableVMHosts -Name $strISODStoreName -ErrorAction:Stop}
		catch {
			## error message to pass on to the Catch handler, and, specify that this is still in the "whatIf" section of code where, if "-WhatIf" switch is specified, this is a "dry" run
			$strMsgErrorGettingKickstartIsoDStore = "encountered an error while trying to get datastore by name of '$strISODStoreName' on hosts in cluster '$cluster_str' -- the datastore name that was to be used for finding/mounting the Kickstart ISO '$BootIsoDStorePath_str'"
			dHandle-ErrorCatch -MessageToConvey $strMsgErrorGettingKickstartIsoDStore -InWhatIfSection:$true -ExitAltogether:$true
		} ## end catch
		dWrite-LogEntry "good, datastore '$($dstKickstartIsoDatastore.Name)' found in this cluster"

		## no longer checking for existence of CD ISO -- mechanism that creates ISO already checks for success of creation (indicating presence of ISO)
		dWrite-LogEntry ("Will use kickstart boot ISO '$BootIsoDStorePath_str' at '{0}\{1}'" -f $dstKickstartIsoDatastore.DatastoreBrowserPath, $strISORelPath.Replace('/','\'))
	} ## end if
	#### end check for boot ISO datastore piece


	## if the -WhatIf switch was passed (and is true), write a short blurb and exit
	if ($WhatIf_sw -eq $true) {
		dExit-Gracefully "End of initialization portion -- variables created, some creds loaded, connection attempted to vC and informative log entries written. '-WhatIf' switch was specified, so exiting without creating VM"
	} ## end if


	## if status URL was provided, send status update
	if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["working"] -Message "working on it"}


	## if not Kickstart-based deploy, prep the OSCustomizationSpec to be used for customizing the OS of the new VM
	if ($bToBeKickstarted -ne $true) {
		## instead of copying Persistent OSCS to a NonPersistent one (due to troubles w/ "New-OSCustomizationSpec" and password encryption where the new OSCS specifies that the password is in plain text), use the CustomizationSpecManager object to duplicate an existing spec
		## somewhat unique suffix for tmp OSCS name (will clone existing, use it for VM deployment, then remove the tmp clone)
		$strTmpOSCSNameSuffix = Get-Date -Format yyyyMMdd.HHmmss
		## create the name to be used for the temporary, persistent OSCS (to be deleted after this use)
		$strTmpOSCSFullName = "${strBaseOSCSName}-tmp-${strTmpOSCSNameSuffix}_${strVMShortName_lowercase}"
		$csmSpecMgr = Get-View 'CustomizationSpecManager'
		try {$csmSpecMgr.DuplicateCustomizationSpec($strBaseOSCSName, $strTmpOSCSFullName)}
		catch {
			## error message to pass on to the Catch handler
			$strMsgErrorDuplicatingCustSpec = "Error:  encountered an error copying OSCustSpec '$strBaseOSCSName' to temporary OSCS '$strTmpOSCSFullName'."
			dHandle-ErrorCatch -MessageToConvey $strMsgErrorDuplicatingCustSpec -ExitAltogether:$true
		} ## end catch

		## set a few things, like the Description of the temp OSCS, for general info when viewed in vCenter; store the OSCS in a variable for later use
		$hshParamForSetOSCustSpec = @{Description = "tmp OSCS for '$strVMShortName_lowercase'"; Domain = $domainName_str.ToLower()}
		if ($bIsWindows) {
			## add the domain-join credentials to the params for updating the"temp copy" of OSCustomizationSpec; set credentials here, so they do not need stored in the 'permanent' OSCustomizationSpec in vC
			#   username needs to be of form user@domain.com, else disables computer account when trying to add to domain via OSCS
			$hshParamForSetOSCustSpec["DomainCredentials"] = $credADAccessUPN
		}
		## else, specify the things to set int he OSCS for a new Linux machine
		else {
			## if Linux, we use the DNSServer property of the OSCustSpec (vs. Windows using the DNS property of the OSCustNicMapping, later)
			$hshParamForSetOSCustSpec["DnsServer"] = $DNSServerIPs_arr
			## set DNS suffix list (Linux only per VMware)
			$hshParamForSetOSCustSpec["DnsSuffix"] = $domainName_str.ToLower()
		} ## end else
		$oscTmp = Get-OSCustomizationSpec $strTmpOSCSFullName | Set-OSCustomizationSpec @hshParamForSetOSCustSpec
		$hshThisRunInfo["OSCustSpecName"] = $oscTmp.Name

		## if Windows VM, set OSCustomizationSpec to use given credentials
		if ($bIsWindows) {
			## import credentials for local administrator account on VM
			$credLocalWinAdmin = dImport-Cred -CredXmlFilespec $strCredsXMLFileForLocAdm -CredDescription "Local admin on VM"
			#if ($credLocalWinAdmin -eq $null) {"should exit -- Local admin creds import failed"}	## Exit here altogether?

			## Windows-only: get the TimeZone value to use for the OSCustomizationSpec for this Windows VM; if specified, use it, else use config'd default value
			$strTimeZoneValue, $strTZValueSource = if ($PSBoundParameters.ContainsKey("TimeZone_int")) {$TimeZone_int; "specified"} else {$hshCfgItems[$vCenterName_str]["intTimeZone"]; "default"}
			try {$oscTmp = Set-OSCustomizationSpec -OSCustomizationSpec $oscTmp -TimeZone $strTimeZoneValue -ErrorAction:Stop}
			catch {
				## error message to pass on to the Catch handler
				$strMsgErrorSettingCustSpecTimeZone = "Error:  encountered problem setting TimeZone value for OSCustSpec '$strTmpOSCSFullName' to '$strTimeZoneValue'"
				dHandle-ErrorCatch -MessageToConvey $strMsgErrorSettingCustSpecTimeZone -ExitAltogether:$true
			} ## end catch
			dWrite-LogEntry "Timezone set to '$($oscTmp.TimeZone)' in OSCS '$($oscTmp.Name)' (using '$strTZValueSource' value of '$strTimeZoneValue')" -Foreground DarkGreen
		} ## end if
		## else, do any things needed for Linux-from-template deployment
		else {
			## import the initial creds for the admin
			$credLocalLinuxAdmin = Import-Clixml -Path $strCredsXMLFileForLinuxAdmin
		} ## end else

		## check DHCP switch; if present, no OSCustNicMap, else, yes (using ip/sm/gw, domain name suffixes, DNSServers)
		$hshParamForSetOSCustNicMap = if ($useDHCP_switch -eq $true) {
			## going to use DHCP, so set OSCustomizationNicMapping to use DHCP (should be set as such by default, but to be sure)
			$strTmpOutput = "going to use DHCP"
			@{IpMode = "UseDhcp"}
		} ## end if
		else {
			## set up explicit IP info in OSCustomizationNicMapping
			$strTmpOutput = "using explicit IP setup"
			$hshTmpParams = @{IpMode = "UseStaticIP"; IpAddress = $vmIP_str; SubnetMask = $vmSubnet_str; DefaultGateway = $vmGateway_str}
			## if Windows, we use the DNS property of the OSCustNicMapping for DNS server settings (vs. Linux using the DNSServers property of the OSCustSpec, above)
			if ($bIsWindows) {$hshTmpParams["Dns"] = $DNSServerIPs_arr}
			$hshTmpParams
		} ## end else
		$oscnmTmp = Get-OSCustomizationNicMapping -OSCustomizationSpec $oscTmp | Set-OSCustomizationNicMapping @hshParamForSetOSCustNicMap
		dWrite-LogEntry $strTmpOutput
		dWrite-LogEntry $("OSCustomizationNicMapping:  SpecID of '{0}', of type '{1}', and IPMode of '{2}'" -f $oscnmTmp.SpecID, $oscnmTmp.SpecType, $oscnmTmp.IpMode) -foreground DarkGreen


		## if the OSCustomizationNicMapping is null, something failed when trying to set
		if ($oscnmTmp -eq $null) {
			## if status URL was provided, send status update
			if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message "problem with OSCustomizationNicMapping -- stopped"}
			dExit-Gracefully "The OSCustomizationNicMapping was null -- there was a problem setting this NIC mapping for the OSCS. Exiting, leaving OSCS in place for further inspection/troubleshooting."
		} ## end if
		## end if DHCP/StaticIP section
	} ## end if


	## create hashtable of params/values to pass to New-VM, based on bToBeKickstarted
	$hshNewVMParams = @{
		## switched to using VMHost instead of ResourcePool, because as of PowerCLI v11.5, using ResourcePool and NetworkName resulted in an error like: "New-VM : 3/5/2020 6:03:42 PM    New-VM          Object reference not set to an instance of an object.   New-VM : 3/5/202 0 6:03:42 PM    New-VM          Object reference not set to an instance of an object."
		# ResourcePool = $clusDestinationCluster
		VMHost = $vmhViableVMHost
		Name = $strVMShortName_lowercase
		Location = $oVMFolderToUse
		Datastore = $dstToUse
		RunAsync = $true
	} ## end hashtable
	## if a description was provided, add it in here
	if ($null -ne $vmDescription_str) {$hshNewVMParams["Description"] = $vmDescription_str}
	if ($bToBeKickstarted -eq $true) {
		## add the GuestId and CD params/values
		$hshNewVMParams["GuestId"] = $strNewVMGuestId
		$hshNewVMParams["CD"] = $true
		$hshNewVMParams["DiskGB"] = $intPrimaryDiskGB
		$hshNewVMParams["MemoryMB"] = $intMemoryMB
		## moved "Thick" to be for Linux only until the bug in PowerCLI is fixed where specify a datastore cluster for -Datastore _and_ specifying -DiskStorageFormat value causes error; still present in PowerCLI 5.8R1
		$hshNewVMParams["DiskStorageFormat"] = "Thick"
	} ## end if
	else {
		## with OSCustomization (requires that template or source VM have VMware Tools installed, and that it just be in a PoweredOff state, NOT sysprep'd)
		## add the OSCustomizationSpec and Template params/values
		$hshNewVMParams["OSCustomizationSpec"] = $oscTmp.Name
		$hshNewVMParams["Template"] = $oTemplateToUse
	} ## end else
	## add vPG/Network info to params
	Switch ($oVPortGrpFromClusterToUse) {
		## if it's a VDPortgroup (type [VMware.VimAutomation.Vds.Types.V1.VmwareVDPortgroup]), use the whole VDPortgroup object as the value for the Portgroup param
		{$_ -is [VMware.VimAutomation.Vds.Types.V1.VmwareVDPortgroup]} {$hshNewVMParams["Portgroup"] = $oVPortGrpFromClusterToUse}
		## if it's a std vPG or an OpaqueNetwork (NSX-T), use just the name of the vPG as the value to NetworkName
		{($_ -is [VMware.VimAutomation.Types.Host.VirtualPortGroup]) -or ($_ -is [VMware.Vim.OpaqueNetwork])} {$hshNewVMParams["NetworkName"] = $oVPortGrpFromClusterToUse.Name}
		default {dWrite-LogEntry "virtual portgroup was of some type other than 'VmwareVDPortgroup', 'OpaqueNetwork', or 'VirtualPortGroup' -- not adding other params to the hsh for New-VM"}
	} ## end switch

	## write out the params and values from the hashtable used for New-VM
	dWrite-LogEntry "params/values for New-VM call:$(dWrite-ObjectToTableString -Object $hshNewVMParams)"
	dWrite-LogEntry "invoking New-VM to create the new VM, of course"

	## start the New-VM task, storing the task object
	$taskCreateNewVM = New-VM @hshNewVMParams

	## if task was created successfully, continue with config/customization (or Kickstarting)
	if ($taskCreateNewVM -ne $null) {
		## if the returned task object is a TaskImpl (CloneVM_Task tasks return TaskImpl objects with more things populated, like Id and ExtensionData, than do CreateVM_Task tasks, which return ClientSideTaskImpl objects)
		switch ($taskCreateNewVM.GetType().Name) {
			"TaskImpl" {
				dWrite-LogEntry $("New-VM task id: '{0}'" -f $taskCreateNewVM.Id) -foreground DarkGreen
				## wait for New-VM task to complete (basically runs synchronously w/ task -- displays live status in PowerShell console)
				Wait-Task $taskCreateNewVM
				## get final task state (after it is done)
				$taskCreateNewVM = Get-Task | Where-Object {$_.Id -eq $taskCreateNewVM.Id}
				break}
			"ClientSideTaskImpl" {
				## wait for New-VM task to complete (though, this is done nearly instantly, as it is just creating a new, empty VM from scratch, not cloning from template)
				Wait-Task $taskCreateNewVM; break}
			default {dWrite-LogEntry "New-VM task type was neither 'TaskImpl' nor 'ClientSideTaskImpl'" -foreground yellow}
		} ## end switch
		dWrite-LogEntry $("Task to '{0}' done running. '{1}'% complete, state of '{2}', done at '{3}', took '{4}'" -f $taskCreateNewVM.Name, $taskCreateNewVM.PercentComplete, $taskCreateNewVM.State, $taskCreateNewVM.FinishTime.ToLocalTime().ToString($hshCfgItems["strLongerDateTimeFormat"]), $(dGet-TimespanString -TimeSpan $taskCreateNewVM.FinishTime.Subtract($taskCreateNewVM.StartTime) -outputUnit auto)) -foreground DarkGreen
		$hshThisRunInfo['tspVMCreation'] = $taskCreateNewVM.FinishTime.Subtract($taskCreateNewVM.StartTime)

		## if the CreateVM task succeeded, finish VM config and start the VM
		if ($taskCreateNewVM.State -eq "Success") {
			## get the newly created VM
			$vmNewVM = Get-VM $vmShortName_str

			## then, set additional items (that may not be specified with New-VM when using -Template):
			$hshSetVMParm = @{
				VM = $vmNewVM
				NumCpu = $intNumCPU
				Confirm = $false
				ErrorAction = "Stop"
			} ## end hsh
			## if not from template (and, so, memory size has not yet been adjusted), add param for that
			if (-not $bToBeKickstarted) {$hshSetVMParm["MemoryMB"] = $intMemoryMB}
			try {$vmUpdatedVMTmp = Set-VM @hshSetVMParm}
			catch {
				## error message to pass on to the Catch handler
				$strMsgErrorAddingCpuAndMem = "Error: encountered an error reconfiguring vCPU and memory on VM. Tried '$intNumCPU' vCPUs, '$($intMemoryMB / 1KB)' GB memory"
				dHandle-ErrorCatch -MessageToConvey $strMsgErrorAddingCpuAndMem -ExitAltogether:$true
			} ## end catch
			dWrite-LogEntry $("VM is set to have '{0}' GB of memory, '{1}' vCPU{2} (per its properties)" -f $vmUpdatedVMTmp.MemoryGB, $vmUpdatedVMTmp.NumCPU, $(if ($vmUpdatedVMTmp.NumCPU -gt 1) {"s"})) -foreground DarkGreen

			## set primary hard disk size, if requested size is greater than default size from template (only for machine from template)
			$hdskPrimary = $vmNewVM | Get-HardDisk -Name "Hard Disk 1"
			if ((-not $bToBeKickstarted) -and ($hdskPrimary.CapacityGB -lt $intPrimaryDiskGB)) {
				try {$hdskPrimary_updated = Set-HardDisk -HardDisk $hdskPrimary -CapacityGB $intPrimaryDiskGB -Confirm:$false -ErrorAction:Stop}
				catch {
					## error message to pass on to the Catch handler
					$strMsgErrorResizingDisk = "Error: encountered an error setting primary hard disk size. Tried new size '$intPrimaryDiskGB' GB, target datastore '$($dstToUse.Name)' in cluster '$($clusDestinationCluster.Name)'.  How is the datastore capacity/freespace there?"
					dHandle-ErrorCatch -MessageToConvey $strMsgErrorResizingDisk -ExitAltogether:$true
				} ## end catch
				dWrite-LogEntry "set VM's primary disk; it is now '$($hdskPrimary_updated.CapacityGB)' GB (per its properties)" -foreground DarkGreen
			} ## end if
			else {dWrite-LogEntry "did not adjust VM's primary disk (primary disk already at or larger than requested size)"}
			## add additional disks of given size, if specified and size is greater than 0; "New-HardDisk" returns HardDisk object
			if ($PSBoundParameters.ContainsKey("AddlDiskGB")) {
				$AddlDiskGB | Foreach-Object {
					$intThisAddlDiskSizeGB = $_
					## if this addl disk size is greater than 0, add a new hard disk to the VM
					if ($intThisAddlDiskSizeGB -gt 0) {
						## try to add a new hard disk to the VM; if issue, catch it and act accordingly
						try {$hdskNewAddlDisk = New-HardDisk -DiskType Flat -StorageFormat Thick -CapacityGB $intThisAddlDiskSizeGB -VM $vmNewVM -Datastore $dstToUse -ErrorAction:Stop}
						catch {
							## error message to pass on to the Catch handler
							$strMsgErrorAddingDisk = "Error: encountered an error adding new hard disk to VM:  disk of size '$intThisAddlDiskSizeGB' GB, target datastore '$($dstToUse.Name)' in cluster '$($clusDestinationCluster.Name)'.  How is the datastore capacity/freespace there?"
							dHandle-ErrorCatch -MessageToConvey $strMsgErrorAddingDisk -ExitAltogether:$true
						} ## end catch
						dWrite-LogEntry "new '$($hdskNewAddlDisk.CapacityGB)GB' hard disk; (requested size: '${intThisAddlDiskSizeGB}GB'); datastore: $($hdskNewAddlDisk.Filename.Split(']')[0].TrimStart('['))" -foreground DarkGreen
					} else {dWrite-LogEntry "not attempting to add 0GB disk (size specified was '${intThisAddlDiskSizeGB}GB')"}
				} ## end foreach object
			} ## end if
			else {dWrite-LogEntry "no additional disks requested; adding none"}

			## if VM being build via kickstart, attach datastore ISO (though, Set-CDDrive does not verify IsoPath; it is just a string value); since ISO datastore and ISO path were verified above, ISO should be valid at this point; will catch other errors if they happen, though
			if ($bToBeKickstarted -eq $true) {
				try {Set-CDDrive -CD (Get-CDDrive -VM $vmNewVM) -IsoPath $BootIsoDStorePath_str -StartConnected:$true -Confirm:$false -ErrorAction:Stop}
				catch {
					## error message to pass on to the Catch handler
					$strMsgErrorConnectingCDDrive = "Error: encountered an error setting CDDrive on VM '$strVMShortName_lowercase' to use IsoPath '$BootIsoDStorePath_str'."
					dHandle-ErrorCatch -MessageToConvey $strMsgErrorConnectingCDDrive -ExitAltogether:$true
				} ## end catch
			} ## end if

			## check for advanced settings to set as specified in cfg,
			#   and set them appropriately if any
			$strOsFamilyForAdvSetting = if ($bIsWindows) {"Windows"} else {"Linux"}
			dWrite-LogEntry "checking for advanced settings to set, if any, for new $strOsFamilyForAdvSetting VM"
			## get the AdvancedVMSettings defined in the config, if any
			$arrAdvVMSettingToSet = $hshCfgItems.AdvancedVMSettings.All, $hshCfgItems.AdvancedVMSettings.$strOsFamilyForAdvSetting | Where-Object {$null -ne $_}
			$intNumAdvVMSettingToSet = ($arrAdvVMSettingToSet | Measure-Object).Count
			if ($intNumAdvVMSettingToSet -gt 0) {
				dWrite-LogEntry ("ok, '$intNumAdvVMSettingToSet' advanced VM setting{0} specified in configuration, so will try to add/update such setting{0} on new VM" -f $(if ($intNumAdvVMSettingToSet -ne 1) {"s"}))
				$arrAdvVMSettingToSet | Foreach-Object {$_.GetEnumerator()} | Foreach-Object {
					$oAdvSettingInfoFromCfg = $_
					dWrite-LogEntry ("advanced setting (from cfg) name: '{0}', desired value: '{1}'" -f $oAdvSettingInfoFromCfg.Name,$oAdvSettingInfoFromCfg.Value)
					## if VM already has setting
					if ($oThisAdvVMSetting = Get-AdvancedSetting -Entity $vmNewVM -Name $oAdvSettingInfoFromCfg.Name) {
						## if setting has the desired value
						if ($oThisAdvVMSetting.Value -eq $oAdvSettingInfoFromCfg.Value) {dWrite-LogEntry "advanced setting '$($oThisAdvVMSetting.Name)' already exists for this VM, and with the desired value" -ForegroundColor White}
						## else, try to set the new value for the existing AdvancedSetting
						else {
							dWrite-LogEntry "advanced setting '$($oThisAdvVMSetting.Name)' already exists for this VM, but not with desired value (currently '$($oThisAdvVMSetting.Value)')" -ForegroundColor White
							try {$oNewlySetAdvSetting = Set-AdvancedSetting -AdvancedSetting $oThisAdvVMSetting -Value $oAdvSettingInfoFromCfg.Value -Confirm:$false -ErrorAction:Stop}
							catch {
								## error message to pass on to the Catch handler
								$strMsgErrorSetAdvSetting = "Error: VM '$strVMShortName_lowercase', encountered an error setting advanced setting '$($oAdvSettingInfoFromCfg.Name)'"
								dHandle-ErrorCatch -MessageToConvey $strMsgErrorSetAdvSetting -ExitAltogether:$true
							} ## end catch
							dWrite-LogEntry "successfully set advanced setting '$($oNewlySetAdvSetting.Name)'; new value is '$($oNewlySetAdvSetting.Value)'" -ForegroundColor DarkGreen
						} ## end else
					} ## end if
					## VM does not already have the setting defined; try to create new advanced setting
					else {
						dWrite-LogEntry "advanced setting not yet present on VM -- will try to create one"
						try {$oNewlyAddedAdvSetting = New-AdvancedSetting -Entity $vmNewVM -Name $oAdvSettingInfoFromCfg.Name -Value $oAdvSettingInfoFromCfg.Value -Confirm:$false -ErrorAction:Stop}
						catch {
							## error message to pass on to the Catch handler
							$strMsgErrorNewAdvSetting = "Error: VM '$strVMShortName_lowercase', encountered an error creating new advanced setting '$($oAdvSettingInfoFromCfg.Name)'"
							dHandle-ErrorCatch -MessageToConvey $strMsgErrorNewAdvSetting -ExitAltogether:$true
						} ## end catch
						dWrite-LogEntry "successfully created advanced setting '$($oNewlyAddedAdvSetting.Name)'; value is '$($oNewlyAddedAdvSetting.Value)'" -ForegroundColor DarkGreen
					} ## end else
				} ## end foreach-object
			} ## end if
			else {dWrite-LogEntry "Ok, no advanced VM setting specified in configuration, not trying to add/update any such setting"}

			dWrite-LogEntry "powering on new VM for the first time"
			## power-on the VM, with an ErrorAction of "Stop", so that there is a terminating error for "catch" to be able to handle; catch error, if any; when run asynchronously, returns the StartVM task; when synchronously, returns VirtualMachine object; changed to run synch, because Wait-Tools errors if VM is not PoweredOn, which breaks things
			try {
				$vmInitialStartedVM = Start-VM $vmNewVM -Confirm:$false -ErrorAction:Stop
				dWrite-LogEntry "VM started up on VMHost '$($vmInitialStartedVM.VMHost.Name)'"
				$hshThisRunInfo['StartedOnVMHost'] = $vmInitialStartedVM.VMHost.Name
			}
			catch {
				## error message to pass on to the Catch handler
				$strMsgErrorStartingVM = "Error:  encountered an error during first power-on operation for VM"
				dHandle-ErrorCatch -MessageToConvey $strMsgErrorStartingVM -ExitAltogether:$true
			} ## end catch

			## if kickstarted, just wait for Tools, then dismount ISO and reboot VM
			if ($bToBeKickstarted -eq $true) {
				dWrite-LogEntry "waiting for Kickstart process and eventual install/startup of VM Tools thereafter (for up to '$($hshCfgItems['intWaitForToolsAfterIsoBootMaxMinutes'])' minutes)"
				## get date/time of the start of waiting for Tools
				$dteWaitToolsStart = Get-Date
				## get date/time of when to stop waiting for Tools
				$dteWaitToolsEnd = $dteWaitToolsStart.AddMinutes($hshCfgItems["intWaitForToolsAfterIsoBootMaxMinutes"])
				## initialize the "remaining minutes" variable
				$intMinutesLeftToWaitForTools = $hshCfgItems["intWaitForToolsAfterIsoBootMaxMinutes"]
				## do a preliminary tools check, write some debugging info to the logs
				dCheck-Tools -VMName $vmNewVM.Name -debugInfo
				## while Tools are not running, it is not past the "end date/time for waiting", and there are remaining minutes to wait, try to wait for Tools
				while (($bToolsAreRunningAfterKickstart -ne $true) -and ((Get-Date) -lt $dteWaitToolsEnd) -and ($intMinutesLeftToWaitForTools -gt 0)) {
					## check the VM and see if tools are running (using the -bool switch has the function return a boolean value)
					$bToolsAreRunningAfterKickstart = dCheck-Tools -VMName $vmNewVM.Name -booleanOutput
					if ($bToolsAreRunningAfterKickstart -eq $true) {dWrite-LogEntry "hurray, tools are running in VM '$($vmNewVM.Name)'"; break;} ## end if
					## else, log something and sleep for a bit
					else {
						dWrite-LogEntry "No tools installed yet.  Sleeping for '$($hshCfgItems['intCheckForToolsAfterIsoBootIntervalMinutes'] * 60)' seconds." -foreground Yellow
						Start-Sleep -Seconds ($hshCfgItems['intCheckForToolsAfterIsoBootIntervalMinutes'] * 60)
						## get the remaining minutes to wait (or 1 minute if the rounded TotalMinutes returned from New-Timespan is less than 1)
						$intMinutesLeftToWaitForTools = [Math]::Round((New-Timespan -Start (Get-Date) -End $dteWaitToolsEnd).TotalMinutes,0)
					} ## end else
				} ## end while
				## if VMware Tools start up within the given amount of time (as specified in the config file)
				if ($bToolsAreRunningAfterKickstart -eq $true) {
					$tspLnxKStartDuration = New-TimeSpan -Start $dteWaitToolsStart; $hshThisRunInfo['tspLnxKStart'] = $tspLnxKStartDuration
					$strMsgKickstartDoneAndToolsRunning = "Supergreat:  Kickstart process seems to have finished and VMware Tools are now running after the build/install. Time taken: '$(dGet-TimespanString -TimeSpan $tspLnxKStartDuration -outputUnit auto)'. Disconnecting Kickstart ISO"
					dWrite-LogEntry $strMsgKickstartDoneAndToolsRunning -foreground DarkGreen
					## disconnect ISO from CDDrive, reboot VM (?); puts resulting CDDrive info in the output
					Get-CDDrive -VM $vmNewVM.Name | Set-CDDrive -NoMedia -Confirm:$false
					$hshThisRunInfo['CompletedSuccessfully'] = $true
					## if status URL was provided, send status update
					if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["complete"] -Message $strMsgKickstartDoneAndToolsRunning}
					#Restart-VMGuest $vmNewVM.Name -Confirm:$false ## not rebooting, as Chris Rodenas said that the add'l reboot is unnecessary (machine is already up and ready at this point)
				} ## end if
				else {
					## there was a problem with the kickstart -- tell someone
					$strMsgVMRunningButNotToolsAfterKickstart = "VMware Tools did not start up after booting VM to Kickstart ISO. Waited '$($hshCfgItems['intWaitForToolsAfterIsoBootMaxMinutes'])' minutes as specified by config. No action taken here to dismount Kickstart ISO."
					## if status URL was provided, send status update
					if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgVMRunningButNotToolsAfterKickstart}
					dWrite-LogEntry $strMsgVMRunningButNotToolsAfterKickstart -foreground Yellow
				} ## end else
			} ## end if
			## else, do the whole check- and wait for customization, run post-setup scripts, etc.
			else {
				## monitor for Customization events for the given amount of time; returns $true if customization succeeds, $false otherwise
				$dteEventMonitorStart = Get-Date
				$oCustMonitorOut = dInvoke-VICustomizationEventMonitor -Entity $vmNewVM -PauseSec $hshCfgItems["intOSCustEventMonitoringIntervalSeconds"] -Start (Get-Date).AddMinutes(-$hshCfgItems["intOSCustEventMonitoringMaxPrevMinutes"]) -Finish (Get-Date).AddMinutes($hshCfgItems["intOSCustEventMonitoringMaxMinutes"]) -DatetimeFormat $hshCfgItems["strLongerDateTimeFormat"]

				## output some pertinent info
				## how long did this monitor for customization activities?
				$tspCustomizationMonitoringDuration = (Get-Date).Subtract($dteEventMonitorStart)
				$hshThisRunInfo["tspCustomizationMonitoringDuration"] = $tspCustomizationMonitoringDuration
				dWrite-LogEntry $("Total event monitoring run time: '{0}'" -f (dGet-TimespanString -TimeSpan $tspCustomizationMonitoringDuration -outputUnit auto))
				if ($oCustMonitorOut.CustIsOver) {
					## how long did customization actually take?
					$tspCustomizationDuration = $oCustMonitorOut.dteCustStopped.Subtract($oCustMonitorOut.dteCustBegan)
					$hshThisRunInfo["tspCustomizationDuration"] = $tspCustomizationDuration
					dWrite-LogEntry $("Customization began and ended.  Total customization time: '{0}'" -f (dGet-TimespanString -TimeSpan $tspCustomizationDuration -outputUnit auto)) -foreground DarkGreen
				} ## end if
				else {dWrite-LogEntry "Customization did not finish in the allotted time of '$($hshCfgItems["intOSCustEventMonitoringMaxMinutes"]) minutes'" -foreground yellow}

				if ($oCustMonitorOut.OSCustomizationSucceeded) {
					## wait until VM's OS is up, then do a touch of config (returns VM object upon which tools successfully started, or $null otherwise (due to SilentlyContinue))
					dWrite-LogEntry "waiting for VMware Tools to start up after OSCustomization's last reboot"
					$vmNewVM_StartedWithToolsRunning = Wait-Tools -VM $vmShortName_str -TimeoutSeconds ($hshCfgItems["intWaitForToolsAfterCustMaxMinutes"] * 60)
					dWrite-LogEntry "Tools started in guest OS"
					## if tools started successfully, start the OS config items
					if ($vmNewVM_StartedWithToolsRunning -ne $null) {
						## if this is a Windows VM, run some config items on it
						if ($bIsWindows) {
							## wait for Windows tasks for initial-boot-after-customization (like, acct mgmt -- in particular, renaming of administrator account that happens right here, passwd policy settings, etc); may be unnecessary now that "retry" code in place for post-setup invocation
							dWrite-LogEntry "Waitin a bit ($($hshCfgItems['intSleepSecWaitingForPostOSCustWindowsTasks']) sec) to make sure things are ready for action -- Windows post-customization tasks must finish (like local account renames, password policy settings, and whatnot)" -foreground DarkGreen
							Start-Sleep -Seconds $hshCfgItems["intSleepSecWaitingForPostOSCustWindowsTasks"]
							## this is to run things in the guest OS, particularly "ipconfig.exe /registerdns" for machines that are using DHCP
							if ($useDHCP_switch -eq $true) {
								## build the array of script items to run in the guest OS
								$arrScriptItems = $hshCfgItems["arrWinGuestOSScriptItems"]
								## concat guest cmds, to be run in one Invoke-VMScript
								$strScriptTxt = $arrScriptItems -join " && "
								dWrite-LogEntry "VMScript to be invoked:  '$strScriptTxt'; -ToolsWaitSecs value:  '$($hshCfgItems["intInvokeVMScriptToolsWaitSecs"])'"
								## invoke the given script in the new VM's guest OS
								$oReturnFromInvoke_VMScript = Invoke-VMScript -VM $vmNewVM_StartedWithToolsRunning -ScriptText $strScriptTxt -GuestCredential $credLocalWinAdmin -ScriptType Bat -Confirm:$false -ToolsWaitSecs $hshCfgItems["intInvokeVMScriptToolsWaitSecs"]
								dWrite-LogEntry "Invoke-VMScript return: '$($oReturnFromInvoke_VMScript.ScriptOutput)'"
							} ## end if DHCP

							## if a post-setup script arguments were specified, run post-setup
							if ($PSBoundParameters.ContainsKey("WinPostSetupArg_str")) {
								## run given .bat- or .ps1 based command (specified in ConfigItems) in guest OS , using this post-setup arg string as the argument to said command (where Windows team installs agents, configs some services, partitions any secondary disks, etc.)
								#   if an explicit post-setup filespec is provided in config, use it; else, use default; using the dereference operator to access properties of the hashtable to check for existence, instead of "traditional", brackets-based key access syntax (to avoid "Cannot index into a null array" errors that occur when subkey does not exist and trying to access a further descendent key)
								$strWinPostSetupScriptFilespecToUse = if ($hshCfgItems.$vCenterName_str."hshWinScriptFilespecs".$vmOS_str."PostSetup") {$hshCfgItems[$vCenterName_str]["hshWinScriptFilespecs"][$vmOS_str]["PostSetup"]} else {$hshCfgItems['strWinPostSetupScriptFilespec']}
								dWrite-LogEntry "invoking '$strWinPostSetupScriptFilespecToUse' with arguments of '$WinPostSetupArg_str' in guest OS"
								$strPostSetupCommandExpr = '$strWinPostSetupScriptFilespecToUse $WinPostSetupArg_str'
								dWrite-LogEntry "Post-setup command string to run (on next line, no quotes added here):`n`t$($ExecutionContext.InvokeCommand.ExpandString($strPostSetupCommandExpr))"
								## get date/time just before invoking VMScript; for reporting the run timespan
								$dteJustBeforePostSetupVMScriptInvocation = Get-Date


								# ## try to run the script in the guest OS, with an ErrorAction of "Stop", so that there is a terminating error for "catch" to be able to handle; catch error, if any
								# try {$intPidOfGuestProcessStarted = Invoke-VMDVMScript -VM $vmNewVM_StartedWithToolsRunning -ScriptText $ExecutionContext.InvokeCommand.ExpandString($strPostSetupCommandExpr) -GuestCredential $credLocalWinAdmin -ErrorAction:Stop}
								# catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while invoking the Windows post-setup script '$strWinPostSetupScriptFilespecToUse'" -ExitAltogether:$true} ## end catch



								$hshParamsForStartVMDScriptBlockWithRetry = @{
									## ScriptBlock to invoke
									ScriptBlock = {Invoke-VMDVMScript -VM $vmNewVM_StartedWithToolsRunning -ScriptText $ExecutionContext.InvokeCommand.ExpandString($strPostSetupCommandExpr) -GuestCredential $credLocalWinAdmin -ErrorAction:Stop}
									## main part of error message to use if error actually encountered (will be appended to)
									ErrorMessageBody = "encountered an error while invoking the Windows post-setup script '$strWinPostSetupScriptFilespecToUse'"
									## number of seconds between invocation retries
									WaitSeconds = $hshCfgItems['intTimeBetweenTriesForInvokePostSetupSeconds']
									## max number of retry attempts
									Attempts = $hshCfgItems['intMaxNumTriesForInvokePostSetup']
									## MethodFault type for which to retry ScriptBlock invocation
									MethodFaultType = $hshCfgItems['arrMethodFaultTypesToRetryInvokePostSetup']
								} ## end hsh
								## try (and retry if necessary) to start a scriptblock in the guest OS; variable with return object from scriptblock invocation attempt(s), with properties InvokeScriptblockOutput, NumInvocationAttempts (if returns at all -- may not return at all if the scriptblock invocation fails either by exceeding the acceptable number of attempts, or by hitting an error that is not of the type(s) for which a retry should be attempted)
								$oPostSetupScriptBlockInvocationReturn = Start-VMDScriptBlockWithRetry @hshParamsForStartVMDScriptBlockWithRetry

								## the number of attempts to start the given scriptblock
								$hshThisRunInfo["NumInvokePostSetupAttempts"] = $oPostSetupScriptBlockInvocationReturn.NumInvocationAttempts
								$intPidOfGuestProcessStarted = $oPostSetupScriptBlockInvocationReturn.InvokeScriptblockOutput



								dWrite-LogEntry "Invoked script in guest for post-setup task. Guest process PID is '$intPidOfGuestProcessStarted'"
								## try to wait for the script in the guest OS to complete; catch error, if any
								dWrite-LogEntry "Starting wait for post-setup script in guest to finish"
								try {$oGuestProcessInfo_postSetup = Wait-VMDGuestProcess -VM $vmNewVM_StartedWithToolsRunning -GuestCredential $credLocalWinAdmin -GuestPID $intPidOfGuestProcessStarted}
								catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while waiting for the Windows post-setup script to finish." -ExitAltogether:$true}
								## write out info about how long it took the VMScript to run
								$hshThisRunInfo['tspRunFinishVM'] = $tspTimeToRunInvokeVMScript_finishVm = New-TimeSpan -Start $dteJustBeforePostSetupVMScriptInvocation -End (Get-Date)
								dWrite-LogEntry $("Invoked script has ended in the guest.  Time taken to do so: '{0}'" -f $(dGet-TimespanString -TimeSpan $tspTimeToRunInvokeVMScript_finishVm -outputUnit auto))
								## write out the results received from the Invoke-VMDVMScript call
								$oGuestProcessInfo_postSetup_formatted = $oGuestProcessInfo_postSetup | Select-Object Name,Pid,Owner,CmdLine,@{n="StartTime_toLocal"; e={$_.StartTime.ToLocalTime().ToString($hshCfgItems['strLongerDateTimeFormat'])}},@{n="EndTime_toLocal"; e={$_.EndTime.ToLocalTime().ToString($hshCfgItems['strLongerDateTimeFormat'])}},ExitCode
								dWrite-LogEntry "Process info returned from running post-setup script in guest:$(dWrite-ObjectToTableString -Object ($oGuestProcessInfo_postSetup_formatted | Format-List *))"
							} ## end if
							else {dWrite-LogEntry "no post-setup script argument specified -- not running post-setup in guest OS"}

							## final reboot (after guest post-setup script, if any); grab the output of the Restart-VMGuest cmdlet, which is a VMGuest object, so that it is not output to the console
							dWrite-LogEntry "rebooting VM for the last time, before running verify script"
							$vmgGuest = Restart-VMGuest $vmNewVM_StartedWithToolsRunning -Confirm:$false

							## wait for VMware Tools to stop in the guest, which is used as an indicator that the VM is nearing an actual reboot (can potentially be large timespan between issuing Restart-VMGuest and the guest OS actually restarting)
							dWrite-LogEntry "restart of VM guest initiated; waiting for VMware Tools to stop in guest (as indicator that OS shutdown is nigh)"
							$dteStartWaitForToolsToStop = Get-Date
							## standby until Tools are not running in guest OS
							while ($bToolsStillRunningInGuest = dCheck-Tools -VMId $vmNewVM_StartedWithToolsRunning.Id -booleanOutput) {Start-Sleep -Seconds 1}
							$hshThisRunInfo["tspWaitToolsStop_LastRestart"] = (Get-Date) - $dteStartWaitForToolsToStop
							dWrite-LogEntry "fabulous, VMware Tools have stopped in guest -- actual guest reboot is imminent; waited '$(dGet-TimespanString -TimeSpan $hshThisRunInfo["tspWaitToolsStop_LastRestart"] -OutputUnit auto)'" -ForegroundColor DarkGreen
							## sleep a bit before starting wait for Tools to start (should only have gotten here if Tools stopped as part of the guest restart); may not be needed in long term, but left here for now -- VM may still go through "Applying Updates" phase upon actual reboot, so may not hurt to stand by for an extra little bit, here
							dWrite-LogEntry "sleeping a bit ('$($hshCfgItems['intSleepSecAfterRestartCmd'])' sec), then waiting on VMware Tools to be running after rebooting"
							Start-Sleep -Seconds $hshCfgItems["intSleepSecAfterRestartCmd"]

							## wait for VMware Tools to start after this reboot
							$vmNewVM_StartedWithToolsRunning_final = Wait-Tools -VM (Get-VM -Id $vmNewVM_StartedWithToolsRunning.Id) -TimeoutSeconds ($hshCfgItems["intWaitForToolsAfterRebootMaxMinutes"] * 60)
							if ($vmNewVM_StartedWithToolsRunning_final -ne $null) {dWrite-LogEntry -ForegroundColor DarkGreen "VM started up successfully after final reboot (based on VMware Tools responding again)"} else {dWrite-LogEntry -ForegroundColor Red "VMware Tools did not start up after final reboot in alotted amount of time of '$($hshCfgItems["intWaitForToolsAfterRebootMaxMinutes"] * 60)' seconds"}

							## Section:  check for GuestOperationsAgent readiness (required for successful guest script invocation). This far better option takes the place of previous iterations that just did a wait for a static amount of time
							## check if the Guest Operations agent is ready (and write some info out to log)
							$bGuestOpsAgentReady = dCheck-GuestOperationsAgent -VM $vmNewVM_StartedWithToolsRunning_final -BooleanOutput -DebugInfo
							## if Guest Ops agent not ready, wait some amount of time for it to be ready
							if (-not $bGuestOpsAgentReady) {
								dWrite-LogEntry "Guest Operations agent not ready yet. Starting wait for agent readiness"
								## start the wait
								try {
									## wait for the Guest Ops agent; returns an object with properties Boolean "GuestOpsAgentReachedReadyState" and TimeSpan "TimeWaited"
									$oGuestOpsAgentWaitResult = Wait-VMDVMGuestOperationsAgent -VM $vmNewVM_StartedWithToolsRunning_final -Minutes $hshCfgItems["intGuestOpsAgentWaitMaxMinutes"] -DatetimeFormat $hshCfgItems["strLongerDateTimeFormat"]
									$hshThisRunInfo["tspWaitGuestOpsAgent"] = $oGuestOpsAgentWaitResult.TimeWaited
								} ## end try
								catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while waiting for the Guest Operations agent to reach 'ready' state." -ExitAltogether:$true}
								## check again, currently just for logging
								$bGuestOpsAgentReady = dCheck-GuestOperationsAgent -VM $vmNewVM_StartedWithToolsRunning_final -BooleanOutput -DebugInfo
							} ## end if
							else {dWrite-LogEntry "Good, Guest Operations agent was already ready -- proceeding with bit to invoke verification code" -Foreground DarkGreen}
							## end Section check for GuestOperationsAgent readiness

							## run automated OS verification after final reboot, as requested by Windows team
							#   if an explicit verification filespec is provided in config, use it; else, use default
							$strWinOsVerificationScriptFilespecToUse = if ($hshCfgItems.$vCenterName_str."hshWinScriptFilespecs".$vmOS_str."Verify") {$hshCfgItems[$vCenterName_str]["hshWinScriptFilespecs"][$vmOS_str]["Verify"]} else {$hshCfgItems['strWinOSVerificationScriptFilespec']}
							dWrite-LogEntry "invoking OS verification script '$strWinOsVerificationScriptFilespecToUse' with argument of '$WinVerifyEmailDest_str' in guest OS"
							## get date/time just before invoking VMScript; for reporting the run timespan
							$dteJustBeforeVMVerificationVMScriptInvocation = Get-Date

							## invoke the Guest OS verification invocation scriptblock, attempting up to the given number of times, and get the output object that has a couple of properties
							$hshParamsForStartVMDScriptBlockWithRetry = @{
								## ScriptBlock to invoke
								ScriptBlock = {Invoke-VMDVMScript -VM $vmNewVM_StartedWithToolsRunning_final -ScriptText "$strWinOsVerificationScriptFilespecToUse '$WinVerifyEmailDest_str'" -GuestCredential $credLocalWinAdmin -ErrorAction:Stop}
								## main part of error message to use if error actually encountered (will be appended to)
								ErrorMessageBody = "encountered an error while invoking the Windows verification script '$strWinOsVerificationScriptFilespecToUse'"
								## number of seconds between invocation retries
								WaitSeconds = $hshCfgItems['intTimeBetweenTriesForInvokeVerifySeconds']
								## max number of retry attempts
								Attempts = $hshCfgItems['intMaxNumTriesForInvokeVerify']
								## MethodFault type for which to retry ScriptBlock invocation
								MethodFaultType = $hshCfgItems['arrMethodFaultTypesToRetryInvokeVerify']
							} ## end hsh
							## return object from scriptblock invocation attempt(s), with properties InvokeScriptblockOutput, NumInvocationAttempts (if returns at all -- may not return at all if the scriptblock invocation fails either by exceeding the acceptable number of attempts, or by hitting an error that is not of the type(s) for which a retry should be attempted)
							$oVerificationScriptBlockInvocationReturn = Start-VMDScriptBlockWithRetry @hshParamsForStartVMDScriptBlockWithRetry

							## the number of attempts to start the given scriptblock
							$hshThisRunInfo["NumInvokeVerifyAttempts"] = $oVerificationScriptBlockInvocationReturn.NumInvocationAttempts
							$intPidOfGuestProcessStarted = $oVerificationScriptBlockInvocationReturn.InvokeScriptblockOutput
							dWrite-LogEntry "Invoked script in guest for verification task. Guest process PID is '$intPidOfGuestProcessStarted'"
							## try to wait for the script in the guest OS to complete; catch error, if any
							dWrite-LogEntry "Starting wait for verification script in guest to finish"
							try {$oGuestProcessInfo_verify = Wait-VMDGuestProcess -VM $vmNewVM_StartedWithToolsRunning_final -GuestCredential $credLocalWinAdmin -GuestPID $intPidOfGuestProcessStarted}
							catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while waiting for the Windows verify script to finish." -ExitAltogether:$true}

							## write out info about how long it took the VMScript to run
							$hshThisRunInfo['tspRunVerifyVM'] = $tspTimeToRunInvokeVMScript_verifyVm = New-TimeSpan -Start $dteJustBeforeVMVerificationVMScriptInvocation -End (Get-Date)
							dWrite-LogEntry $("Invoked script has ended in the guest after VM verification.  Time taken to do so: '{0}'" -f $(dGet-TimespanString -TimeSpan $tspTimeToRunInvokeVMScript_verifyVm -outputUnit auto))
							## write out the results received from the Invoke-VMDVMScript call
							$oGuestProcessInfo_verify_formatted = $oGuestProcessInfo_verify | Select-Object Name,Pid,Owner,CmdLine,@{n="StartTime_toLocal"; e={$_.StartTime.ToLocalTime().ToString($hshCfgItems['strLongerDateTimeFormat'])}},@{n="EndTime_toLocal"; e={$_.EndTime.ToLocalTime().ToString($hshCfgItems['strLongerDateTimeFormat'])}},ExitCode
							dWrite-LogEntry "Process info returned from running verification script in guest:$(dWrite-ObjectToTableString -Object ($oGuestProcessInfo_verify_formatted | Format-List *))"

							## done with deploying this Windows VM
							$strMsgVMDeploymentFromTemplateDone = "Awww, yes! Windows VM deployment finished -- no more actions being taken on new Windows VM"
						} ## end if ($bIsWindows)
						## else, this is a new Linux VM from VMware template
						else {
							## Section: ensure that GuestOperationsAgent is ready (required for successful guest script invocation)
							## if Guest Ops agent not ready, wait some amount of time for it to be ready
							try {
								## wait for the Guest Ops agent
								$oGuestOpsAgentWaitResult = Wait-VMDVMGuestOperationsAgent -VM $vmNewVM_StartedWithToolsRunning -Minutes $hshCfgItems["intGuestOpsAgentWaitMaxMinutes"] -DatetimeFormat $hshCfgItems["strLongerDateTimeFormat"]
								$hshThisRunInfo["tspWaitGuestOpsAgent"] = $oGuestOpsAgentWaitResult.TimeWaited
							} ## end try
							catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while waiting for the Guest Operations agent to reach 'ready' state." -ExitAltogether:$true}
							## end Section check for GuestOperationsAgent readiness

							## the command to run in the new VM's guest OS for post-deploy setup things; $bIsRunningInProd populated at config initialization time
							$strVMDeployEnvironment = if ($bIsRunningInProd) {"Prod"} else {"Dev"}
							$strPostSetupCommandExpr = $hshCfgItems["hshLinuxPostSetupCommandInfo"]["cmdlineBaseString"] -f ($strVMShortName_lowercase, $domainName_str.ToLower() -join "."), $hshCfgItems["hshLinuxPostSetupCommandInfo"][$strVMDeployEnvironment]["strTowerHostConfigKey"], $hshCfgItems["hshLinuxPostSetupCommandInfo"][$strVMDeployEnvironment]["strTowerCallbackUrl"]

							## Invoke post-setup configuration command in guest OS
							# $intPidOfGuestProcessStarted = Invoke-VMDVMScript -VM $vmNewVM_StartedWithToolsRunning -ScriptText $strPostSetupCommandExpr -GuestCredential $credLocalLinuxAdmin -ScriptType BASH -ErrorAction:Stop
							$hshParamsForStartVMDScriptBlockWithRetry = @{
								## note: to do some local logging in guest for later debugging, could use a -ScriptText like "set -x; exec &> >(tee /tmp/invoke-vmdvmscriptOutput.txt); $strPostSetupCommandExpr; exit"
								ScriptBlock = {Invoke-VMDVMScript -VM $vmNewVM_StartedWithToolsRunning -ScriptText $strPostSetupCommandExpr -GuestCredential $credLocalLinuxAdmin -ScriptType BASH -ErrorAction:Stop}
								ErrorMessageBody = "encountered an error while invoking the Linux 'initiate guest configuration' command in new guest OS"
								WaitSeconds = $hshCfgItems['intTimeBetweenTriesForInvokeVerifySeconds']
								Attempts = $hshCfgItems['intMaxNumTriesForInvokeVerify']
								MethodFaultType = $hshCfgItems['arrMethodFaultTypesToRetryInvokeVerify']
							} ## end hsh
							## invoke the Guest OS configuration scriptblock, attempting up to the given number of times (may not return at all if the scriptblock invocation fails 'Attempts' times)
							$oGuestScriptBlockInvocationReturn = Start-VMDScriptBlockWithRetry @hshParamsForStartVMDScriptBlockWithRetry

							## the number of attempts it took to start the given scriptblock
							$hshThisRunInfo["NumInvokeGuestConfigAttempts"] = $oGuestScriptBlockInvocationReturn.NumInvocationAttempts
							$intPidOfGuestProcessStarted = $oGuestScriptBlockInvocationReturn.InvokeScriptblockOutput
							dWrite-LogEntry "Invoked script in guest for configuration task. Guest process PID is '$intPidOfGuestProcessStarted'"

							## try to wait for the script in the guest OS to complete; catch error, if any
							dWrite-LogEntry "Starting wait for post-setup configuration initiation command in guest to finish"
							try {$oGuestProcessInfo_initiateConfiguration = Wait-VMDGuestProcess -VM $vmNewVM_StartedWithToolsRunning -GuestCredential $credLocalLinuxAdmin -GuestPID $intPidOfGuestProcessStarted}
							catch {dHandle-ErrorCatch -MessageToConvey "Error:  encountered an error while waiting for the Linux 'initiate guest configuration' command to finish." -ExitAltogether:$true}

							$hshThisRunInfo['tspInvokeGuestConfigCommand'] = New-TimeSpan -Start $oGuestProcessInfo_initiateConfiguration.StartTime.ToLocalTime() -End $oGuestProcessInfo_initiateConfiguration.EndTime.ToLocalTime()
							dWrite-LogEntry "Process info returned from running 'initiate guest config' command in guest:$(dWrite-ObjectToTableString -Object ($oGuestProcessInfo_initiateConfiguration | Format-List *))"

							## exit if not exit code 0 from guest for calling post-setup command
							if (0 -ne $oGuestProcessInfo_initiateConfiguration.ExitCode) {
								$strMsgInvokeLinuxGuestConfigCommandNonSuccessfulExit = "Error:  the Linux 'initiate guest configuration' command exited with code other than success (0). Exited with code '$($oGuestProcessInfo_initiateConfiguration.ExitCode)'. Should have succeeded in order to initiate rest of Linux guest OS configuration. Platform team may need to research"
								if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgInvokeLinuxGuestConfigCommandNonSuccessfulExit}
								dExit-Gracefully -ExitMessage $strMsgInvokeLinuxGuestConfigCommandNonSuccessfulExit
							}
							## done with deploying this Linux VM from template
							else {$strMsgVMDeploymentFromTemplateDone = "Awww, yes! Linux VM deployment from VMware template finished -- no more actions being taken on new VM"}
						} ## end "else, this is a new Linux VM from VMware template"

						## done deploying new VM from VMware template!
						dWrite-LogEntry $strMsgVMDeploymentFromTemplateDone -foreground DarkGreen
						$hshThisRunInfo['CompletedSuccessfully'] = $true
						## if status URL was provided, send status update
						if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["complete"] -Message $strMsgVMDeploymentFromTemplateDone}
					} ## end if ($vmNewVM_StartedWithToolsRunning -ne $null)
					else {
						## else, VMware Tools did not start up after OSCust
						$strMsgVMRunningButNotToolsAfterOSCust = "VMware Tools did not start up after OSCustomization and reboot in alotted amount of time of '$($hshCfgItems['intWaitForToolsAfterCustMaxMinutes'] * 60)' seconds"
						if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgVMRunningButNotToolsAfterOSCust}
						dWrite-LogEntry $strMsgVMRunningButNotToolsAfterOSCust -foreground Red
					} ## end else
				} ## end if
				else {
					## else, OSCustomization failed or did not complete in the alotted time
					$strMsgOSCustFailedOrNotComplete = "boooo -- OSCust failed/did not complete with alotted amount of time of '$($hshCfgItems['intOSCustEventMonitoringMaxMinutes'])' minutes"
					if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgOSCustFailedOrNotComplete}
					dWrite-LogEntry $strMsgOSCustFailedOrNotComplete -foreground Red
				} ## end else
			} ## end conditional statement about "if kickstarted {do this} else {do that}
		} ## end if ($taskCreateNewVM.State -eq "Success")
		## else, the task to create a new VM had a State other than 'Success'
		else {
			## else, the CreateVM task was initiated, but did not succeed; add pertinent info to log
			$strMsgCreateVMTaskFailed = "CreateVM task '{0}' did not succeed.  Ended in State of '{1}', with Message of '{2}' and Fault of '{3}'" -f $taskCreateNewVM.Id, $taskCreateNewVM.State, $taskCreateNewVM.ExtensionData.Info.Error.LocalizedMessage, $taskCreateNewVM.ExtensionData.Info.Error.Fault
			if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgCreateVMTaskFailed}
			dWrite-LogEntry $strMsgCreateVMTaskFailed -foreground Red
		} ## end else
	} ## end if ($taskCreateNewVM -ne $null)
	else {
		## else, the CreateNewVM task was null (no CreateVM task was created)
		$strMsgCreateVMTaskNotCreated = "New-VM task not created successfully.  VM creation not initiated.  Possible causes:  invalid host-, template-, datastore-, CustSpec-, foldername value provided, host maintenance activity, template unavailable, etc.  Ending deployment script.  The last two (2) errors in `$Error:  '$($Error[0..1])'"
		if ($StatusUrl_str) {dSend-StatusToURL -Uri $StatusUrl_str -Status $hshCfgItems["hshStatusUpdateStates"]["error"] -Message $strMsgCreateVMTaskNotCreated}
		dWrite-LogEntry $strMsgCreateVMTaskNotCreated -foreground Red
	} ## end else

	## if not kickstarted, remove the tmp OSCS from vCenter (once it is used on a VM, that VM has a ".tmp" file in its datastore folder that contains the sysprep tools, .inf, etc.; named "icm????.tmp", and goes away after it is used (after VM is powered on and customization runs)); OSCS can be removed from vC as soon as the call is made to deploy a VM w/ it -- does not have to remain until after VM deploy/reconfig is complete.  This call is at the end of the script in efforts to keep vC clean, regardless of outcome of deployment tasks.
	if ($bToBeKickstarted -ne $true) {
		dWrite-LogEntry "removing temporary OS Customization Specification '$($oscTmp.name)' from vCenter"
		Remove-OSCustomizationSpec $oscTmp.name -Confirm:$false
	} ## end if

	## call the function to exit gracefully
	dExit-Gracefully "Done with deployment, cleaning up and exiting normally/intentionally"
} ## end of deployment section