## computer names of development/prod machines on which this code can execute; used for determining which computer-specific, additional config to include
$hshExecComputernames = @{
	"dev" = "abc-server"
	"prod" = "efg-server"
} ## end hashtable

## name of file in CWD with additional configuration items (so can have local/dev web server/prod web server sub-pieces in unique config files, and keep the following, more "universal" settings in one file)
$strAdditionalConfigItemsFileName = Switch (${env:COMPUTERNAME}) {
	$hshExecComputernames["dev"] {"dConfigItemsSvc_IncludeforDevWebserver.ps1"; break}
	$hshExecComputernames["prod"] {
		"dConfigItemsSvc_IncludeforProdWebserver.ps1"
		## is this running in the production vmDeploy environment?
		$bIsRunningInProd = $true
		break
	} ## end case
	default {"dConfigItemsSvc_IncludeforLocal.ps1"; $bIsRunningLocal = $true}
} ## end switch

## status URL to use for "heist" or intercept of vmDeploy errors -- will send errors to the URL given here (old Lilly Cloud status listener) instead of the StatusUrl specified at vmDeploy invocation
$strStatusUrlOverrideForErrorMessages = if ($bIsRunningInProd) {"https://lillycloud.blah.lilly.com/gcrs/cgi-bin/status.pl?id={0}&state="} else {"https://gcrs-d.aa.lilly.com/dev/cgi-bin/status.pl?id={0}&state="}

## enable/disable logging
$bDoLog = $false

## enable/disable log-type info output to console during execution
$bDoConsoleOutput = $true

## mostly static below here
## item for creating the path string for the creds XML files
$strCredsOnMachineName = ${env:\COMPUTERNAME}
## dot-source the specific additional config items file ("$strScriptCWD" is defined in base script)
. "$strScriptCWD\$strAdditionalConfigItemsFileName"
## username in User Principal Name ("UPN") format of user@dom.fqdn.com for VCAccess, ADAccessShort
$strCredsXMLFileForVCAccess = "$strCredsXMLBaseFolder\creds.${strVCAcctFileNamePortion}.as_${strCredsAsUserName}_on_${strCredsOnMachineName}.enc.xml"
## base for filename that will eventually be of format "creds.dom_bslash_usercn.as_V2X5333_on_someComputer.enc.xml"; the "dom" part gets populated later once the "what domain to use?" part is settled
$strCredsXMLFileForADAccessShort_base = "$strCredsXMLBaseFolder\creds.{0}_bslash_${strADAccessAcctCN}.as_${strCredsAsUserName}_on_${strCredsOnMachineName}.enc.xml" ## used for AD computer-object operations
## username in creds is in form of user@domain.com for ADAccessAtAmLillyCom (used by OSCustSpec); base for filename that will eventually be of format "creds.usercn_at_subdom_dom_com.as_V2X5333_on_someComputer.enc.xml"; the "subdom" part gets populated later once the "what domain to use?" part is settled
$strCredsXMLFileForADAccessUPN_base = "$strCredsXMLBaseFolder\creds.${strADAccessAcctCN}_at_{0}_lilly_com.as_${strCredsAsUserName}_on_${strCredsOnMachineName}.enc.xml"
## local admin creds for new Windows VM
$strCredsXMLFileForLocAdm = "$strCredsXMLBaseFolder\creds.locadm.as_${strCredsAsUserName}_on_${strCredsOnMachineName}.enc.xml"
## local admin creds for new Linux VM from template
$strCredsXMLFileForLinuxAdmin = "$strCredsXMLBaseFolder\creds.linxAdmin.as_${strCredsAsUserName}_on_${strCredsOnMachineName}.clixml"

## hash table for holding config items
$hshCfgItems = [ordered]@{
	## version tag for this product
	strVmDeployVersion = "1.7.8"

	## default template names for given OS strings; if there are not vCenter-specific entries later, the main code will use this default section for tepmlate name; keys are the valid values for the Windows VM types parameter (vmOS)
	hshDefaultTemplateNames = @{
		Win2008R2		 = "lillycloud_gwin2k8r2_201607"			## 2008 R2 Enterprise 64-bit
		Win2008R2_legacy = "lillycloud_gwin2k8r2_legacy_201607"		## 2008 R2 Enterprise 64-bit with older .NET and IE
		Win2012R2		 = "lillycloud_gwin2k12r2_201810"			## 2012 R2 Enterprise 64-bit
		Win2012R2SQL	 = "lillycloud_gwin2k12r2sql_201607"		## 2012 R2 Enterprise 64-bit with SQL installer already in template
		Win2016			 = "lillycloud_gwin2k16_202207"				## 2016 Enterprise 64-bit
		Win2019			 = "lillycloud_gwin2k19_current"
		Win2022			 = "lillycloud_gwin2k22_current"
		RHEL7_64         = "RHEL7_Template_v1.0"
		RHEL8_64         = "RHEL8_Template_v1.0"
        RHEL9_64         = "RHEL9_Template_v1.0"     
	} ## end hsh

	## names of GuestIDs for creating new RHEL VMs from scratch (not from template)
	strGuestId_RHEL5_64 = "rhel5_64Guest" ## for RHEL 5, 64-bit
	strGuestId_RHEL6_64 = "rhel6_64Guest" ## for RHEL 6, 64-bit
	strGuestId_RHEL7_64 = "rhel7_64Guest" ## for RHEL 7, 64-bit; Since vSphere API 5.5
	strGuestId_RHEL8_64 = "rhel8_64Guest" ## for RHEL 8, 64-bit; Since vSphere API 6.7
    strGuestId_RHEL9_64 = "rhel9_64Guest" ## for RHEL 9, 64-bit; Since vSphere API 6.7

	## default primary disk size for from-scratch RHEL VMs, to use if a primary size was not specified when calling the script
	intPrimaryDiskSizeGB_RHEL = 60
	## value for Type for adding new NetworkAdapter to VM if needed
	strNewNetworkAdapterType = "Vmxnet3"

	## advanced VM settings to set on new VM, with setting name and value in key/value pairs in a hashtable per OS family, and an "All" for settings to apply to all VMs
	AdvancedVMSettings = @{
		Linux = @{"disk.enableUUID" = $true}
		Windows = $null
		## any advanced settings to add/set for _all_ new VMs
		All = $null
	} ## end hsh

	## maximum numbers of additional harddisks that may be added to new VM (as agreed upon by people, not as limited by technology)
	maxAddlDiskCounts = @{
		Linux = 49
		Windows = 20
	} ## end hsh

	## regex pattern for names of datastores that should not be used for new VM deployment (string is used in a "-notlike" comparison)
	strDatastoreNamesToNotUse_RegEx = "DO_NOT_USE|Templates"
	## minimum amount of freespace to leave on a datastore after creating a new VM on it (used in determining destination datastore candidates)
	intDatastoreMinSpaceToLeaveAfterDeploy_GB = 20

	## domain info:  "main" domain to use for when given, associated domains (domains in same forest) are requested; the key is the domain in which the vmD service acct resides for operations in any of the <values> domains for that key
	hshADDomInfo = @{
		"aa.lilly.com" = @("aa.lilly.com","bb.lilly.com","cc.cc.lilly.com","dd.aa.lilly.com","ee.lilly.com","ff.lilly.com")
		"gg.lilly.com" = @("cc.lilly.com","hh.lilly.com","ii.aa.lilly.com","jj.lilly.com","hh.lilly.com")
		"ff.lilly.com" = @("gg.lilly.com","kk.lilly.com","mm.lilly.com","nn.lilly.com")
	} ## end hsh

	## hash of AD OUs in which to create computer objects for given domains
	hshADOUsForComputerObjs = @{
		# aa.lilly.com forest"
		"xx.lilly.com" = "xx.lilly.com/Member Servers"
		"yy.lilly.com" = "yy.lilly.com/SingaporeRSC/Member Servers"
		"zz.lilly.com" = "zz.lilly.com/Ringway/Member Servers"
		"aa.lilly.com" = "aa.lilly.com/Member Servers"
		# bb.lilly.com domains:
		"bb.lilly.com" = "bb.lilly.com/Member Servers"
		"cc.lilly.com" = "cc.lilly.com/SingaporeRSC/Member Servers"
		"dd.ddd.lilly.com" = "dd.ddd.lilly.com/Member Servers"
		"ee.lilly.com" = "ee.lilly.com/Ringway/Member Servers"
		"jj.lilly.com" = "jj.lilly.com/Member Servers"
		# cc.lilly.com domains:
		"bb.lilly.com" = "bb.lilly.com/SingaporeRSC/Member Servers"
		"cc.lilly.com" = "cc.lilly.com/Ringway/Member Servers"
		"dd.lilly.com" = "dd.lilly.com/Member Servers"
		"ee.lilly.com" = "ee.lilly.com/Member Servers"
	} ## end hsh

	## times for the OSCustomization event monitoring (timeout and interval between each check)
	intOSCustEventMonitoringMaxPrevMinutes = 5  ## maximum number of minutes back to consider events for start- and finish of OSCustomization (to handle when OSCust starts and has a corresponding event _before_ beginning to monitor for such events)
	intOSCustEventMonitoringMaxMinutes = 60  ## maximum number of minutes to monitor for start- and finish of OSCustomization events
	intOSCustEventMonitoringIntervalSeconds = 5  ## interval (in seconds) between checks for events in the monitoring function

	## maximum amount of time to wait for VMtools to finish starting up after OSCustomization; if too low, script does not continue with VM config after final boot
	intWaitForToolsAfterCustMaxMinutes = 20
	## amount of time to wait (via Start-Sleep) for Windows tasks for initial-boot-after-customization (like, acct mgmt -- in particular, renaming of administrator account that happens)
	intSleepSecWaitingForPostOSCustWindowsTasks = 10

	## Items for Guest OS post-setup invocation retries
	## the max number of tries allowed for invoking the automated OS post-deployment/customization setup script in the guest
	intMaxNumTriesForInvokePostSetup = 20
	## the amount of time to wait in between attempts at invoking post-setup script in guest (in seconds); this is probably waiting for AD replication to finish and guest to get GPO applied (which is what renames the local admin acct and enables auth'ing into guest with given credentials)
	intTimeBetweenTriesForInvokePostSetupSeconds = 45
	## the MethodFault typenames that are "acceptable" as fault types when considering whether or not to retry a ScriptBlock invocation (like, the invocation of FinishVM in the guest); see http://pubs.vmware.com/vsphere-55/index.jsp?topic=%2Fcom.vmware.wssdk.apiref.doc%2Fvim.vm.guest.ProcessManager.html for possible fault types for StartProgramInGuest() method in vSphere
	## MethodFault type "InvalidGuestLogin" is for "invalid credential", say, for like when the LocAdm acct has not yet been renamed
	## MethodFault type "GuestOperationsUnavailable" is generally when VMware Tools are not fully running (and, so, the Guest Operations agent is not yet available)
	arrMethodFaultTypesToRetryInvokePostSetup = @("VMware.Vim.InvalidGuestLogin", "VMware.Vim.GuestOperationsUnavailable")

	## amount of time to wait (via Start-Sleep) after issuing Restart-VMGuest cmd befor going on to next command (to provide timing for things like "Wait-Tools", so that Wait-Tools doesn't return immediately if it found tools running _before_ the VM Guest was down)
	intSleepSecAfterRestartCmd = 60
	## maximum amount of time to wait for VMtools to finish starting up; if too low, script does not continue with VM config after final boot
	intWaitForToolsAfterRebootMaxMinutes = 20
	## maximum amount of time for -ToolsWaitSecs param for Invoke-VMScript calls; default for cmdlet is 20 sec
	intInvokeVMScriptToolsWaitSecs = 180
	## maximum amount of time to wait for Guest Operations agent to be ready
	intGuestOpsAgentWaitMaxMinutes = 10

	## maximum amount of time after initiating Kickstart process (booting VM to ISO) to wait for VMtools to finish starting up
	intWaitForToolsAfterIsoBootMaxMinutes = 465	## up from 165, on 24 Mar 2014
	intCheckForToolsAfterIsoBootIntervalMinutes = 2  ## interval (in minutes) between checks VMware Tools (via Wait-Tools)

	## items to run on Windows VM after it is deployed, customized, restarted, and VMtools are running (OS config-type items)
	arrWinGuestOSScriptItems = @("ipconfig.exe /registerdns")  ## force guest to re-register their DNS name -- useful when VM is using DHCP

	## default Windows post-setup script to run after Windows VM is customized, on the domain, up, etc. (if none specified in given vCenter's config section)
	strWinPostSetupScriptFilespec = "C:\build\FinishVM.ps1"
	## default Windows OS verification script to run at end (if none specified in given vCenter's config section)
	strWinOSVerificationScriptFilespec = "C:\Windows\temp\verifyVM.ps1"

	## Linux post-setup commands for Linux VMs deployed from VMware template
	hshLinuxPostSetupCommandInfo = @{
		## the overall command line to run, with formatting placeholders (for substituting actual values at invocation time); example resultant command line after formatting with variable values:
		#	/usr/bin/curl -k -H "X-Forwarded-For: dev0-coolserver0.aa.lilly.com" --data "host_config_key=e4b1608f-5cb9-47d5-ac5d-8e1723b806f5" https://tower.aa.lilly.com/api/v2/job_templates/118/callback/
		cmdlineBaseString = '/usr/bin/curl -k -H "X-Forwarded-For: {0}" --data "host_config_key={1}" {2}'
		Dev = @{
			strTowerHostConfigKey = "e4b1608f-5cb9-47d5-ac5d-8e1723b806f5"
			strTowerCallbackUrl = "https://tower.aa.lilly.com/api/v2/job_templates/118/callback/"
		}
		Prod = @{
			strTowerHostConfigKey = "c77232be-ab2a-42fb-89b0-40a34255abdc"
			strTowerCallbackUrl = "https://tower.aa.lilly.com/api/v2/job_templates/107/callback/"
		}
	}

	## Items for Guest OS Verify invocation retries
	## the max number of tries allowed for invoking the automated OS build verification script in the guest
	intMaxNumTriesForInvokeVerify = 10
	## the amount of time to wait in between attempts at invoking Verify script in guest (in seconds)
	intTimeBetweenTriesForInvokeVerifySeconds = 15
	## the MethodFault typenames that are "acceptable" as fault types when considering whether or not to retry a ScriptBlock invocation (like, the invocation of VerifyVM in the guest); see http://pubs.vmware.com/vsphere-55/index.jsp?topic=%2Fcom.vmware.wssdk.apiref.doc%2Fvim.vm.guest.ProcessManager.html for possible fault types for StartProgramInGuest() method in vSphere
	arrMethodFaultTypesToRetryInvokeVerify = @("VMware.Vim.GuestOperationsUnavailable")

	## status update "states" as specified by LillyCloud system; key -> value:  key is the vmD-specific key, value is the value expected by LillyCloud
	hshStatusUpdateStates = @{
		accepted = "Accepted"
		working = "Working"
		complete = "Complete"
		error = "Error"
		## items for VM retirement actions; still using "old style" while retirements are handled by old LillyCloud; will be updated (removed) once LCS handles retirements (LCS uses "new" status comms)
		vmPoweredOff = 5
		vmDeleted = 6
		vmPoweredOn = 7
	} ## end hashstable
	## Old Style states from old LillyCloud; to be removed once all things are in LCS
	hshOldStatusUpdateStates = [ordered]@{
		accepted = 1
		working = 2
		complete = 3
		error = 4
	}

	## date/time formats to use for output/logging throughout script
	strLongerDateTimeFormat = "ddd dd MMM yyyy, HH:mm:ss"

	## filesystem location to which to write stats files
	strStatsDirFilespec = if ($bIsRunningLocal) {"$PSScriptRoot\logs\stats"} else {"E:\webItems\vmDeployStats"}

	## vCenters with TLS certificates that are in some way invalid at the moment (like, AVS vCenters with their self-signed certificates); used for conditionally setting InvalidCert configuration for the current PowerShell session so as to be able to successfully connect to given vCenter
	arrVCentersWithSelfSignedCerts = Write-Output bb.aa.lilly.com cc.aa.lilly.com dd.aa.lilly.com ee.aa.lilly.com ff.aa.lilly.com gg.aa.lilly.com

	## items specifically for querying/actions other than deploying
	## list of vCenters in which non-deployment operations are allowed
	arrAllowedVCsForVMActions = @("bb.aa.lilly.com", "cc.aa.lilly.com", "dd.aa.lilly.com", "ee.aa.lilly.com", "ff.aa.lilly.com", "gg.aa.lilly.com", "hh.aa.lilly.com", "ii.aa.lilly.com", "gg.aa.lilly.com", "hh.aa.lilly.com", "ii.bb.lilly.com", "kk.aa.lilly.com")
	## name of file that holds the "act on VM" code
	strFilename_ActOnVMSection = "section_actOnVM.ps1"
	## name of file that holds the "storage auto provisioning" code for provisioning storage from storage array and creating new datastore for cluster
	strFilename_NewDStoreForCluster = "storage_New-DatastoreForCluster.ps1"
	## times for the Guest OS Shutdown operation monitoring (timeout and interval between each check)
	fltGuestShutdownTimeoutMins = 10		## amount of time (minutes) to wait for VM guest shutdown to complete (after call to shutdown guest via Tools)
	intVMPowerstateMonitoringIntervalSec = 5  ## interval (in seconds) between checks for PowerState of VM during shutdown/stop/etc. process
} ## end hsh




## vCenter instance-specific configurations
## config items for aa.bb.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_labvcenter = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "GIS"		## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## optional:  names of VM templates to use for each given OS, specific to this vCenter; if not specified here, main code looks for default template names config item (defined elsewhere); keys are the valid values for the Windows VM types parameter (vmOS)
	hshTemplateNames = @{
		# Win2008R2		= "sometemplate_gwin2k8r2"
		# Win2012R2		= "lillycloud_gwin2k12r2_201810"			## 2012 R2 Enterprise 64-bit from Dhiraj Upadhyay
		# Win2016			= "lillycloud_gwin2k16_201810"				## 2016 Enterprise 64-bit from Dhiraj Upadhyay
	} ## end hsh
	## names of OSCustomizationSpecs to use for each given OS; written such that each template could use a different OSCS, or, if no template-specific entry, use "defaultOscs"
	hshOSCSNames = @{defaultOscs = @{Windows = "Win2008_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
	# hshOSCSNames = @{
	# 	Win2008R2		= "Win2008_for_RDSS_withLocalPasswd"
	# 	Win2012R2		= "Win2008_for_RDSS_withLocalPasswd"
	# } ## end hsh
	## optional:  names of post-setup ("finish") and verify script to be run for Windows machines; if no entry for given OS type, will default to using "overall" finish/verify scripts specified elsewhere in config
	#hshWinScriptFilespecs = @{
	#	Win2008R2 = @{
	#		PostSetup = "C:\build\FinishVM.ps1"
	#		Verify = "C:\Windows\temp\verifyVM.ps1"
	#	} ## end hsh
	#	Win2012R2 = @{
	#		PostSetup = "C:\build\FinishVM.ps1"
	#		Verify = "C:\Windows\temp\verifyVM.ps1"
	#	} ## end hsh
	#} ## end hsh
} ## end hashtable for labvcenter

## config items for cc.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_labAvsZ1vcenter = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z1 lab vcenter

## config items for dd.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_osvcenter = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "Osaka"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for Z1 prod vcenter

## config items for ee.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodZ1vcenter = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "LillyZone1"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Win2008_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for Z1 prod vcenter

## config items for ee.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodAvsZ1vcenter = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z1 prod vcenter

## config items for kk.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodAvsZ1vcenter2 = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z1 prod vcenter 2

## config items for ll.aa.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodAvsZ1vcenter3 = @{
	intTimeZone 			= 35			## default timezone to use; "035" is for "Eastern (U.S. and Canada)"
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_vmDeploy"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z1 prod vcenter 3

$hshCfgItemsTmp_drZ1vcenter = @{
	intTimeZone 			= 4				## default timezone to use; "035" is for "Eastern (U.S. and Canada)", "004" is for Pacific
	WindowsVMFolderPattern	= "*Windows"	## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "*Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object
	VDCenterForDefaultTemplate = "LasVegas"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Win_for_vmDeploy"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for Z1 DR vcenter

## config items for aa.bb.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodZ2vcenter = @{
	intTimeZone 			= 85			## default timezone to use; "085" is for "GMT (Greenwich Mean Time)"
	WindowsVMFolderPattern	= "Windows"		## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object; "Linux VMs" exists in every Z2 VMw datacenter (except for Beerse, which has no custom VM folders at all)
	VDCenterForDefaultTemplate = "Z2EISLondon"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Win2008_for_RDSS_GMT_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for Z2 prod vcenter

## config items for ff.bb.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodAvsZ2vcenter = @{
	intTimeZone 			= 85			## default timezone to use; "085" is for "GMT (Greenwich Mean Time)"
	WindowsVMFolderPattern	= "Windows"		## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object; "Linux VMs" exists in every Z2 VMw datacenter (except for Beerse, which has no custom VM folders at all)
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z2 prod vcenter

## config items for gg.bb.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodZ3vcenter = @{
	intTimeZone 			= 215			## default timezone to use; "215" is for "Singapore"
	WindowsVMFolderPattern	= "Windows"		## name pattern of VM folder to use for inventory location of new Windows VM object; each Z3 datacenter has *Windows top-level VM folder, but some have more than 1 that would match
	LinuxVMFolderPattern	= "Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object; each Z3 datacenter has *Linux top-level VM folder, but some have more than 1 that would match
	VDCenterForDefaultTemplate = "Singapore"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Win2008_for_RDSS_GMTPlus8_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for Z3 prod vcenter

## config items for aa.kk.lilly.com (gets added to $hshCfgItems later)
$hshCfgItemsTmp_prodAvsZ3vcenter = @{
	intTimeZone 			= 215			## default timezone to use; "085" is for "GMT (Greenwich Mean Time)"
	WindowsVMFolderPattern	= "Windows"		## name pattern of VM folder to use for inventory location of new Windows VM object
	LinuxVMFolderPattern	= "Linux"		## name pattern of VM folder to use for inventory location of new Linux VM object; "Linux VMs" exists in every Z2 VMw datacenter (except for Beerse, which has no custom VM folders at all)
	VDCenterForDefaultTemplate = "SDDC-Datacenter"	## name of virtual datacenter in which to look for VMware template by default, if such a template does not exist in destination cluster/vDCenter
	## names of OSCustomizationSpecs to use for each given OS
	hshOSCSNames = @{defaultOscs = @{Windows = "Windows_for_RDSS_withLocalPasswd"; Linux = "Linux_for_vmDeploy"}}
} ## end hashtable for AVS Z3 prod vcenter




## DO NOT EDIT below
## add the vCenter-specific config info to the config items hash table
$hshCfgItems["aa.xx.lilly.com"] = $hshCfgItemsTmp_labvcenter
$hshCfgItems["bb.xx.lilly.com"] = $hshCfgItemsTmp_labAvsZ1vcenter
$hshCfgItems["cc.xx.lilly.com"] = $hshCfgItemsTmp_osvcenter
$hshCfgItems["dd.xx.lilly.com"] = $hshCfgItemsTmp_prodZ1vcenter
$hshCfgItems["ee.xx.lilly.com"] = $hshCfgItemsTmp_prodAvsZ1vcenter
$hshCfgItems["ff.xx.lilly.com"] = $hshCfgItemsTmp_prodAvsZ1vcenter2
$hshCfgItems["gg.xx.lilly.com"] = $hshCfgItemsTmp_prodAvsZ1vcenter3
$hshCfgItems["hh.xx.lilly.com"] = $hshCfgItemsTmp_drZ1vcenter
$hshCfgItems["ii.xx.lilly.com"] = $hshCfgItemsTmp_prodZ2vcenter
$hshCfgItems["jj.xx.lilly.com"] = $hshCfgItemsTmp_prodAvsZ2vcenter
$hshCfgItems["hh.yy.lilly.com"] = $hshCfgItemsTmp_prodZ3vcenter
$hshCfgItems["jj.yy.lilly.com"] = $hshCfgItemsTmp_prodAvsZ3vcenter
## end of DO NOT EDIT
