#2023-06-15
#You can freely use and adapt this code, no support will be given on it.

# Your Cloud One Workload Security API credentials
# API key is create in Cloud One 
$api_Secret = "<PLEASE ADD YOUR API SECRET HERE>"
$expand="all"
$hostFile = ".\ProtectedHosts.csv"
$url = "https://cloudone.trendmicro.com"
$urlSearch = "$url/api/computers?expand=$expand"
$AMCurlSearch = "$url/api/antimalwareconfigurations"


# Set up authentication headers
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = "$api_Secret"
}

#Check if outputfile exists
if (!(Test-Path $hostFile)) {
    Write-Output "$($hostFile), file doesn't exists"
  }Else {
    Write-Output "$($hostFile), File exists"
    Remove-Item $hostFile
  }

# Create headers in CSV file ($hostFile)
Add-Content -Path $hostFile -Value "HOSTNAME,PLATFORM,AGENTSTATUS,AGENTVERSION,POLICY_ID,ANTIMALWARESTATE,RTS_ID,BM_ENABLED,BM_ACTION,PML_ENABLED,PML_ACTION,AMSI_ENABLED,AMSI_ACTION"

# Make the API request
$computers = (Invoke-RestMethod -Uri $urlSearch -Method get -Headers $headers ).computers
$AntiMalwareConfigurations = (Invoke-RestMethod -Uri $AMCurlSearch -Method get -Headers $headers ).antiMalwareConfigurations

# Check the status of each item from the API request

Foreach($item in $computers){
  if ($($item.computerStatus.agentStatus) -ne "inactive") {
    if ($($item.antiMalware.realTimeScanConfigurationID) -eq 0){
      Write-Output "$($item.hostName),$($item.platform),$($item.computerStatus.agentStatus),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.antiMalware.realTimeScanConfigurationID),NO ANTIMALWARE ENABLED"
      Add-Content -Path $hostFile -Value "$($item.hostName),$($item.platform),$($item.computerStatus.agentStatus),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.antiMalware.realTimeScanConfigurationID),NO ANTIMALWARE ENABLED"
    }
    Foreach($itemamc in $AntiMalwareConfigurations){
      if ($($itemamc.ID) -eq $($item.antiMalware.realTimeScanConfigurationID)){
        Write-Output "$($item.hostName),$($item.platform),$($item.computerStatus.agentStatus),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.antiMalware.realTimeScanConfigurationID),$($itemamc.behaviorMonitoringEnabled),$($itemamc.scanActionForBehaviorMonitoring),$($itemamc.machineLearningEnabled),$($itemamc.scanActionForMachineLearning),$($itemamc.amsiScanEnabled),$($itemamc.scanActionForAmsi)"
        Add-Content -Path $hostFile -Value "$($item.hostName),$($item.platform),$($item.computerStatus.agentStatus),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.antiMalware.realTimeScanConfigurationID),$($itemamc.behaviorMonitoringEnabled),$($itemamc.scanActionForBehaviorMonitoring),$($itemamc.machineLearningEnabled),$($itemamc.scanActionForMachineLearning),$($itemamc.amsiScanEnabled),$($itemamc.scanActionForAmsi)"
      }
    }
  }
}