#2020-01-28
#Created by Stefaan Van Hoornick - BeNeLux Hybrid Cloud Security SE
#You can freely use and adapt this code, no support will be given on it.

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set variables
# the api_key and dsm_url are files that exist in a folder -1 (so 1 folder up), just add the dsm_url.txt (like this (without https://): dsm.url.com:4119) and the api_key.txt is just a file with a copy of the api_key that you created in DSM.
$api_key = Get-Content -Path ..\api_key.txt
$dsm_url = Get-Content -Path ..\dsm_url.txt
$expand = 'all' #you can change this see https://automation.deepsecurity.trendmicro.com
$urlSearch = "https://$dsm_url/api/computers?expand=$expand"
$hostFile = ".\ProtectedHosts.csv"

# Headers to use for all REST queries
$headers = @{
  "api-version" = "v1"
  "api-secret-key" = $api_key
  "cache-control" = "no-cache"
  "Content-Type" = "application/json"
}

#Check if outputfile exists
if (!(Test-Path $hostFile)) {
  Write-Output "$($hostFile), file doesn't exists"
}Else {
  Write-Output "$($hostFile), File exists"
  Remove-Item $hostFile
}

# Create headers in CSV file ($hostFile)
Add-Content -Path $hostFile  -Value '"Hostname","DisplayName","ComputerID","AgentVersion","PolicyID","AM State","WRS State","IPS State","IM State","LI State"'

# Getting the necessary information with we REST Method and outputting to screen and adding it to the $hostFile
$computers = (Invoke-RestMethod -Method get -Headers $headers -Uri $urlSearch).computers
Foreach($item in $computers){
  Write-Output "$($item.hostName),$($item.displayName),$($item.ID),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.webReputation.state),$($item.intrusionPrevention.state),$($item.integrityMonitoring.state),$($item.loginspection.state)"
  Add-Content -Path $hostFile -Value "$($item.hostName),$($item.displayName),$($item.ID),$($item.agentVersion),$($item.policyID),$($item.antiMalware.state),$($item.webReputation.state),$($item.intrusionPrevention.state),$($item.integrityMonitoring.state),$($item.loginspection.state)"
}
