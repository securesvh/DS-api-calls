#2020-01-28
#Created by Stefaan Van Hoornick - BeNeLux Hybrid Cloud Security SE
#You can freely use and adapt this code, no support will be given on it.

#CVE to search for
param (
   [Parameter(Mandatory=$true, HelpMessage="Please specify the CVE number; ex CVE-2020-6052")][string]$cveNumber
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set variables
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

# Getting the necessary information with we REST Method and outputting to screen and adding it to the $hostFile
$computers = (Invoke-RestMethod -Method get -Headers $headers -Uri $urlSearch).computers
Foreach($item in $computers){
  switch ($item.intrusionPrevention.state){
    off {
      Write-Output "Intrusion Prevention Service is OFF for: $($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
    }
    <#
    on {
      Write-Output "$($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
      $ipsRules = (Invoke-RestMethod -Method get -Headers $headers -Uri "https://$($dsm_url)/api/computers/$($item.ID)/intrusionprevention/rules").intrusionPreventionRules
      Write-Output "$($ipsRules.CVE)"
    }
    prevent{
      Write-Output "$($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
      $ipsRules = (Invoke-RestMethod -Method get -Headers $headers -Uri "https://$($dsm_url)/api/computers/$($item.ID)/intrusionprevention/rules").intrusionPreventionRules
      Write-Output $ipsRules.CVE
    }
    detect {
      Write-Output "$($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
      $ipsRules = (Invoke-RestMethod -Method get -Headers $headers -Uri "https://$($dsm_url)/api/computers/$($item.ID)/intrusionprevention/rules").intrusionPreventionRules
      Write-Output $ipsRules.CVE
    }
    #>
    default {
      #Write-Output "$($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
      $ipsRules = (Invoke-RestMethod -Method get -Headers $headers -Uri "https://$($dsm_url)/api/computers/$($item.ID)/intrusionprevention/rules").intrusionPreventionRules
      if ($ipsrules.CVE -eq $cveNumber){
        Foreach ($cve in $ipsrules){
          if ($cve.CVE -eq $cveNumber){
            Write-Output "CVE FOUND : $($cve.CVE),$($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
          }
        }  
      } Else {
          Write-Output "CVE NOT FOUND : $($item.hostName),$($item.ID),$($item.intrusionPrevention.state)"
      }
    }
  }
}