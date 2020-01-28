'2020-01-28
'Created by Stefaan Van Hoornick - BeNeLux Hybrid Cloud Security SE
'You can freely use and adapt this code, no support will be given on it.

DSM_URL="https://"`cat ../dsm_url.txt`
API_KEY=`cat ../api_key.txt`

echo "Hostname,DisplayName,ComputerID,AgentVersion,PolicyID,AM State,WRS State,IPS State,IM State,LI State" > test.csv

curl -k -X POST ${DSM_URL}/api/computers/search?expand=all -H "Content-Type:application/json" -H "api-version:v1" -H "api-secret-key:${API_KEY}" | jq -r '.computers[] | [.hostName,.displayName,.ID,.agentVersion,.policyID,.antiMalware.state,.webReputation.state,.intrusionPrevention.state,.integrityMonitoring.state,.logInspection.state] | @csv' >> test.csv
