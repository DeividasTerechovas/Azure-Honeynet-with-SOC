# Building Azure Honeynet with SOC 
### Results from 24h will be uploaded here: <a href="https://github.com/DeividasTerechovas/Azure-Honeynet-with-SOC-Results"> Press For Results </a>
Start Time: March 16th 2025 10:06PM

### (Image for refrence, full details will be in above link after 24h period) 
<img src="https://i.imgur.com/Yih9yxK.png" width="500">

## Overview

In this project, I set up a mini honeynet in Azure to collect logs from various resources into a Log Analytics Workspace. Using Microsoft Sentinel, I created attack maps, triggered alerts, and generated incidents based on the ingested data. To evaluate the security posture, I measured key security metrics in an unsecured environment over 24 hours, applied security controls to harden it, and then measured the metrics again for another 24 hours. The results of this comparison are shared below. The metrics collected include:

* SecurityEvent (Windows Event Logs)
* Syslog (Linux Event Logs)
* SecurityAlert (Alerts triggered in Log Analytics)
* SecurityIncident (Incidents created by Sentinel)
* AzureNetworkAnalytics_CL (Malicious flows allowed into the honeynet)

 The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel 

### Prerequisites

Azure Subscription: Create a free Azure account to receive $200 in credit.

Basic Networking and Cloud Knowledge: Understanding of virtual machines (VMs), subnets, and firewalls.

# Steps to Create the Honeynet

## 1. Set Up Virtual Machines 

Create Resource Group: Organize resources under a single group (e.g., RG-lab).

Deploy Windows and Linux VMs: You can also see <a href="https://github.com/DeividasTerechovas/Azure-Sentinel-SIEM">Here </a>how to set up VMs.

Use a shared virtual network (vNet) and subnet for connectivity.

### Configure Vulnerable Settings:

Remove default Network Security Group (NSG) rules.

Allow unrestricted inbound traffic (any source, port, and destination).

Disable firewalls inside the Windows VM using Remote Desktop Protocol (RDP).

## 2. Set Up a SQL Database

Install SQL Server on Windows VM:

Download and mount the SQL Server evaluation ISO.

Configure mixed-mode authentication with a secure password.

Enable Logging:

Use SQL Server Management Studio (SSMS) to enable login auditing for both successful and failed attempts.

Link SQL Server logs to the Windows Event Viewer.

## 3. Create an Attacker VM

Deploy an Attacker VM:

Place it in a separate resource group and geographical location.

Simulate Attacks:

Attempt RDP, SQL, and SSH connections to the honeynet VMs using incorrect credentials.

## 4. Enable Logging and Monitoring

Log Analytics Workspace:

Create a workspace to centralize logs.

Add diagnostic settings for virtual machines, NSGs, and Azure resources.

Set up Xpath Query:

// Windows Defender Malware Detection XPath Query
Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117)]]

// Windows Firewall Tampering Detection XPath Query
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*[System[(EventID=2003)]]

Microsoft Sentinel:

Integrate Sentinel with the Log Analytics workspace.

Add a GeoIP watchlist to visualize attacker locations. (You the file attached called "geoip-summarized" for this information)

## 5. Query and Analyze Logs

Log Queries:

Use KQL (Kusto Query Language) to analyze logs for failed authentication attempts, RDP connections, and SQL access.

Create Workbooks:

Develop visualizations for activities such as RDP and SSH login failures, SQL authentication attempts, and NSG traffic.

Observing and Responding to Attacks

Leave the honeynet active for an extended period to gather data.

Analyze logs for attacker patterns and geographical distributions.

Use Sentinel to generate incident alerts and track remediations.

## Find below each Workbook

### linux-ssh-auth-fail 
```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet IpAddress_REGEX_PATTERN = @\"\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b\";\nSyslog\n| where Facility == \"auth\"\n| where SyslogMessage startswith \"Failed password for\"\n| order by TimeGenerated desc\n| project TimeGenerated, SourceIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type\n| evaluate ipv4_lookup(GeoIPDB_FULL, SourceIP, network)\n| project TimeGenerated, SourceIP, DestinationHostName, DestinationIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, \" (\", countryname, \")\");",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "latitude",
      "sizeAggregation": "Count",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "friendly_location",
      "legendAggregation": "Count",
      "itemColorSettings": {
        "nodeColorField": "latitude",
        "colorAggregation": "Count",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```

### mssql-auth-fail
```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet IpAddress_REGEX_PATTERN = @\"\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b\";\n// Brute Force Attempt MS SQL Server\nEvent\n| where EventLog == \"Application\"\n| where EventID == 18456\n| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription), DestinationHostName = Computer, RenderedDescription\n| evaluate ipv4_lookup(GeoIPDB_FULL, AttackerIP, network)\n| project TimeGenerated, AttackerIP, DestinationHostName, RenderedDescription, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, \" (\", countryname, \")\");",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "latitude",
      "sizeAggregation": "Count",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "friendly_location",
      "legendAggregation": "Count",
      "itemColorSettings": {
        "nodeColorField": "latitude",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```

### nsg-malicious-allowed-in
```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet MaliciousFlows = AzureNetworkAnalytics_CL \n| where FlowType_s == \"MaliciousFlow\"\n| order by TimeGenerated desc\n| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;\nMaliciousFlows\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, \" (\", countryname, \")\")",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "city",
      "sizeAggregation": "Count",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "IpAddress",
      "legendAggregation": "Count",
      "itemColorSettings": {
        "nodeColorField": "city",
        "colorAggregation": "Count",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```

### windows-rdp-auth-fail
```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| project TimeGenerated, Account, AccountType, Computer, EventID, Activity, IpAddress, LogonTypeName, network, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, \" (\", countryname, \")\");\n",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "locInfoColumn": "countryname",
      "latitude": "latitude",
      "longitude": "longitude",
      "sizeSettings": "EventID",
      "sizeAggregation": "Count",
      "opacity": 0.8,
      "labelSettings": "friendly_location",
      "legendMetric": "EventID",
      "legendAggregation": "Count",
      "itemColorSettings": {
        "nodeColorField": "EventID",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 0"
}
```
## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and the logs were pushed into a Log Analytics Workspace for analysis. Microsoft Sentinel was also employed to trigger alerts and create incidents based on the ingested logs.

