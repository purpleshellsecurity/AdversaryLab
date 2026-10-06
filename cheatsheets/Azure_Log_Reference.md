# Azure Entra and Activity Logs Reference

This document provides a comprehensive overview of Azure Entra audit logs and Azure Activity logs available through diagnostic settings.
## Azure Entra (Identity) Audit Logs

Azure Entra provides various log categories that capture identity and access management activities. These logs are essential for security monitoring, compliance, and troubleshooting identity-related issues.

| Log Type | Description | Primary Use Cases |
|----------|-------------|-------------------|
| **AuditLogs** | Records all logged activities and changes in Azure Entra ID including user/group management, application changes, and policy updates | Track administrative changes, compliance auditing, change management, security investigations |
| **SignInLogs** | Interactive user sign-in events to Azure Entra ID applications and services | Monitor user authentication patterns, detect suspicious sign-ins, troubleshoot access issues, conditional access analysis |
| **NonInteractiveUserSignInLogs** | Non-interactive sign-ins including service accounts, refresh tokens, and programmatic authentication | Track automated sign-ins, service account activity, token refresh patterns, application authentication flows |
| **ServicePrincipalSignInLogs** | Service principal and application sign-in events for app-to-app authentication | Monitor application authentication, API access patterns, service-to-service authentication, OAuth flows |
| **ManagedIdentitySignInLogs** | Azure managed identity sign-in events and authentication activities | Track managed identity usage, troubleshoot Azure resource authentication, monitor system-assigned and user-assigned identities |
| **ProvisioningLogs** | User provisioning and deprovisioning activities including SCIM operations | Monitor identity lifecycle management, troubleshoot provisioning issues, track automated user management |
| **ADFSSignInLogs** | Sign-ins from Active Directory Federation Services in hybrid environments | Track hybrid identity sign-ins, monitor ADFS authentication, troubleshoot federation issues |
| **RiskyUsers** | Users flagged as risky by Azure Identity Protection based on behavior analysis | Identity security monitoring, risk-based conditional access policies, security incident response |
| **UserRiskEvents** | Specific risk events and detections for individual users | Detailed risk analysis, security incident investigation, threat hunting, anomaly detection |
| **NetworkAccessTrafficLogs** | Traffic flowing through Microsoft Entra Private Access and Internet Access | Zero Trust network access monitoring, application usage tracking, network security analysis |
| **RiskyServicePrincipals** | Service principals flagged as risky by Identity Protection | Monitor compromised applications and service accounts, automated threat detection for apps |
| **ServicePrincipalRiskEvents** | Specific risk events detected for service principals and applications | Application security monitoring, investigate suspicious app behavior, automated threat response |
| **EnrichedOffice365AuditLogs** | Enhanced Office 365 audit events enriched with Entra identity context | Comprehensive Office 365 activity monitoring, identity-aware audit analysis, compliance reporting |
| **MicrosoftGraphActivityLogs** | Microsoft Graph API usage, calls, and performance metrics | API monitoring, application behavior analysis, performance optimization, throttling analysis |
| **RemoteNetworkHealthLogs** | Health and connectivity status of remote networks in Global Secure Access | Monitor branch office connectivity, troubleshoot network issues, track remote access performance |
| **NetworkAccessAlerts** | Security and connectivity alerts from Global Secure Access services | Network security incident response, connectivity issue alerting, policy violation notifications |
| **NetworkAccessConnectionEvents** | Detailed connection events and session information for network access | Network forensics, connection troubleshooting, user activity tracking, bandwidth analysis |
| **MicrosoftServicePrincipalSignInLogs** | Microsoft first-party service principal sign-in events (Preview) | Monitor Microsoft service authentication, track system service activity, troubleshoot service connectivity |
| **AzureADGraphActivityLogs** | Legacy Azure AD Graph API usage and activity (being deprecated) | Legacy API monitoring, migration tracking to Microsoft Graph, historical analysis |

## Azure Activity Logs (Resource/Subscription Level)

Azure Activity Logs capture control plane operations and events at the Azure resource and subscription level. These logs are crucial for operational monitoring and governance.

| Category | Description | Primary Use Cases |
|----------|-------------|-------------------|
| **Administrative** | Control plane operations including resource creation, updates, deletions, and configuration changes | Track resource changes, compliance auditing, change management, operational monitoring |
| **Security** | Security-related events, alerts, and security center notifications | Security monitoring, threat detection, compliance reporting, incident response |
| **ServiceHealth** | Azure service health notifications, planned maintenance, and service incidents | Service availability monitoring, incident response planning, SLA tracking, maintenance scheduling |
| **Alert** | Azure Monitor alert activations, resolutions, and state changes | Alert management, performance monitoring, automated response tracking, alert effectiveness analysis |
| **Recommendation** | Azure Advisor recommendations for cost, performance, security, and reliability | Cost optimization initiatives, performance improvements, security hardening, operational excellence |
| **Policy** | Azure Policy evaluation results, compliance states, and enforcement actions | Compliance monitoring, governance enforcement, policy effectiveness measurement, regulatory reporting |
| **Autoscale** | Azure autoscale operations, scaling decisions, and capacity adjustments | Performance optimization, cost management, capacity planning, scaling effectiveness analysis |
| **ResourceHealth** | Resource-specific health events, availability status, and degradation alerts | Resource availability monitoring, proactive troubleshooting, maintenance planning, SLA monitoring |

## Log Categories Overview

### Entra Logs Focus Areas
- **Identity and Access Management**: User authentication, authorization, and identity lifecycle
- **Security Posture**: Risk detection, conditional access, identity protection
- **Application Access**: Service principal authentication, API usage patterns
- **Network Access**: Global Secure Access (GSA) traffic, remote network health
- **Compliance**: Audit trails, provisioning activities, administrative changes

### Activity Logs Focus Areas  
- **Resource Management**: Infrastructure changes, policy compliance, governance
- **Operational Health**: Service availability, performance monitoring, recommendations
- **Cost Management**: Resource optimization, scaling decisions, advisor recommendations
- **Security Operations**: Security alerts, policy enforcement, compliance monitoring

## Configuration and Routing

Both Entra and Activity logs are configured through **Azure Diagnostic Settings** and can be routed to multiple destinations:

### Supported Destinations
- **Log Analytics Workspace**: For advanced querying with KQL (Kusto Query Language)
- **Azure Storage Account**: For long-term retention and compliance archival
- **Azure Event Hub**: For real-time streaming to external systems
- **Partner Solutions**: Integration with third-party SIEM and monitoring tools