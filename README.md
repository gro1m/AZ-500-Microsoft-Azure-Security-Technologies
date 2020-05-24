# AZ-500-Microsoft-Azure-Security-Technologies

## Session 1
### Topics
*Identity and Access*: 
Azure AD, Users and Groups, Azure AD Roles, MFA, SSPR, App registration, Azure AD custom domains, Azure AD Connect.

### Summary
- AAD : Azure Active Directory is an identity service.
- Identity: AAD account, AAD tenant, AAD subscription.
- https (web-based service through REST-API): 
  - oAuth
  - OpenID
  - SAML
  - Catalogue (flat)
  - No OU (Organizational Unit)
  - No GPO (Group Policy Object)
  - No LDAP (Lightweight Directory Access Protocol)
  - No Kerberos
  - No NTLM (New Technology LAN Manager)
- Authentication ruled via 
  - User catalogue
  - MFA
  - Self-Service Passowrd Reset
  - Conditional Access Policies.
  
|   |**FREE**   | **OFFICE 365 APPS**  |**PREMIUM P1**   |**PREMIUM P2**   |
|---|---|---|---|---|
| **Core Identity and Access Management**  |   |   |   |   |
| Directory Objects1	| 500,000 Object Limit	| No Object Limit	| No Object Limit	| No Object Limit  |
|   |   |   |   |   |

### Reading
1. Student Handbook: “Module 1 – Manage Identity and Access”. 
2. Azure AD official documentation: https://docs.microsoft.com/en-us/azure/active-directory/ 
3. Azure Identity best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_03_MFA.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_04_App_Registration.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_05_Application_Service_Principal.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_06_RBAC.md 
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-groups-members-azure-portal 
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-groups-create-azure-portal 
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-users-profile-azure-portal 

## Session 2
### Topics
*Identity and Access*: 
RBAC, Azure AD Privileged Identity Management, Identity Protection, Switch tenant. 
 
*Platform protection*: 
Shared responsibility model, Virtual Networks and subnets, Virtual Network Gateway, Load Balancer, Traffic Manager. 

### Reading
1. Student Handbook: “Module 2 – Implement Platform Protection” => “Understand cloud security”, 
“Implement network security” 
2. Azure AD PIM official documentation: https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure 
3. Azure Virtual Networking official documentation: https://docs.microsoft.com/en-us/azure/virtual-network/  
4. Azure Virtual Networking security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_01_PIM.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_09_Subscriptions.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_04_Create%20a%20VNet.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_10_Load%20Balancer%20and%20App%20Gateway.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_08_VNet%20Peering.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_18_Custom%20Domains.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_09_Azure%20DNS.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_19_Private%20DNS.md 

## Session 3
### Topics
*Platform protection*: 
Network Security Groups, NVA, forced tunneling, UDR, Azure Firewall, DDoS protection.  
VM Security: Admin access.

### Reading
1. Student Handbook: “Module 2 – Implement Platform Protection” => “Secure the network”, “Implement host security”  
2. Azure VMs security official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/virtual-machines-overview 
3. Azure IaaS security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/iaas 
4. Security recommendation for Azure Windows VMs official documentation: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/security-recommendations

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_11_VPN%20Gateways%20and%20Tunnelling.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_05_NSGs.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_06_NVA.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_12_Azure%20Firewall.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_15_DDoS%20Protection.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_13_Secure%20Admin%20Access.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_14_Azure%20Bastion.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_16_Antimalware.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_17_Update%20Management.md 

## Session 4
### Topics
*Platform protection*: 
VM Security: Antimalware, Security Center, Updates, Availability Set.  
Management Groups, Azure Resource Manager, locks, Azure Policy. 
### Reading
1. Student Handbook: “Module 2 – Implement Platform Protection” => “Configure security policies by using Microsoft Azure Security Center”, “Implement subscription security”  
2. Azure Windows VM availability sets official documentation: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/manage-availability 
3. Azure Container instances security official documentation: https://docs.microsoft.com/en-us/azure/container-instances/container-instances-image-security 
4. Azure Policy official documentation: https://docs.microsoft.com/en-us/azure/governance/policy/overview 
### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_02_Function%20Apps.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_08_Azure_Locks.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_07_Azure_Policy.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_20_Azure%20Blueprints.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_03_Create%20a%20Kubernetes%20Cluster.md 

## Session 5
### Topics
*Security operations*: 
Serverless apps and containers security (Continue). 

Azure Monitor, Log Analytics, diagnostic logging. 
### Reading
1. Student Handbook: “Module 3 – Manage Security Operations” => “Configure security services”, “Configure security policies by using Microsoft Azure Security Center”  
2. Azure Monitor official documentation: https://docs.microsoft.com/en-us/azure/azure-monitor/overview 

3. Azure Security Center official documentation: https://docs.microsoft.com/en-us/azure/security-center/security-center-intro 

4. Azure Operational Security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/operational-best-practices
### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_01_Azure%20Monitor.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_02_Security%20Center.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_07_Secure%20score%20in%20Azure%20Security%20Center.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_05_Manage%20endpoint%20protection%20issues.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_01_Monitor%20%26%20Autoscale.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_09_JIT.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_04_Azure%20Sentinel.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_06_Security%20Playbook%20in%20Azure%20Sentinel.md 

## Session 6
### Topics
*Security operations*: 
Security alerts, security baseline. 

*Secure data and applications*: 
Data classification, Azure SQL firewall, Azure SQL Database Advanced Data Security, SAS. 

### Reading
1. Student Handbook: “Module 3 – Manage Security Operations” => “Manage security alerts”, “Respond to and remediate security issues”, “Create security baselines” 
2. Student Handbook: “Module 4 – Secure Data and Applications” => “Configure security policies to manage data”, “Configure security for data infrastructure” 
3. Azure SQL data classification official documentation: https://docs.microsoft.com/en-us/azure/sql-database/sql-database-data-discovery-and-classification 
4. Azure SQL Advanced Data Security official documentation: https://docs.microsoft.com/en-us/azure/sql-database/sql-database-advanced-data-security 
5. Storage Access Signatures (SAS) official documentation: https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview 
6. Azure Security Alerts official documentation: https://docs.microsoft.com/en-us/azure/security-center/security-center-alerts-overview

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_08_Create%20security%20baselines.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_01_Classify%20a%20SQL%20Database.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_02_Auditing%20a%20Database.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_03_Analyze%20audit%20logs%20and%20reports.md 

## Session 7
### Topics
*Secure data and applications*: 
Azure SQL Database Always Encrypted, Storage encryption, Azure Disk encryption, Azure Backup encryption, Web App for containers, Application Insights, Microsoft Security Development Lifecycle.
### Reading
1. Student Handbook: “Module 4 – Secure Data and Applications” => “Configure encryption for data at rest”, “Understand application security”, “Implement security for application lifecycle” 
2. Azure Disk Encryption official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/azure-disk-encryption-vms-vmss 
3. Azure SQL Database Always Encrypted official documentation: https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-database-engine?redirectedfrom=MSDN&view=sql-server-ver15 
4. Azure Application Security (Azure Architecture Framework) official documentation: https://docs.microsoft.com/en-us/azure/architecture/framework/security/applications-services 
5. Azure Application secure development and lifecycle management official documentation: https://docs.microsoft.com/en-us/azure/security/develop/secure-dev-overview 
### Labs
- https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart 
- https://docs.microsoft.com/en-us/azure/storage/common/storage-encryption-keys-portal 

## Session 8
### Topics
*Secure data and applications*: 
Managed Identity, PaaS firewall and Service Endpoint, Front Door, Key Vault 
### Reading
1. Student Handbook: “Module 4 – Secure Data and Applications” => “Secure applications”, “Configure and manage Microsoft Azure Key Vault” 
2. Azure Network Service Endpoint official documentation: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview 
3. Azure Front Door official documentation: https://docs.microsoft.com/en-us/azure/frontdoor/front-door-overview 
4. Azure Key Vault official documentation: https://docs.microsoft.com/en-us/azure/key-vault/general/overview
### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_02_Key_Vault.md 
- https://docs.microsoft.com/en-us/azure/virtual-network/tutorial-restrict-network-access-to-resources 
- https://docs.microsoft.com/en-us/azure/frontdoor/quickstart-create-front-door 
