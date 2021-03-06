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
  - Self-Service Password Reset
  - Conditional Access Policies.
  
https://azure.microsoft.com/en-us/pricing/details/active-directory
|   |**FREE**   | **OFFICE 365 APPS**  |**PREMIUM P1**   |**PREMIUM P2**   |
|---|---|---|---|---|
| **Core Identity and Access Management**  |   |   |   |   |
| Directory Objects	| 500,000 Object Limit	| No Object Limit	| No Object Limit	| No Object Limit  |
| Single Sign-On (SSO)  | <ul><li> [x] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [x] </li></ul>|
|User provisioning |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Federated Authentication (ADFS or 3rd party IDP) |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|User and group management (add/update/delete) |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Device registration |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Cloud Authentication (Pass-Through Auth, Password Hash sync, Seamless SSO) |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Azure AD Connect sync (extend on-premises directories to Azure AD) |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Self-Service Password Change for cloud users |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Azure AD Join: desktop SSO & administrator bitlocker recovery |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Password Protection (global banned password) |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Multi-Factor Authentication3 |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Basic security and usage reports |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Business to Business Collaboration** | | | |
|Azure AD features for guest users |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Identity & Access Management for Office 365 apps** | | | |
|Company branding (customization of logon & logout pages, access panel) |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Self-service password reset for cloud users |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Service Level Agreement (SLA) |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Device write-back (device objects two-way synchronization between on-premises directories and Azure) |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Premium Features** | | | |
|Password Protection (custom banned password) |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Password Protection for Windows Server Active Directory (global & custom banned password) |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Self-service password reset/change/unlock with on-premises write-back |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Group access management |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Microsoft Cloud App Discovery5 |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Azure AD Join: MDM auto enrollment & local admin policy customization |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Azure AD Join: self-service bitlocker recovery, enterprise state roaming |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Advanced security and usage reports |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Hybrid Identities** | | | |
|Application Proxy |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Microsoft Identity Manager user CAL |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Connect Health |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Advanced Group Access Management** | | | |
|Dynamic groups |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Group creation permission delegation |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Group naming policy |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Group expiration |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Usage guidelines |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Default classification |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Conditional Access** | | | |
|Conditional Access based on group, location, and device status |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Azure Information Protection integration |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|SharePoint limited access |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Terms of Use (set up terms of use for specific access) |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Multi-Factor Authentication with Conditional Access |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|Microsoft Cloud App Security integration |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|3rd party identity governance partners integration |NA |NA |<ul><li> [x] </li></ul> |<ul><li> [x] </li></ul>
|**Identity Protection** | | | |
|Vulnerabilities and risky accounts detection |NA |NA |NA |<ul><li> [x] </li></ul>
|Risk events investigation |NA |NA |NA |<ul><li> [x] </li></ul>
|Risk based Conditional Access policies |NA |NA |NA |<ul><li> [x] </li></ul>
|**Identity Governance** | | | |
|Privileged Identity Management (PIM) |NA |NA |NA |<ul><li> [x] </li></ul>
|Access Reviews |NA |NA |NA |<ul><li> [x] </li></ul>
|Entitlement Management |NA |NA |NA |<ul><li> [x] </li></ul>
|---|---|---|---|---|
|**Price** |Free |O365 E1, E3, E5, F1, F3 |$6 user/month |$9 user/month


User:
- *Guest* - Microsoft Account (no MFA)
- *Member* - Azure Active Directory
- *synchronized* - Windows Server Active Directory.

add massive amount of users:
- use Az-User cmdlet with .csv

*Manage Security defaults* has to be set to False if you use *Conditional Access*.

New Group -> Membership type.
If someone moves department, should lose permissions -> dynamic user in Azure AD Premium P2.

*Azure Active Directory* is used to manage
- Users
- Groups
- Roles

*Subscription* 
- is linked to AAD 
- you cannot have a subscription without AAD but the opposite is possible.
- The licenses of the subscription are not coupled to AAD.
- do not use AAD Roles inside Subscription.


### Reading
1. Student Handbook: “Module 1 – Manage Identity and Access”. 
2. Azure AD official documentation: https://docs.microsoft.com/en-us/azure/active-directory/ 
3. Azure Identity best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_03_MFA.md 
  - Enable Security defaults: No -> Security > Conditional Access | Policies: + Add Policy
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_04_App_Registration.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_05_Application_Service_Principal.md 
  - service principal: code/app identity to create/modify resources.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_06_RBAC.md 
  - how to create user via Powershell:
  ```powershell
  Connect-AzureAD
  $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
  $PasswordProfile.Password = "Pa55w.rd"
  New-AzureADUser -DisplayName "Mark" -PasswordProfile $PasswordProfile     -UserPrincipalName "Mark@yourdomain.onmicrosoft.com" -AccountEnabled $true -MailNickName "Mark"
  Get-AzureADUser # gets list of Users in Azure AD
  ```
  - how to create groups via Powershell:
  ```powershell
  Connect-AzureAD
  New-AzureADGroup -DisplayName "Junior Admins" -MailEnabled $false -SecurityEnabled $true -MailNickName JuniorAdmins
  ```
  - how to assign roles via Powershell:
  ```powershell
  $sub_id = Get-AzSubscription | Select-Object -ExpandProperty Id | Out-String
  $subScope = "/subscriptions/$sub_id" | Out-String
  New-AzRoleAssignment -SignInName bill@yourdomain.onmicrosoft.com -RoleDefinitionName "Reader" -Scope $subScope 
  Get-AzRoleAssignment -SignInName bill@yourdomain.onmicrosoft.com -Scope $subScope
  Get-AzRoleAssignment -SignInName bill@yourdomain.onmicrosoft.com     -ResourceGroupName "myRBACrg"
  Remove-AzRoleAssignment -SignInName bill@yourdomain.onmicrosoft.com -RoleDefinitionName "Contributor" -ResourceGroupName "myRBACrg"
  Remove-AzRoleAssignment -SignInName bill@yourdomain.onmicrosoft.com -RoleDefinitionName "Reader" -Scope $subScope
  Remove-AzResourceGroup -Name "myRBACrg"
  ```
  - how to create user via Azure CLI:
  ```bash
  az ad user create --display-name Tracy --password Pa55w.rd --user-principal-name Tracy@yourdomain.onmicrosoft.com
  az ad user list # gets list of Users in Azure AD
  ```
  - how to create groups via Azure CLI:
  ```bash
  az login
  az ad group create --display-name ServiceDesk --mail-nickname ServiceDesk
  ```
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-groups-members-azure-portal 
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-groups-create-azure-portal 
- https://docs.microsoft.com/en-us/azure/active-directory/active-directory-users-profile-azure-portal 

## Session 2
### Topics
*Identity and Access*: 
RBAC, Azure AD Privileged Identity Management, Identity Protection, Switch tenant. 
 
*Platform protection*: 
Shared responsibility model, Virtual Networks and subnets, Virtual Network Gateway, Load Balancer, Traffic Manager. 

### Summary
1 subscription belongs to only one tenant.
Azure AD is an authentication service, it is an identity provider and authenticator for subscriptions. The Azure Resource Manager "connects" AAD to the individual subscriptions.
RBAC: https://docs.microsoft.com/en-us/azure/role-based-access-control/overview
Service Principal comes from AAD.
Scope -> roles are inherited:
- If someone Reader on Management Group and Contributor on Subscription, then also Contributor on Resource in that Subscription.
- Deny access is highest priority.
non-service oriented roles:
- Owner
- Contributor 
- Reader
To see other roles, e.g. Roles > Virtual Machine Contributor > Permissions.
```powershell
help *-AzRole*
Get-AzRoleDefinition -Name Owner
Get-AzRoleDefinition | Select Name
Get-AzRoleDefinition -Name "Virtual Machine Contributor" | ConvertTo-JSON
```
Custom Role Definitions

#### Azure AD Privileged Identity Management (PIM)
- assignment for particular time
- access reviews -> signed
- Azure AD Roles - authorization to manage services
- Azure Subscription - RBAC roles give authorization to manage ressources 
- JIT gives just-in-time access to managing AAD Roles and RBAC roles.
- assignment is always for a particular time
- first Global Administrator that has enabled PIM is the only one who can manage PIM.
- Others need to have to have Role of *Privileged Role Administrator*
- only works for Premium P2 licenses.

assignment:
- eligible: role assigned but access not activated.
- active: role is active right now.

Account Admin is Billing Owner. Change Billing Owner by *Transfer Billing Ownership*.

#### Azure Identity Protection
Risk classification:
- Sign-In risk:
  - anonymous IP address
- User risk:
  - leaked credentials
  
Risk level:
- low
- medium
- high

#### Application proxy
- registered in App registration
- add platform redirect URIs
- loop: AAD connector service to Web and from Web via URL App Proxy back to AAD
- Branding Enterprise Applications Assign Users and Groups

Glossary: https://docs.microsoft.com/en-us/azure/active-directory/develop/developer-glossary#security-token

Overview of Microsoft Authentication Library (abbreviated as MSAL):
- ADAL -> v1.0 endpoint
- MSAL -> v2.0 endpoint

- Application types for Microsoft identity platform
- JWT tokens

#### Conditional access policies
Security -> Conditional access policies:
https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview
Named Location
- IP ranges
- Policies
Signal:
- everything that signifies activity.
- Users
- Location
- IP address
Condition:
- checks signal, triggers control mechanism
Control:
- block or grant access (control block)

#### MFA (Multi-factor authentication)
More than one verification method:
- username and password
- SMS
- Phone call
- Authenticator app
- etc.
MFA Registration
Good practice: Admins should also have MFA.

#### Self-Service Password Reset (SSPR)
- AAD to on-prem ADDS is per-se one-way connection, so no way to reset password in Cloud
  - Use Write Back Configured in AD Connect.
- Synchronize on-prem ADDS with AAD via ADConnect
- aka.ms/sspr

#### Single Sign-On (SSO)
- not re-enter credentials

#### Sychronization Methods
https://docs.microsoft.com/en-us/microsoft-365/education/deploy/aad-connect-and-adfs
1. Password Hash Synchronization:
   - recommended
2. Pass-Through Synchronization:
  - only Identity without password
  - needs on-prem ADDS
3. AD FS Synchronization
  - FS: Federation Services
  
AAD -> Global Administrator role
ADDS -> Enterprise Admin

#### Application Gateway
- OSI Level 7 load balancing
- http/https requests

#### Web Application Firewall (WAF)
- security checks on incoming traffic based on OWASP recommendations

#### Traffic Manager
- load balancer for DNS requests
- e.g. closest website e.g. choose between EU and US region for a certain user.


### Reading
1. Student Handbook: “Module 2 – Implement Platform Protection” => “Understand cloud security”, 
“Implement network security” 
2. Azure AD PIM official documentation: https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure 
3. Azure Virtual Networking official documentation: https://docs.microsoft.com/en-us/azure/virtual-network/  
4. Azure Virtual Networking security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_01_PIM.md 
  ```powershell
  Get-AzRoleDefinition
  Connect-AzureAD
  $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
  $PasswordProfile.Password = "Pa55w.rd"
  $domainObj = get-azureaddomain
  $domain = $domainObj[0].name
  New-AzureADUser -DisplayName "Isabella Simonsen" -PasswordProfile $PasswordProfile -UserPrincipalName "Isabella@$domain" -AccountEnabled $true -MailNickName "Isabella" -UsageLocation "US"
  ```
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_09_Subscriptions.md
  - Cost Management + Billing > Subscriptions and click Manage.
  - Click Transfer Billing Ownership.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_04_Create%20a%20VNet.md 
  - Creating Virtual Networks and installing ICMP on one of the VMs in the same subnet lets the other VM successfully ping the first VM that has ICMP installed.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_10_Load%20Balancer%20and%20App%20Gateway.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_08_VNet%20Peering.md 
  - Virtual networks can be connected with virtual network peering. 
  - These VNets can be in the same region or different regions (also known as Global VNet peering). 
  - The resources of peered VNets are able to communicate with each other, with the same latency and bandwidth as if the resources were in the same virtual network. 
  - The VNets have to be in same resource group
  - You need to enable Internet Control Message Protocol (ICMP) on VM, e.g. VM1:
  ```powershell
  New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4
  ```
  - Connect to VM2 from VM1 via:
  ```powershell
  mstsc /v:10.1.0.4 # 10.1.0.4 is VM2's VNet IPadress
  ``
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_18_Custom%20Domains.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_09_Azure%20DNS.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_19_Private%20DNS.md 

## Session 3
### Topics
*Platform protection*: 
Network Security Groups, NVA, forced tunneling, UDR, Azure Firewall, DDoS protection.  
VM Security: Admin access.

### Summary
#### Networking
- CIDR notation: https://www.digitalocean.com/community/tutorials/understanding-ip-addresses-subnets-and-cidr-notation-for-networking.
- Virtual Networks: https://docs.microsoft.com/en-us/azure/virtual-network/security-overview
IP address space, e.g. 10.10.0/16 -> subnet e.g. 10.10.1.0/24: CIDR IP subnet masks follow IPv4 protocol.
Virtual Net with same space of IP addresses will not be connected to outside.
IP address spaces for each subnet should be different, as networks with same IP address space cannouted be routed together.
Subnets inside a VNet are interconnected by system routes.
IP addresses:
- private always with VNets (dynamic or static)
- public: dynamic or static. For production has to be static.
Connection possibilites:
- VNet-2-VNet
- VPN connection using VPN Gateways
- Site-2-Site via IPSec tunnel
- VNet peering: 
  - more secure because it goes through Microsoft network backbone infrastracture.
  - allows to connect globally (global VNet peering).
 
 Hub-and-spoke (STAR):
 - Hub: security appliance
   - on-prem can connect to Hub via Virtual Network Gateway on Hub.
 - Spoke: 
   - routed through hub
   - hub has peering to individual spokes, but the spokes are not peered by the default ("VNet peering is not transitive by default")
   
 Virtual Network Gateway:
 - site-to-site connection between VNets or VNet and Gateway.
 Connect on-prem to Virtual Network Gateway:
 1) Create VPN Gateway Subnet.
 2) Create VPN Gateway.
 3) Create Local Network Gateway
 4) Connect
 
 Tool for inspecting Network architecture on Azure: Network Watcher > Topology.
 ExpressRoute always runs over Microsoft device
 
 Load Balancer:
 - public: internet-facing
 - private: virtual subnet-facing
 - OSI level 4 that balances the requests on the front-end pool to the backend-pool, e.g. VMs.


#### Network Security Group
- simple packet filter and control
- 5-tuple rule:
  - Source IP address
  - Source Port
  - Destination IP
  - Destination Port
  - Protocol:
    - TCP
    - UDP
- Allow/Deny rules

Predefined default rules exist for inbound and outbound traffic. You can’t delete these rules, but you can override them, because they have the lowest priority. The default rules allow all inbound and outbound traffic within a virtual network, allow outbound traffic towards the internet, and allow inbound traffic to an Azure load balancer. A default rule with the lowest priority also exists in both the inbound and outbound sets of rules that denies all network communication.

priority:
- lowest number has highest priority

inbound traffic:
- first through Subnet and then through Network Interface Card
outbound traffic:
- first through Network Interface Card and then through Subnet
best practice:
assign NSG rules on Subnet level.

#### Application Security Group (ASG)
Network Virtual Appliance (NVA)
- typically set of VMs
- packet inspection filter

UDR
- user-defined routing
- routing table associated with particular subnet.

#### Azure Firewall
- stateful service
- less dummy than NSGs
- packet filter
- NVA for Routing
- automatically scalable enterprise-level service
- subnet has to be named *Azure Firewall Subnet* 
- similiar to Threat Management Gateway

Fully-Qualified Domain Names (FQDN):
- Target FQDNs e.g. *google.com

Distributed-Denial-of-Service (DDoS):
- Level 3 and 4 of OSI model
- Standard DDoS plan

https://www.ixiacom.com/products/breakingpoint_cloud

#### VM Security: Admin access
Why bad practice to expose RDP to public internet?
- prone to DDoS attack on level 3 or 4.

better practice: avoid public IP access assignment to VMs at all

Options to access VMs with private IP addresses
1) BASTION (encrypted-in-browser https session) - does not need public IP address (similar to Remote Stop Gateway Service)
2) connect via Jumphost/Jumpbox/Privileged access station VM inside Management Subnet with NSG available via Public IP address
3) DNAT with Firewall
4) Best practice: VPN Gateway on VNet (highly secure world)
   - connect on-prem network to VPN Gateway (via S-2-S (site-to-site))
   - connect from Home to on-prem via VPN (P-2-S (point-to-site))
   - connect from Home to Azure VNet directly also via P-2-S
5) ExpressRoute 
   - direct connection from on-prem to Azure.
   
specific Roles for VMs (Virtual Machine User Login, Virtual Machine Contributor, Virtual Machine Administrator Login)

VMs configure specificpublic Internet address on which you go out:
NAT Gateway:
- SNAT (Source Network Address Translation)
- assign on Subnet level inside VNet.

### Reading
1. Student Handbook: “Module 2 – Implement Platform Protection” => “Secure the network”, “Implement host security”  
2. Azure VMs security official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/virtual-machines-overview 
3. Azure IaaS security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/iaas 
4. Security recommendation for Azure Windows VMs official documentation: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/security-recommendations

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_11_VPN%20Gateways%20and%20Tunnelling.md 
  - Deploy a custom template
  - Create Virtual Network inside Resource Group with Subnet
  - Create Gateway Subnet and Virtual Network Gateway:
    - On VNet > Subnets > Add Gateway Subnet.
    - Networking > Virtual Network Gateways 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_05_NSGs.md 
  - You can filter network traffic inbound to and outbound from a virtual network subnet with a network security group. Network security groups contain security rules that filter network traffic by IP address, port, and protocol. Security rules are applied to resources deployed in a subnet.
  - An application security group enables you to group together servers with similar functions, such as web servers.
  - Select your NSG > Settings > Subnets >+ Associate: Under Associate subnet, under Virtual network select your VirtualNetwork. Then under Subnet, select your subnet and then select OK.
  - Connect to other VM in same Virtual Network -> Powershell Command:
  ```powershell
  mstsc /v:myVmWeb
  ```
  - Install IIS via PowerShell (to open Internet Website by Microsoft):
  ```powershell
  Install-WindowsFeature -name Web-Server -IncludeManagementTools
  ```
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_06_NVA.md 
  - Azure routes traffic between all subnets within a virtual network, by default. You can create your own routes to override Azure's default routing. The ability to create custom routes is helpful if, for example, you want to route traffic between subnets through a network virtual appliance (NVA). NVAs are VMs that help with network functions like routing and firewall optimization. 
  - Create Route Table. Then under Route Table Settings select Routes and then add Route.
    - The next hop handles the matching packets for this route. It can be the virtual network, the virtual network gateway, the Internet, a virtual appliance, or none. Virtual network gateways can't be used if the address prefix is IPv6.
 - The trace route tool to test routing uses the Internet Control Message Protocol (ICMP), which the Windows Firewall denies by default. Enable ICMP through the Windows firewall:
   ```powershell
   New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4
   ```
 - Connect to myVmNva:
   ```powershell
   mstsc /v:myvmnva
   ```
- Turn on IP forwarding:
  ```powershell
  Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name IpEnableRouter -Value 1
  ```
  Needs Restart afterwards.
- Test trace routes:
  ```powershell
  tracert myVmPrivate
  ```
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_12_Azure%20Firewall.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_15_DDoS%20Protection.md 

- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_13_Secure%20Admin%20Access.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_14_Azure%20Bastion.md 
  - create a Resource Group and Virtual Machine and VNet 
  ```powershell
  New-AzResourceGroup -Name myResourceGroup -Location "East US"
  New-AzVm -ResourceGroupName "myResourceGroup" -Name "myVM" -Location "East  US" -VirtualNetworkName "myVnet" -SubnetName "mySubnet" -SecurityGroupName   "myNetworkSecurityGroup"
  ```
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_16_Antimalware.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_17_Update%20Management.md 

## Session 4
### Topics
*Platform protection*: 
VM Security: Antimalware, Security Center, Updates, Availability Set.  
Management Groups, Azure Resource Manager, locks, Azure Policy.

### Summary
#### VM-Security: Availability Set
datacenter:
- has multiple server racks
- each server rack is a so-called *fault domain*
- each server contains update-domains

availability zone:
- 2-3 datacenters in a certain region that are high-speed (via optical fibers) interconnected.

availability set:
- Your VM would be spread across update and fault domains but it could happen that your Azure VM is running within the sam datacenter (e.g. same building).


#### VM-Security: Azure Security Center
- scans Azure subscription resources by default
- deploys Azure Policy on subscriptions which in turn triggers a *Detect-Prevent-Alert* mechanism
- Pricing and settings:
  - Free
  - Standard: protect and alert.

#### VM-Security: Antimalware
Cloud has shared responsibility model, but Azure has Antimalware solutions.

#### VM-Security: Updates
Native to Azure: Update Management solution
Machines that are managed by Update Management use the following configurations to perform assessment and to update deployments:

- Log Analytics agent for Windows or Linux
- PowerShell Desired State Configuration (DSC) for Linux
- Automation Hybrid Runbook Worker (Automation Account)
- Microsoft Update or Windows Server Update Services (WSUS) for Windows machines

https://docs.microsoft.com/en-us/azure/automation/automation-update-management

![](images/updates.png)

#### VM-Security: Management group
- lets you group subscriptions
- you can have nested management groups
- you can have up to six levels of management groups
- Root Managemnet Group is created by default
- on level of management group you assign RBAC and Policies for Centralized management.


#### VM-Security: Azure Resource Manager (ARM)
- https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/overview
- management layer for entire Azure infrastructure
- Requests by tools go to Azure Resource Manager that sends requests to Resource Provider e.g. for VMs Compute, Storage Storage Account, etc.
- AAD provides users, groups, principals  (identity for authentication)
- also acts as authorization service additionally to authentication. ARM checks RBAC assignments.
- additional features: 
  - Azure Policy
  - Azure Locks


#### VM-Security: locks
- https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
- automatic inherits to down-side levels.
- can be assigned on subscription, resource group, resource
- has 2 lock actions
  - read-only
  - delete (does not prevent creation)
- roles that can create locks:
  - Owner
  - User Access Administrator


#### VM-Security: Azure Policy
- https://docs.microsoft.com/en-us/azure/governance/policy/overview
- https://docs.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure
- assign on management group, subscription, resource group
- group policies to initiative
- under-the-hood just a JSON file (policy definition) with an if-then evaluation.
- Effect: what to do if policy not met, e.g. audit (send message to portal dashboard) or deny.
  - https://docs.microsoft.com/en-us/azure/governance/policy/concepts/effects
  - be careful with *DeployIfNotExists*
2 options:
- 1. Evaluation: scheduled every hour.
- 2. Check on the ARM call


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
  - When you learn how to create and assign blueprints, you can define common patterns to develop reusable and rapidly deployable configurations based on Azure Resource Manager templates, policy, security, and more. In this tutorial, you learn to use Azure Blueprints to do some of the common tasks related to creating, publishing, and assigning a blueprint within your organization.
  - Artifacts that you can select:
    - Policy Assignment
    - Role Assignment
    - Azure Resource Manager Template (Subscription)
    - Resource group
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_03_Create%20a%20Kubernetes%20Cluster.md 
  - Create Ressource Group and Kubernetes Cluster via Bash:
    ```bash
    az group create --name myAKSResourceGroup --location eastus
    az aks create  --resource-group myAKSResourceGroup --name myAKSCluster --node-count 1 --enable-addons monitoring --generate-ssh-keys
    ```
  - Connect to Kubernetes Cluster via Bash:
    ```bash
    az aks get-credentials --resource-group myAKSResourceGroup --name myAKSCluster
    ```
  - Verify cluster connection by returning list of cluster nodes:
    ```bash
    kubectl get nodes
    ```
  - Run application:
    ```bash
    kubectl apply -f https://raw.githubusercontent.com/MicrosoftLearning/AZ-500-Azure-Security/master/Allfiles/Labs/Mod2_Lab03/azure-vote.yaml
    ```
  - Test application:
    ```bash
    kubectl get service azure-vote-front --watch # watch to monitor progress
    ```
  - Monitor health and logs:
    - Select Cluster -> Under Monitoring>Insights>Namespace>View Containers.
  - Delete cluster:
    ```bash
    az group delete --name myAKSResourceGroup --yes --no-wait # --no-wait option runs the command in the background
    ```

## Session 5
### Topics
*Security operations*: 
Serverless apps and containers security (Continue). 

Azure Monitor, Log Analytics, Alerts, diagnostic logging. 

### Summary
Serverless: 
- develop certain type of code (options: Functions, Logic Apps) and run code with trigger executed on an execution environment (typically application services). You do not care about execution environment.
functions should not run too long.
- Possible Plan types:
  - Consumption (Serverless)
  - Premium
  - App Service Plan
- Pricing Tier:
  - Dynamic
  - Free
- you can set:
  - can be code or Docker container
  - Runtime stack
  - Version
  - Region
  - either Linux or Windows OS
  - Application Insights Monitoring

Durable Functions: https://docs.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-overview?tabs=csharp

Security Considerations (similar to Web App because underlying platform is App Service):
- Deployment Center to deploy functions 
- Deployment slots
- Configuration:
  - Application settings
  - Function runtime settings
  - General settings: 
    - *Always on* is disabled for free tier - only enabled on Standard S1 tier.
- Authentication / Authorization: App Service Authentication can be turn to *On* and then choose authentication provider such as Azure AAD.
- Backups can be enabled
  - Snapshots require a Premium App Service plan
  - backup need minimally Standard S1 plan - can be one-time or scheduled backups.
- Custom domains:
  - you should not use generic Microsoft URL *.azurewebsites.net*, but custom enterprise domains
  - need D1 plan if Dev/Test, otherwise for production minimally S1.
  - you can use SSL configuration and manual scaling and more powerful VM for B1 plan in Dev/Test, otherwise S1 for production
- TLS/SSL settings:
  - *HTTPS only* is by default disabled, i.e. HTTP also allowed
  - *Minimum TLS Version* by default is 1.2.
  - you can upload Private KEy Certifcates (.pfx) or Create App Service Managed Certificate and then you can add TLS/SLL binding. 
  - you can upload Public Key Certificate
- Networking:
  - VNet Integration
    - you can use Function or Web App with VNet Integration 
    - only outbound connection, so you can connect Function or Web App to VNet - from VNet to Function/WebApp is not available
  - hybrid connection
    - you can configure IP port connections (tunneling) 
    - Point-to-Point Connection
- API Management:
  - API: subset of functions based on Application Services
  - hide underlying APIs (backend) behind one big API proxy (frontend)
  - just URL of API Management and through slash you connect to particular APIs e.g. Function Apps, Container Services, Web Apps.
  - you can enable Azure AD Authentication on API Management level.
- API:
  - frontend configuration
  - inbound processing: request to backend
    - you can configure policies. -> you can use show snippets
  - backend: http(s) endpoint.
  - outbound processing: modify response before it is sent to the client
    - you can configure policies. -> you can use show snippets
- Scale up (vertical scaling)
  - increase power of VM
  - dev/test, production and isolated environments
- Scale out (horizontal scaling)
  - increases copies of VM

#### Container security
Azure Container Registry (ACR):
- repository for docker container images
- Access Control (IAM) > Role assignments:
  - service-specific roles are AcrDelete, AcrPull, AcrPush, AcrImageSigner etc.
- Encryption > Customer-managed keys
- Networking > (Endpoints / PaaS Firewalls)
- Replications
  - motivation: high availability and you can spread load for your registries
- Policies > Content Trust:
  - if enabled you can push signed and trusted containers
  - needs Premium tier for this registry
- Security Center > Pricing and Settings > Pricing tier (Standard):
  - enable Container Registries checks vulnerabilities

Azure Kubernetes Service (AKS):
- https://docs.microsoft.com/en-us/azure/security-center/container-security
- https://docs.microsoft.com/en-us/azure/container-instances/container-instances-image-security
- https://azure.microsoft.com/de-de/resources/container-security-in-microsoft-azure/
- https://docs.microsoft.com/en-us/azure/security-center/monitor-container-security
- https://docs.microsoft.com/en-us/azure/aks/use-network-policies
- Networking: https://docs.microsoft.com/en-us/azure/aks/use-network-policies
- Managed K8s (you do not pay for this)
- connect via public API URL (via kubectl) to Managed K8s
- Managed K8s manages pool of hosts in which you run containers called *pod* (automatic scheduling).
- To connect privately, there is an option:
  - https://docs.microsoft.com/en-us/azure/aks/private-clusters
- Access via Azure AD:
  - https://docs.microsoft.com/en-us/azure/aks/azure-ad-integration
  - `powershell az aks get-credentials --resource-group myResourceGroup --name myAKSCluster --admin`
  - Assign AAD Identity to K8s (Kubernetes) platform and use own RBAC:
    - create role
    - create role binding
    - https://docs.microsoft.com/en-us/azure/aks/azure-ad-rbac?toc=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fazure%2Faks%2Ftoc.json&bc=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fazure%2Fbread%2Ftoc.json
  
#### Azure Monitor
Set of services based on 3 databases (where data is stored: STORE):
- Activity Log
  - every operation related to create, update and delete inside Azure Subscription will be logged with information on who (user/service principal), what (action), when (date)
  - not manageable by you
- Metrics
  - value at particular point in time
  - can be grabbed from Azure Resources (platform-level), Custom Metrics (have to be tied to particular Azure resource)
  - supports up to 90 days of retention of metrics from your Resources
  - almost real-time (each metric is ingested in 1-3 minutes)
  - you can use them for:
    - Metric Explorer called *Metrics*
    - you can run Alerts on top of these metrics
    - Azure Portal Dashboards 
  - (can also be connected to Grafana)
- Logs
  - behind the scenes *Log Analytics Workspace*
  - Log Analytics Workspaces
  - you can use KQL (Keyword Query Language) to get data
  - you can create Alerts, Dashboards
  
You can send Custom Logs to Log Analytics Workspace (performance counters and metrics will also be stored as logs) via Microsoft Monitoring Agent (MMA).
  
Insights builds on top of the Logs and Metrics.
Security Center works on top of Log Analytics Workspace.
Azure Sentinel (SIEM) on top of Log Analytics Workspace:
- https://docs.microsoft.com/en-us/azure/sentinel/overview
Log Analytics Workspace is not created by default.


#### Log Analytics Workspace (LAW)
Security Center > Pricing settings > Data Collection > Auto Provisioning > Log Analytics
https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-data-collection
How to Create LAW:
- Add Log Analytics Workspace
- if in connection with Automation Account you need to choose right location

MMA logs or custom logs via HTTP Data Collector API can be pushed to Log Analytics Workspace

Advanced Settings:
- Download Windows Agent (MMA)
- need Workspace ID and key.
- Data > Windows Event Logs > (e.g.) Application Logs
- Data > Windows Performance Counters > ...

You can also use Security Center > Compute ] apps > Add Servers > Log Analytics Workspace.

Workspace Data Sources > Virtual Machines:
- Log Analytics Connection can be *This workspace* or *Other workspace*

Solutions:
- set of rules which collects your data on your agents and pushes it to LAW.
- if enabled for Security Center security logs automatically send to LAW.

Usage and estimated costs:
- pay for log data ingestion
- pay for log data retention (30 days to 2years)
- you can create daily cap but does not include logs by Azure Security Center.

Logs: Query console
- Example:
  ```bash 
  SecurityEvent 
  | where TimeGenerated > ago(3h)
  | where EventID == 4625 and Account contains "AZUREADMIN" #Event ID 4625 for account failed to logon
  ```
- https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-queries

#### Diagnostic settings
If you want to see guest level metrics, need to enable Diagnostic settings.
- unified platform for streaming metrics and logs to somewhere e.g. Log Analytics Workspace, Storage Account, Event Hub (option to send logs to Splunk).

#### Logs
Option to enable logs for VMs.


### Reading
1. Student Handbook: “Module 3 – Manage Security Operations” => “Configure security services”, “Configure security policies by using Microsoft Azure Security Center”  
2. Azure Monitor official documentation: https://docs.microsoft.com/en-us/azure/azure-monitor/overview 

3. Azure Security Center official documentation: https://docs.microsoft.com/en-us/azure/security-center/security-center-intro 

4. Azure Operational Security best practices official documentation: https://docs.microsoft.com/en-us/azure/security/fundamentals/operational-best-practices
### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_01_Azure%20Monitor.md
  - Create Resource Group and VM:
  ```powershell
  New-AzResourceGroup -Name myResourceGroup -Location EastUS
  New-AzVm -ResourceGroupName "myResourceGroup" -Name "myVM" -Location "East  US" -VirtualNetworkName "myVnet" -SubnetName "mySubnet" -SecurityGroupName   "myNetworkSecurityGroup" -PublicIpAddressName "myPublicIpAddress"     -OpenPorts 80,3389
  ```
 - Create Log Analytics Workspace:
   - Under Workspace Data Sources select Virtual Machines
   - Select specific VM and click connect; LAW agent will be automatically installed.
- Collect event and performance of a Windows VM:
  - Click Advanced Settings > Data: Choose Windows Event Logs and Windows Performance Counters.
- View data collected:
  - Select Logs.
  - Type `Perf` into query.
- With User Flows you can track the pathway visitors takes through the various parts of your website.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_02_Security%20Center.md 
  - Azure Security Center is a unified infrastructure security management system that strengthens the security posture of your data centers, and provides advanced threat protection across your hybrid workloads in the cloud - whether they're in Azure or not - as well as on premises. Azure Security Center provides you the tools needed to harden your network, secure your services and make sure you're on top of your security posture.
  - Automate data collection:
    - Security Center collects data from your Azure VMs and non-Azure computers to monitor for security vulnerabilities and threats. Data is collected using the Microsoft Monitoring Agent, which reads various security-related configurations and event logs from the machine and copies the data to your workspace for analysis. By default, Security Center will create a new workspace for you.
  - ![](images/security_center_pricing.png)
  - Security Center > Pricing & Settings > Data Collection: turn Auto-Provisioning to on
  - Security Center: Install Agents tab to install MMA
  - Security Center > Threat protection > Security alerts: see high, medium, low severity security alerts
  - Security Center > Threat protection > Security alerts (map): This map presents security alerts that contain IP addresses targeting your resources. Markings on the map represent sources of the attack on your resources.
  - Security center > Resource security hygiene > Resource health by severity > Compute & apps resources: Now you can review the recommendations.
  

When automatic provisioning is enabled, Security Center installs the Microsoft Monitoring Agent on all supported Azure VMs and any new ones that are created. Automatic provisioning is strongly recommended.
  
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_07_Secure%20score%20in%20Azure%20Security%20Center.md 
  - Security Center > Secure Score > View recommendations: ordered by strongest to least impact.
  - https://docs.microsoft.com/en-us/azure/security-center/security-center-secure-score
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_05_Manage%20endpoint%20protection%20issues.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_2/LAB_01_Monitor%20%26%20Autoscale.md 
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_09_JIT.md 
  - Just-in-time (JIT) virtual machine (VM) access can be used to lock down inbound traffic to your Azure VMs, reducing exposure to attacks while providing easy access to connect to VMs when needed. Brute force attacks commonly target management ports as a means to gain access to a VM. If successful, an attacker can take control over the VM and establish a foothold into your environment. One way to reduce exposure to a brute force attack is to limit the amount of time that a port is open. Management ports don't need to be open at all times. They only need to be open while you're connected to the VM, for example to perform management or maintenance tasks. When just-in-time is enabled, Security Center uses network security group (NSG) and Azure Firewall rules, which restrict access to management ports so they cannot be targeted by attackers.
    - There are three ways to configure a JIT policy on a VM:
      - Configure JIT access in Azure Security Center
        - Security Center > Getting Started > Install Agents. Overview > Compute & app resources > Just-In-Time network access control should be applied on virtual machines. On the JIT VM access configuration blade click Save.
        - REQUEST JIT access: Security Center > Just in time VM access > Configured > select the VM > click REquest Access > select ports you want to open. Note: If a user who is requesting access is behind a proxy, the option My IP may not work. You may need to define the full IP address range of the organization.
        - You can also edit JIT access policy in Configured tab as well as audit JIT access activity by opening Activity log in the Configured tab.
      - Configure JIT access in an Azure VM blade
        - Virtual Machines > select a VM > Configuration > Just-in-time-access > Enable just-in-time policy. This enables just-in-time access for the VM using the following settings:
          - Windows: RDP port 3389, 3hrs maximum access, allowed source IP addresses: any
          - Linux: SSH port 22, 3hrs maximum access, allowed source IP addresses: any
        - REQUEST JIT access: In the Azure portal, when you try to connect to a VM, Azure checks to see if you have a just-in-time access policy configured on that VM. If you do have a JIT policy configured on the VM, you can click Request access to enable you to have access in accordance with the JIT policy set for the VM.
      - Configure a JIT policy on a VM programmatically
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_04_Azure%20Sentinel.md
  - Azure Sentinel is your bird's-eye view across the enterprise. Put the cloud and large-scale intelligence from decades of Microsoft security experience to work. Make your threat detection and response smarter and faster with artificial intelligence (AI). To on-board Azure Sentinel, you first need to enable Azure Sentinel, and then connect your data sources. Azure Sentinel comes with a number of connectors for Microsoft solutions, available out of the box and providing real-time integration, including Microsoft Threat Protection solutions, Microsoft 365 sources, including Office 365, Azure AD, Azure ATP, and Microsoft Cloud App Security, and more.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_06_Security%20Playbook%20in%20Azure%20Sentinel.md 
  - you can use Logic App Designer in conjunction with Azure Sentinel.

## Session 6
### Topics
*Security operations*: 
Security alerts, security baseline. 

*Secure data and applications*: 
Data classification, Azure SQL firewall, Azure SQL Database Advanced Data Security, SAS. 

### Summary
Security Alert:
- notification in Security Portal that something happened - sent to Azure Security Center
Incidents:
- collection of similar alerts
Standard Pricing tier you can enable alerts on Resource level.
Network traffic and Logs are analyzed regarding:
- behavioral pattern
- anomalies (with Machine learning techniques)
- TI
Investigation gives an assessment:
- high 
- medium
- low
- informational
Security Alerts and the intent kill chain: https://docs.microsoft.com/en-us/azure/security-center/alerts-reference

```powershell
kubectl get pods
kubectl cluster -info
kubectl get namespace
```

Security Baseline:
- document that defines business risk and from this technical risk in a document. This should then result in Policies which are deployed through all environments and then reviewed. Upon review the whole cycle may start again-

References:
- https://azure.microsoft.com/en-us/resources/cis-microsoft-azure-foundations-security-benchmark/
- https://github.com/MicrosoftDocs/SecurityBenchmarks/blob/master/spreadsheets/AzureSecurityBenchmark_v1.0.xlsx
- https://docs.microsoft.com/en-us/azure/security/benchmarks/overview
- https://docs.microsoft.com/en-us/azure/security/fundamentals

- https://learn.cisecurity.org/benchmarks
- https://www.cisecurity.org/cis-benchmarks

- https://docs.microsoft.com/en-us/learn/modules/create-security-baselines/4-create-a-storage-accounts-baseline
- https://docs.microsoft.com/en-us/azure/storage/common/security-baseline

Replication:
- Locally-redundant storage (LRS)
  - storage account (instance of storage server) in only one region in particular datacenter with 3 synchronous replicas
- Geo-redundant storage (GRS)
  - LRS in particular datacenter in one region + LRS copy in particular datacenter in a second region. Copy is asynchronous repliace of primary LRS. Acess to second region only if first region is down.
  - RA-GRS: read access to second region
- Zone-redundant storage (ZRS)
  - storage account in one region but 3 replicas are spread over datacenters synchronously.
- Geo-zone-redundant storage (GZRS):
  - in primary region: ZRS, in secondary region: LRS
  - RA-GZRS: read access in second region
Enable *Secure transfer required*:
- Secure data in transit via SSL/TLS certificate.
  
```powershell
"Hello World" | Out-File test.txt
```

Shared Access Signature (SAS):
- URL
- can be assigned on blob or on container level
- url of blob service: /<container name>/<file name>?<SAS>

Restrict internet access:
- container level
  - change access level:
    - private
    - blob (no shared access signature needed, but not good practice if not only used in VNet)
    - container (no shared access signature needed, but not good practice if not only used in VNet)
    
Access policy:
- Stored access policies > Add policy
- you can specify retention time

Storage explorer:
- compromised URL: without stored access policies you can only regenerate keys
- Manage Access policies -> change ID, delete

Options to secure storage account:
- Access keys
- Shared Access Signatures + Stored Access Policy + Access Level on container
- Azure AD Identities + Role-Based Access Control:
  - allows you to specify roles more granularly (best version)

### Reading
1. Student Handbook: “Module 3 – Manage Security Operations” => “Manage security alerts”, “Respond to and remediate security issues”, “Create security baselines” 
2. Student Handbook: “Module 4 – Secure Data and Applications” => “Configure security policies to manage data”, “Configure security for data infrastructure” 
3. Azure SQL data classification official documentation: https://docs.microsoft.com/en-us/azure/sql-database/sql-database-data-discovery-and-classification 
4. Azure SQL Advanced Data Security official documentation: https://docs.microsoft.com/en-us/azure/sql-database/sql-database-advanced-data-security 
5. Storage Access Signatures (SAS) official documentation: https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview 
6. Azure Security Alerts official documentation: https://docs.microsoft.com/en-us/azure/security-center/security-center-alerts-overview

### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_4/LAB_08_Create%20security%20baselines.md 
  - Restrict access to Azure AD Administration Portal: non-Admins will not have access
  - Enable MFA
  - Block remembering MFA on trusted devices: check Restore multi-factor authentication on all remembered devices.
  - Limit permissions of guest users or disallow them completely.
  - Azure Active Directory > Users > Password reset > Authentication methods: Set number of methods to 2.
  - Azure Active Directory > Users > Password reset > Registration > Number of days before users are asked to re-confirm their authentication information to a value of non-zero (default: 180 days)
  - Disable members invitations: AAD > Users > User settings > Manage external collaboratio settings > No.
  - Restrict Security Group creation to admins: AAD > Groups > General > Users can create security groups in Azure portals > No.
  - Disable self-service group management
  - Disallow users to register apps.
  - ASC baselines:
    - enable system updates: Security Center > Security Policy > View effective policy > System updates should be installed on your machines
    - enable security configurations: Security Center > Security Policy > View effective policy > Vulnerabilities in security configuration on your virtual machine scale sets should be remediated 
    - send e-mails about alerts: Security Center > Pricing&Settings > Subscription > Email notifications > Save.
  - Azure Storage baselines:
    - require security enhanced transfers: Storage Accounts > Settings > Configuration > Secure Transfer Required: Enabled
    - enable binary large object encryption: Storage Accounts > Settings > Encryption > Microsoft Managed Keys (Enabled by default and cannot be disabled).
    - periodically regenerate access keys: Storage Accounts > Activity Log > Time-span drop-down > Custom : choose Start and End time > Apply
    - require shared access signatures (SAS) to expire within an hour: Storage Accounts > Shared Access Signature > choose Start and expiry date/time > set allowed protocols to HTTPS only
    - require only private access to blob containers: Storage Accounts > Containers > Public access level: Private.
 - Azure SQL Database baselines:
   - enable auditing:
     - Auditing for Azure SQL Database and SQL Data Warehouse tracks database events and writes them to an audit log in your Azure storage account, OMS workspace or Event Hubs. Auditing also:Helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations. 
     - Security > Auditing: On and check Audit log destination: Storage, Log Analytics or Event Hubs.
   - enable threat detection service:
     - Threat detection for single and pooled databases detects anomalous activities indicating unusual and potentially harmful attempts to access or exploit databases.Threat detection is part of the advanced data security (ADS) offering, which is a unified package for advanced SQL security capabilities. Threat detection can be accessed and managed via the central SQL ADS portal. 
     - Security > Advanced Data Security > Settings > Enable Advanced Data Security on the server > Yes
   - enable all threat detection device:
     - Advanced data security (ADS) provides a set of advanced SQL security capabilities, including data discovery & classification, vulnerability assessment, and Advanced Threat Protection (ATP).
     - Security > Advanced Data Security > Settings > Send alerts: Also send email to admins and subscription owners.
 - Logging and Monitoring baseline:
 Logging and monitoring are a critical requirement when trying to identify, detect, and mitigate security threats. Having a proper logging policy can ensure you can determine when a security violation has occurred, but also potentially identify the culprit responsible. Azure Activity logs provide data about both external access to a resources and diagnostic logs, which provide information about the operation of that specific resource.
   - ensure log profile exists:
      - Monitor > Activity Log > Diagnostic Settings > Export Activity Log.
   - change activity log retention:
     - Monitor > Activity Log > Diagnostic Settings > Export Activity Log, set Retention to above 0, 0 keeps data forever.
   - Create an activity log alert for "Creating, updating, or deleting a Network Security Group"
     - By default, no monitoring alerts are created when NSGs are created/updated/deleted.
     - Monitor > Alerts > New alert rule > Resource: Select Subscription, Condition: Add; Create or Update Network Security Group. Configure > Event initiated by any. Create Action Group
 - Networking baselines:
   - Restrict RDP and SSH access from the Internet:
     - After direct RDP and SSH access from the Internet is disabled, you have other options that you can use to access these VMs for remote management: 
       - Point-to-site VPN
       - Site-to-site VPN
       - Azure ExpressRoute
       - Azure Bastion Host
     - Virtual Machines > specific VM > Networking > delete RDP inbound port rule.
   - Restrict SQL Server access from the Internet: To access an instance of the SQL Server through a firewall, you must configure the firewall on the computer that is running SQL Server. Allowing ingress for the IP range 0.0.0.0/0 (Start IP of 0.0.0.0 and End IP of 0.0.0.0) allows open access to any/all traffic potentially making the SQL Database vulnerable to attacks. 
     - SQL servers > Firewalls and virtual networks > Ensure that the firewall rules exist, and no rule has a Start IP of 0.0.0.0 and End IP of 0.0.0.0 or other combinations which allows access to wider public IP ranges.
   - Configure the NSG flow rules: When you create or update a virtual network in your subscription, Network Watcher will be enabled automatically in your Virtual Network's region. There is no impact to your resources or associated charge for automatically enabling Network Watcher. Network security group (NSG) flow logs are a feature of Network Watcher that allows you to view information about ingress and egress IP traffic through an NSG. Flow logs are written in JSON format, and show outbound and inbound flows on a per rule basis, the network interface (NIC) the flow applies to, 5-tuple information about the flow (Source/destination IP, source/destination port, and protocol), if the traffic was allowed or denied, and in Version 2, throughput information (Bytes and Packets). Logs can be used to check for anomalies and give insight into suspected breaches.
     - All services > Networking > Network Watcher > NSG Flow Logs under Logs > On. Select a Storage Account and Save.
   - enable Network Watcher:
     - All services > Network Watcher. If a region is disabled, click and press Enable Network Watcher.
 - Azure VM baseline:
   - ensure OS disk is encrypted: Azure Disk Encryption helps protect and safeguard your data to meet your organizational security and compliance commitments. It uses the BitLocker feature of Windows and the DM-Crypt feature of Linux to provide volume encryption for the OS and data disks of Azure virtual machines (VMs). It is also integrated with Azure Key Vault to help you control and manage the disk encryption keys and secrets, and ensures that all data on the VM disks are encrypted at rest while in Azure storage. Azure Disk Encryption for Windows and Linux VMs is in General Availability in all Azure public regions and Azure Government regions for Standard VMs and VMs with Azure Premium Storage. If you use Azure Security Center (recommended), you're alerted if you have VMs that aren't encrypted.
     - All services > Key Vault > Access policy > check Azure Disk Encryption for volume encryption. -> VM is encrypted but not disk. Upon creation click on Encryption > OS data & disks > Select a key vault and key for encryption > Save.
   - ensure only approved extensions are installed:
     - Virtual Machines > Settings > Extensions: Ensure that the listed extensions are approved for use.
     
Enables and facilitates adherence to compliance standards, although it doesn't guarantee compliance.
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_01_Classify%20a%20SQL%20Database.md 
 - Turn on Advanced Security on SQL database and server
 - On SQL server add storage account for vulnerability assessment.
 - On Advance Security on SQL database select Card *Data Discovery and Classification*:
   ![](images/database_classification.png)
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_02_Auditing%20a%20Database.md 
 - SQL Server > Security > Auditing > On and select at least one of where to send logs to:
   - Storage - retention forever (0 days) or between 1 day and 9 years.
   - Log Analytics (Preview)
   - Event Hub (Preview)
 - Go to Database > View audit logs. (Even though auditing not enabled here, as configured on server level you will see it here).
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_3/LAB_03_Analyze%20audit%20logs%20and%20reports.md 
  - The query language used by log analytics is called the Kusto query language. The full documentation for this language can be found here https://docs.microsoft.com/en-us/azure/kusto/query/, example queries:
  ```bash
  Event | where Source  == "MSSQLSERVER" 
  ```
  or
  ```bash
  Event 
  | where EventLevelName == "Error" 
  | where TimeGenerated > ago(1d) 
  | where Source != "HealthService" 
  | where Source != "Microsoft-Windows-DistributedCOM" 
  | summarize count() by Source
  ```

## Session 7
### Topics
*Secure data and applications*: 
Azure SQL Database Always Encrypted, Storage encryption, Azure Disk encryption, Azure Backup encryption, Web App for containers, Application Insights, Microsoft Security Development Lifecycle.

### Summary
Users/Applications can access DB Server via 
- SQL Server Management Studio with T-SQL queries 
- PowerShell
- Azure Portal
From there you can access individual DBs.
Direct DB connection is only possible via T-SQL.

Connection options:
Client via Azure SQL Data Gateway via Proxy or Redirect.

Azure SQL authentication:
- Integrated AAD (ADDS if federated trust; azure pass-through or hash; needs SSO)
- AAD with Password
- universal - with MFA

Procedure:
1. DBA@mycompany.com federated (Data-Base Admin)
2. DBO (Data-Base Owner)
3. Create User Accounts (contained users)
4. Roles DB
You can have advanced data security for 15USD/server/month.

Data Security measures
- Data Classification:
  - Tag data in databases (VNets, Ressources)
  - Process:
    1. Data Discovery (Business Analyst)
    2. Classification
- Vulnerability Assessment
- Threat Protection

Database Encryption:
- Transparent Data Encryption (TDE)
  - pages in database are encrypted
  - not related to applications
- Always Encrypted

Always Encrypted is Client-Side Encryption.
TDE is server-side encryption (SSE).
Data in Transit is encrypted by SSL/TLS, HTTPS or VPN channel.

key encryption key is column encryption key that encrypts or decryptes database encryption key.
Encrypted columns: need to be careful how to configure getting data via T-SQL queries.

Dynamic Masking

Azure Backup encryption:
- Azure VMs send data encrypted in transit (via https) to Recovery Service Vault (specific form of storage), which is encrypted by SSE (Storage Server Encryption).
- Windows Server sends data via Microsoft Azure Recovery Services Agent (MARS) to Recovery Service Vault.

(Encryption on the fly: protection on CPU level)

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

### Summary
#### Security Development Lifecycle (SDL)
- https://www.microsoft.com/en-us/securityengineering/sdl/resources
Procedure:
1. Design
- Requirement
- Security Requirement
- Threat Modeling: aka.ms/threatmodeling
2. CI
- Code -> (Code Review) -> Build -> Test / Security Test
- e.g. use SonarCloud, SonarQube
3. CD
- Artefact -> Test (e.g. Penetration) / Security Tests -> Prod
- e.g. WhiteSourceBolt

#### Azure Disk Encryption
- Always via Azure Key Vault.
- Manage Disk uses system-managed key, customer-managed key for server-side encryption of Storage (SSE).
  - Use Disk encryption set -> granted permission to KeyVault to Get, Wrap and Unwrap Key.
- Unmanaged Disk use Disk Encryption Key (DEK, secret) via Bitlockerkey (BEK, Windows) or DM-Crypt (Linux) to CSE inside Operating System

https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-powershell-quickstart

#### Managed Identity
- behing the scenes service principal
- Use Case: App/identity needs access to resource. 
  - 1. Managed Identity for resource
  - 2. RBAC for resource
  - 3. Resource requests JSON Token from the App that retrieves it from the Azure Instance Metadata Service (on non-routable IP address: 169.254.169.251)
  
Types:
- system-assigned managed identity:
  - cannot be shared among resources
  - alive as long as resource alive
- user-assigned managed identity:
  - more efficient for multiple resources
  
```powershell
Connect-AzAccount -Identity
Get-AzVM
```

Service Endpoints and PaaS Firewall typically together:
1. Service Endpoint functionality enabled on subnet
2. Enable Service Endpoint on resource
3. Now Subnet and Resource are connected through internal network through Azure backbone.

https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview

#### The Key Vault
Key Vault = Secured Storage
Data to secure:
- key
- secret
- certificate
Management of Key Vault is via RBAC, whereas data access is managed via shared access policy:
If you deploy a key vault it does not mean that you have access to the data.

Soft-delete:
- allows to recover key vault within retention period.

purge protection:
- disallows to delete soft-deleted items.

#### Front Door
- is a global service, whereas Application Gateway is a regional service
- WebSockets probably not supported, but WAF can be enabled
- L7 load balancer for backends that can be in East US, West EU, etc.
- publishing service
- only http/https


### Reading
1. Student Handbook: “Module 4 – Secure Data and Applications” => “Secure applications”, “Configure and manage Microsoft Azure Key Vault” 
2. Azure Network Service Endpoint official documentation: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview 
3. Azure Front Door official documentation: https://docs.microsoft.com/en-us/azure/frontdoor/front-door-overview 
4. Azure Key Vault official documentation: https://docs.microsoft.com/en-us/azure/key-vault/general/overview


### Labs
- https://github.com/MicrosoftLearning/AZ-500-Azure-Security/blob/master/Instructions/Labs/Module_1/LAB_02_Key_Vault.md 
  - Azure Key Vault to create a hardened container (a vault) in Azure, to store and manage cryptographic keys and secrets in Azure.
  - Download SQL Server Management Studio (SSMS): https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017
  - SSMS only runs on Windows.
  - Create Key Vault via Powershell:
  ```powershell
  Login-AzAccount
  New-AzResourceGroup -Name 'KeyVaultPSRG' -Location 'eastus'
  New-AzKeyVault -VaultName '<keyvault name>' -ResourceGroupName 'KeyVaultPSRG' -Location 'eastus'
  ```
  - Add Access Policy:
    - Select Key, Secret and Certificate Management from Configure from template (optional)
    - Select Principal and select your account
  - Add Key to Key Vault via Powershell:
  ```powershell
  $key = Add-AZKeyVaultKey -VaultName '<YourVaultName>' -Name 'MyLabKey' -Destination 'Software'
  ```
  - View Key via:
  ```powershell
  Get-AZKeyVaultKey -VaultName '<YourVaultName>'
  ```
  - Add Secret to Key Vault via Powershell:
  ```powershell
  $secretvalue = ConvertTo-SecureString 'Pa55w.rd1234' -AsPlainText -Force
  $secret = Set-AZKeyVaultSecret -VaultName 'YourVaultName' -Name 'SQLPassword' -SecretValue $secretvalue
  ```
  - View Secret via:
  ```powershell
  Get-AZKeyVaultSecret -VaultName 'YourVaultName'
  ```
  - Enable Client application via App Registration (select Expiry date)
  - Add access policy for Client application:
  ```
  $subscriptionName = '[Azure_Subscription_Name]'
  $applicationId = '[Azure_AD_Application_ID]'
  $resourceGroupName = '[Resource_Group_with_KeyVault]'
  $location = '[Azure_Region_of_KeyVault]'
  $vaultName = '[KeyVault_Name]' 
  Login-AzAccount
  Set-AZKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $applicationId -PermissionsToKeys get,wrapKey,unwrapKey,sign,verify,list
  ```
  - To access SQL database you need to add client IP via server and firewall configurations of Database Server.
  - You can encrypt Columns of your table (randomized or deterministic), which leads to Always Encrypted keys.
- https://docs.microsoft.com/en-us/azure/virtual-network/tutorial-restrict-network-access-to-resources 
- https://docs.microsoft.com/en-us/azure/frontdoor/quickstart-create-front-door 
