$h= Get-ADComputer -Filter * | select -Property @{n='computername';e={$PSItem.Name}}, @{n='status';e={$PSItem.Enabled}}, @{n='FQDN';e={$PSItem.DNSHostName}}, @{n='samACCOUNTNAME';e={$PSItem.SamAccountName}}, @{n='LOCATION';e={$PSItem.DistinguishedName}}, @{n='ObjectClass';e={$PSItem.ObjectClass}}   | Format-Table -AutoSize

$k = Get-ADForest | select -Property @{n='DomainNamingMaster'; e = {$PSItem.DomainNamingMaster}},@{n='Forestmode'; e = {$PSItem.ForestMode }}, @{n='Sites'; e = {$PSItem.Sites}}, @{n='Rootdomain'; e = {$PSItem.RootDomain}}, @{n='GlobalCatalog'; e = {$PSItem.GlobalCatalogs}},@{n='SchemaMaster'; e = {$PSItem.SchemaMaster}}, @{n='Application Partition'; e = {$PSItem.ApplicationPartitions}} ,@{n='partitionContainer'; e = {$PSItem.PartitionsContainer}}  | Format-Table -AutoSize
Write-Host "information regarding forest is as follows"
$k


$u = Get-ADDomainController | select -Property @{n='DC with path'; e={$PSItem.ComputerObjectDN}}, @{n='DefaultPartition'; e={$PSItem.DefaultPartition}}, @{n='Domain'; e={$PSItem.Domain}}, @{n='Enabled'; e={$PSItem.Enabled}}, @{n='Forest'; e={$PSItem.Forest}}, @{n='HostName'; e={$PSItem.HostName}},  @{n='InvocationId'; e={$PSItem.InvocationId}}, @{n='IPv4Address'; e={$PSItem.IPv4Address}}, @{n='IPv6Address'; e={$PSItem.IPv6Address}}, @{n='Global Catalog'; e={$PSItem.IsGlobalCatalog}}, @{n='Read Only DC'; e={$PSItem.IsReadOnly}}, @{n='LdapPort'; e={$PSItem.LdapPort}}, @{n='Name'; e={$PSItem.Name}},  @{n='NTDSSettingsObjectDN'; e={$PSItem.NTDSSettingsObjectDN}}, @{n='Operating System'; e={$PSItem.OperatingSystem}}, @{n='OperationMasterRoles'; e={$PSItem.OperationMasterRoles}}, @{n='Partitions'; e={$PSItem.Partitions}} | Format-Table -AutoSize    
Write-Host "Information about all Domain Controllers are as follows"
$u  

$w = Get-ADGroup -filter * | select -Property @{n='DistinguishedName'; e={$PSItem.DistinguishedName}}, @{n='GroupCategory'; e={$PSItem.GroupCategory}}, @{n='GroupScope'; e={$PSItem.GroupScope}}, @{n='Name'; e={$PSItem.Name}}, @{n='ObjectClass'; e={$PSItem.ObjectClass}}, @{n='SamAccountName'; e={$PSItem.SamAccountName}}, @{n='SID'; e={$PSItem.SID}} | Format-Table -AutoSize  
Write-Host "Following contains information of groups in this Domain"
$w

$p = Get-ADDomain | select -Property @{n='child domains';e={$PSItem.ChildDomains}},  @{n='DNSRoot';e={$PSItem.DNSRoot}}, @{n='ParentDomain ';e={$PSItem.ParentDomain}}, @{n='PDCEmulator';e={$PSItem.PDCEmulator}}, @{n='ReplicaDirectoryServers';e={$PSItem.ReplicaDirectoryServers}}, @{n='RIDMaster';e={$PSItem.RIDMaster}}, @{n='DomainMode';e={$PSItem.DomainMode}}, @{n='Forest ';e={$PSItem.Forest }}, @{n='InfrastructureMaster ';e={$PSItem.InfrastructureMaster}}, @{n='Name';e={$PSItem.Name}}, @{n='NetBIOSName ';e={$PSItem.NetBIOSName}}  | Format-Table -AutoSize
Write-Host "Domain wide information is as follows"
$p

 $r = Get-ADOrganizationalUnit -Filter * | select -Property @{n='City';e={$PSItem.City}}, @{n='Country';e={$PSItem.Country}},  @{n='DistinguishedName';e={$PSItem.DistinguishedName}}, @{n='LinkedGroupPolicyObjects';e={$PSItem.LinkedGroupPolicyObjects}}, @{n='ManagedBy';e={$PSItem.ManagedBy}}, @{n='Name';e={$PSItem.Name}}, @{n='ObjectClass';e={$PSItem.ObjectClass}},  @{n='State';e={$PSItem.State}} | Format-Table -AutoSize  
 Write-Host "following are description of OU in this domain"
 $r


$d = Get-ADObject -Filter * | select -Property @{n='DistinguishedName';e={$psitem.DistinguishedName}}, @{n='Name';e={$psitem.Name}}, @{n='ObjectClass';e={$psitem.ObjectClass}} | Format-Table -AutoSize 
Write-Host "Follwing are details of all objects in forest"
$d
