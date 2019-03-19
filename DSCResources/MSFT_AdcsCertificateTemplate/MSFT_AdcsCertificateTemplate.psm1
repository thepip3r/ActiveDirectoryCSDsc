function Get-TargetResource
{
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $TemplateName,
        [Parameter(Mandatory=$True)]
        [String]
        $Cn,
        [Parameter(Mandatory=$True)]
        [String]$displayName,
        [Parameter(Mandatory=$True)]
        [String]
        $name,
        [Parameter(Mandatory=$True)][String]$msPKI_Cert_Template_OID,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Application_Policy,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Minor_Revision,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Schema_Version,
        [Parameter(Mandatory=$True)][String]$flags,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Name_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Enrollment_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Private_Key_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Minimal_Key_Size,
        [Parameter(Mandatory=$True)][String]$pKIKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIExtendedKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIDefaultCSPs,
        [Parameter(Mandatory=$True)][String]$msPKI_RA_Application_Policies,
        [Parameter(Mandatory=$True)][String]$copyFrom,
        [Parameter(Mandatory=$False)][String]$Security,
        [Parameter(Mandatory=$False)][String]$copyFromValidityPeriod,
        [Parameter(Mandatory=$False)][String]$PrivateKeyPermissions

    )
    Write-Verbose (whoami)
    $templates = Get-CATemplate
    $templateExists = $templates.Name -contains $TemplateName
    $return = @{
        templateSettings = $PSBoundParameters
        issued = $templateExists
    }
    return $return
}

function Set-TargetResource
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][String]$TemplateName,
        [Parameter(Mandatory=$True)][String]$cn,
        [Parameter(Mandatory=$True)][String]$displayName,
        [Parameter(Mandatory=$True)][String]$name,
        [Parameter(Mandatory=$True)][String]$msPKI_Cert_Template_OID,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Application_Policy,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Minor_Revision,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Schema_Version,
        [Parameter(Mandatory=$True)][String]$flags,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Name_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Enrollment_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Private_Key_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Minimal_Key_Size,
        [Parameter(Mandatory=$True)][String]$pKIKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIExtendedKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIDefaultCSPs,
        [Parameter(Mandatory=$True)][String]$msPKI_RA_Application_Policies,
        [Parameter(Mandatory=$True)][String]$copyFrom,
        [Parameter(Mandatory=$False)][String]$Security,
        [Parameter(Mandatory=$False)][String]$copyFromValidityPeriod,
        [Parameter(Mandatory=$False)][String]$PrivateKeyPermissions

    )
    Write-Verbose $(whoami)
    $templateName = $TemplateName
    #Build Template Here!
    $config = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$config"
    $template = $ADSI.Create("pKICertificateTemplate","CN=$templateName")
    try
    {
        $ADSI.Delete("pKICertificateTemplate", "CN=$templateName")
    }
    catch
    {
        Write-Verbose "Failed to remove template"
    }

    $template.put("distinguishedName","CN=$templateName,CN=CN=Certificate Templates,CN=Public Key Services,CN=Services,$config")
    $templateItems = $PSBoundParameters
    $excludedItemsList = @()
    foreach($parameter in $templateItems.GetEnumerator()){
        $propertyName = $parameter.Key
        $propertyValue = $parameter.Value
        if($propertyName -eq 'Verbose' -or $propertyName -eq 'TemplateName' -or $propertyName -eq 'Security' -or $propertyName -eq 'PrivateKeyPermissions'){
            continue
        }
	    $propertyName = $propertyName -replace '_','-'
        Write-Verbose "$propertyName : $PropertyValue"
        if($propertyName -match "copyFrom"){
            try{
                $template.SetInfo()
                $DefaultTemplate = $ADSI.psbase.children | Where-Object {$_.cn -eq "$propertyValue"}
                if($propertyName -eq "copyFromValidityPeriod" -and $null -ne $propertyValue){
                    $template.pKIExpirationPeriod = $DefaultTemplate.pKIExpirationPeriod
                    $template.pKIOverlapPeriod = $DefaultTemplate.pKIOverlapPeriod
                }else{
                    $Settings = ($DefaultTemplate | Get-Member)
                    foreach($item in $Settings){
                        if($item.MemberType -eq "Property"){
                            $itemName = $item.Name
                            if($excludedItemsList -ccontains $itemName -or $itemName -eq "replPropertyMetaData" -or $itemName -match "USN" -or $itemName -match "when" -or $itemName -eq "dsCorePropagationData" -or $itemName -match "object" -or $itemName -eq "nTSecurityDescriptor" -or $itemName -eq "instanceType" ){
                                continue
                            }
                            $template.$itemName = $DefaultTemplate.$itemName
                        }
                        }
                    }
            }catch{
                Write-Verbose "Error: Failed to copy default template properties of $propertyValue to $templateName. $_"
                return
            }
        }
        else{
            $excludedItemsList += $propertyName
            if(($propertyName -notmatch "Security") -and ($propertyName -notmatch "PrivateKeyPermissions")){
                if(($propertyValue -match ";") -and ($propertyName -ne "msPKI-RA-Application-Policies")){
                    $itemArray = $propertyValue.split(";",[StringSplitOptions]'RemoveEmptyEntries')
                    foreach ($item in $itemArray){
                        $template.$propertyName.add($item) | Out-Null
                    }
                    continue
                }
                if($propertyName -eq "pKIKeyUsage"){
                    try{
                        [byte]$byteVal = [System.Convert]::ToByte($propertyValue)
                        [byte[]]$keyUsage = @($byteVal, 0x00)
                        $template.put($propertyName, $keyUsage)
                    }
                    catch{
                        Write-Verbose "Error: Failed to set PKI Key Usage for $templateName template."
                        return
                    }
                }
                else{
                    try{
                        $template.put($propertyName, $propertyValue)
                    }
                    catch{
                        Write-Verbose "Error: Failed to set $propertyName for $templateName template. $_"
                    }
                }
            }
        }
    }
    if(-not ($null -eq $PrivateKeyPermissions)){
        $usersToAdd = $PrivateKeyPermissions.split(";",[StringSplitOptions]'RemoveEmptyEntries')
        $keyPermissionsItem = "msPKI-RA-Application-Policies"
        foreach($user in $usersToAdd){
            try{
                $adGroup = New-Object System.Security.Principal.NTAccount($user)
                $groupSID = $adGroup.Translate([System.Security.Principal.SecurityIdentifier]).value
                $originalKeyPerms = $template.$keyPermissionsItem
                $updatedKeyPerms = "$originalKeyPerms`msPKI-Key-Security-Descriptor``PZPWSTR``D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;$groupSID)``"
                $template.$keyPermissionsItem=$updatedKeyPerms
            }
            catch{
                Write-Verbose "ERROR: Failed to give user $user permissions to private key"
                throw "ERROR: Failed to give user $user permissions to private key"
            }
        }
    }
    try{
        $template.SetInfo()
    }
    catch{
        Write-Verbose "Error: Failed to save template properties for $templateName template. $_"
        return
    }
    # add ACL info if needed
    if(-not ($null -eq $Security)){
        try{
            $securityValueArray = $Security.split(";",[StringSplitOptions]'RemoveEmptyEntries')
            foreach($group in $securityValueArray){
                $groupAndRights = $group.split(":",[StringSplitOptions]'RemoveEmptyEntries')
                $securityGroup = $groupAndRights[0]
                $ADObj = New-Object System.Security.Principal.NTAccount($securityGroup)
                $identity = $ADObj.Translate([System.Security.Principal.SecurityIdentifier])
                $adRights = $groupAndRights[1]
                $type = "Allow"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
                $template.psbase.ObjectSecurity.SetAccessRule($ACE)
            }
            $template.psbase.commitchanges()
        }
        catch{
            Write-Verbose "Error: Failed to apply access security settings to $templateName template. Make sure the group $securityGroup exists."
            throw "Failed the ACE addition to the cert template Error: $_"
        }
    }
    $createdTemplates += $templateName

    # Set certificate template cache to 0, so templates sync faster
    try{
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\CertificateTemplateCache" -name "Timestamp" -Value 0  -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Cryptography\CertificateTemplateCache" -name "Timestamp" -Value 0 -ErrorAction SilentlyContinue
    }catch{
        Write-Verbose "Could set sync time"
    }

    # add the templates to the CA
    foreach ($temp in $createdTemplates){
        try{
            Remove-CATemplate -Name $temp -Confirm:$false -Force
        }
        catch{
            Write-Verbose "Failed to remove template"
        }
        $actionDone = 0
        while($actionDone -eq 0){
            try{
                Add-CATemplate -Name $temp -Confirm:$false
                $actionDone = 1
                Write-Verbose "Information: Successfully added $temp template to the CA."
            }
            catch{
                Start-Sleep(10)
            }
        }

    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$True)][String]$TemplateName,
        [Parameter(Mandatory=$True)][String]$cn,
        [Parameter(Mandatory=$True)][String]$displayName,
        [Parameter(Mandatory=$True)][String]$name,
        [Parameter(Mandatory=$True)][String]$msPKI_Cert_Template_OID,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Application_Policy,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Minor_Revision,
        [Parameter(Mandatory=$True)][String]$msPKI_Template_Schema_Version,
        [Parameter(Mandatory=$True)][String]$flags,
        [Parameter(Mandatory=$True)][String]$msPKI_Certificate_Name_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Enrollment_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Private_Key_Flag,
        [Parameter(Mandatory=$True)][String]$msPKI_Minimal_Key_Size,
        [Parameter(Mandatory=$True)][String]$pKIKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIExtendedKeyUsage,
        [Parameter(Mandatory=$True)][String]$pKIDefaultCSPs,
        [Parameter(Mandatory=$True)][String]$msPKI_RA_Application_Policies,
        [Parameter(Mandatory=$True)][String]$copyFrom,
        [Parameter(Mandatory=$False)][String]$Security,
        [Parameter(Mandatory=$False)][String]$copyFromValidityPeriod,
        [Parameter(Mandatory=$False)][String]$PrivateKeyPermissions

    )
    $templates = Get-CATemplate
    $return = $templates.Name -contains $TemplateName
    return $return
}
