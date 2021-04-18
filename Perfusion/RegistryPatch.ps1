
function Invoke-RegistryPatch {
    <#
    .SYNOPSIS

    Patch for the RpcEptMapper/DnsCache registry key vulnerability 

    Author: Clément Labro (@itm4n)
    
    .DESCRIPTION

    This script is intended for system administrators who still have to manage old Windows machines (Windows 7, Windows 2008 R2, Windows 8, Windows 2012). It checks whether "NT AUTHORITY\INTERACTIVE", "BUILTIN\Users" and/or "BUILTIN\Authenticated Users" have the "CreateSubKey" right on the "RpcEptMapper" and "DnsCache" registry keys. If at least one occurrence is found, the machine is vulnerable and the script returns "True", otherwise it returns "False". You can then choose to apply the patch by using the "-Patch" switch. If the patch is successfully applied, the script returns "True", otherwise it returns "False".
    
    .PARAMETER Patch

    By default, the script only checks whether the machine is vulnerable. To apply the patch, simply enable this switch.
    
    .EXAMPLE

    PS C:\Temp> . .\RegistryPatch.ps1; Invoke-RegistryPatch
    True

    .EXAMPLE

    PS C:\Temp> . .\RegistryPatch.ps1; Invoke-RegistryPatch -Verbose
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper
    VERBOSE: Found a vulnerable ACE: "NT AUTHORITY\Authenticated Users" has "QueryValues, CreateSubKey, ReadPermissions" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper
    VERBOSE: Found a vulnerable ACE: "BUILTIN\Users" has "QueryValues, CreateSubKey, Notify" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    True

    .EXAMPLE

    PS C:\Temp> . .\RegistryPatch.ps1; Invoke-RegistryPatch -Patch -Verbose 
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper
    VERBOSE: Found a vulnerable ACE: "NT AUTHORITY\Authenticated Users" has "QueryValues, CreateSubKey, ReadPermissions" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper
    VERBOSE: Found a vulnerable ACE: "BUILTIN\Users" has "QueryValues, CreateSubKey, Notify" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper
    VERBOSE: The new ACL was applied
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\DnsCache
    VERBOSE: Found a vulnerable ACE: "NT AUTHORITY\INTERACTIVE" has "QueryValues, CreateSubKey, EnumerateSubKeys, ReadPermissions" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\DnsCache
    VERBOSE: Found a vulnerable ACE: "BUILTIN\Users" has "CreateSubKey, ReadKey" rights
    VERBOSE: InheritanceFlags: None
    VERBOSE: IsInherited: False
    VERBOSE: Registry key: HKLM\SYSTEM\CurrentControlSet\Services\DnsCache
    VERBOSE: The new ACL was applied
    True
    
    .NOTES

    More info here:
    - https://github.com/itm4n/Perfusion
    - https://itm4n.github.io/windows-registry-rpceptmapper-eop/
    #>

    [CmdletBinding()] param(
        [switch]$Patch
    )

    $IsVulnerable = $False

    # List of vulnerable registry keys
    $RegistryKeys = @(
        "HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper",
        "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache"
    )

    # List of low-privilege groups
    $WellKnownSids = @(
        "S-1-5-32-545",         # BUILTIN\Users
        "S-1-5-11",             # BUILTIN\Authenticated Users
        "S-1-5-4"               # NT AUTHORITY\INTERACTIVE
    )

    # Convert the list of SIDs to a list of NT identity names
    $WellKnownGroups = New-Object System.Collections.ArrayList
    ForEach ($WellKnownSid in $WellKnownSids) {
        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($WellKnownSid)
        $GroupName = $SidObj.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
        [void]$WellKnownGroups.Add($GroupName)
    }

    $CreateSubKeyRight = [System.Security.AccessControl.RegistryRights]"CreateSubKey"
    $AccessControlAllow = [System.Security.AccessControl.AccessControlType]"Allow"

    ForEach ($RegistryKey in $RegistryKeys) {
        
        $Acl = Get-Acl -Path "Registry::$RegistryKey"
        $ApplyNewAcl = $False
        
        ForEach ($Ace in $($Acl | Select-Object -ExpandProperty "Access")) {

            $IdentityReference = $Ace | Select-Object -ExpandProperty "IdentityReference"

            # Check if:
            #   - the identity is either "BUILTIN\Users" or "BUILTIN\Authenticated Users"
            if ($WellKnownGroups -Contains $IdentityReference) {

                $RegistryRights = $Ace | Select-Object -ExpandProperty "RegistryRights"
                $AccessControlType = $Ace | Select-Object -ExpandProperty "AccessControlType"

                # Check if:
                #   - the "RegistryRights" contain the value "CreateSubKey";
                #   - the "AccessControlType" is "Allow";
                #   - the value of "RegistryRights" is greater than 0 (sometimes, it's negative for whatever reason)
                if (
                    $($($RegistryRights -band $CreateSubKeyRight) -eq $CreateSubKeyRight) -and
                    $($AccessControlType -eq $AccessControlAllow) -and
                    $($RegistryRights -ge 0)
                ) {

                    Write-Verbose -Message "Registry key: $RegistryKey"
                    Write-Verbose -Message "Found a vulnerable ACE: `"$IdentityReference`" has `"$RegistryRights`" rights"
                    Write-Verbose -Message "InheritanceFlags: $($Ace | Select-Object -ExpandProperty "InheritanceFlags")"
                    Write-Verbose -Message "IsInherited: $($Ace | Select-Object -ExpandProperty "IsInherited")"

                    $IsVulnerable = $True

                    # Remove the weak ACE from the ACL
                    [void]$Acl.RemoveAccessRule($Ace)

                    # Create a new enum without the "CreateSubKey" right
                    $NewRegistryRights = [System.Security.AccessControl.RegistryRights]$([uint32]$RegistryRights - [uint32]$CreateSubKeyRight)
                    
                    # Create an ACE with the new enum
                    $NewAce = New-Object System.Security.AccessControl.RegistryAccessRule(
                        $($Ace | Select-Object -ExpandProperty "IdentityReference"),
                        $NewRegistryRights,
                        $($Ace | Select-Object -ExpandProperty "InheritanceFlags"),
                        $($Ace | Select-Object -ExpandProperty "PropagationFlags"),
                        $($Ace | Select-Object -ExpandProperty "AccessControlType")
                    )

                    # Add the modified ACE to the ACL
                    [void]$Acl.AddAccessRule($NewAce)

                    $ApplyNewAcl = $True
                }
            }
        } 

        if ($ApplyNewAcl) {
            if ($Patch) {
                $Acl | Set-Acl -Path "Registry::$RegistryKey"
                Write-Verbose -Message "Registry key: $RegistryKey"
                Write-Verbose -Message "The new ACL was applied"
            }
        }
    }

    if ($Patch) {
        # Ensure the machine is no long vulnerable
        -not $(Invoke-RegistryPatch)
    } else {
        # Check if the machine is vulnerable
        $IsVulnerable
    }
}
