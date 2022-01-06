<#
    .SYNOPSIS
    Checks for necessary configurations for SharePoint environment to function over TLS 1.2

    .DESCRIPTION
    This script requires no inputs and will autotically determine the appropriate configuration depending on SharePoint and Windows version.

    .OUTPUTS
    Example output:

    SharePoint 2016 detected, please reference:
    https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016


    Name                                                             Required Configured
    ----                                                             -------- ----------
    Install OBDC Driver 11 for SQL Server update for TLS 1.2 support True           True
    Install SQL Server 2012 Native Client update for TLS 1.2 support True           True
    Enable strong cryptography in .NET Framework 4.6 or higher       False          True
    Enable strong cryptography in .NET Framework 3.5                 False         False
    Disable earlier versions of TLS in Windows Schannel              False          True
#>

<#
    Required actions per version:
        2019
            - N/A 1.2 is used by default

        2016
            - ODBC driver 11 must be installed
                https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016#ODBC1.1
            - SQL 2012 Native Clinet for 1.2 support
                https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016#sql2012

        2013
            - Enable TLS 1.1/1.2 in Schannel
            - Enable TLS 1.1/1.2 in WinHTTP
            - Enable TLS 1.1/1.2 in Internet Explorer
            - Install SQL Server 2008 R2 Native CLient w/TLS 1.2 support

        2010
            - Enable TLS 1.1/1.2 in Schannel
            - Enable TLS 1.1/1.2 in WinHTTP
            - Enable TLS 1.1/1.2 in Internet Explorer
            - Install SQL Server 2008 R2 Native CLient w/TLS 1.2 support
            - Install ADO.NET 2.0 SP2 upate
            - Install .Net framework update

        Optional (applies to all versions):
            - Enable strong cryptography in .Net 3.5
            - Disable earlier versions of TLS in Schannel
#>

function checkFriendlyName ([string]$checkName)
{
    switch ($checkName)
    {
        oldTlsVersionsDisabled          {return "Disable earlier versions of TLS in Windows Schannel"}
        tlsEnabledInSchannel            {return "Enable TLS 1.1 and 1.2 support in Windows Schannel"}
        tlsEnabledInWinHTTP             {return "Enable TLS 1.1 and 1.2 support in WinHTTP"}
        sql2008R2NativeClientUpdated    {return "Install SQL Server 2008R2 Native Client update for TLS 1.2 support"}
        sql2012NativeClientUpdated      {return "Install SQL Server 2012 Native Client update for TLS 1.2 support"}
        adoNetUpdated                   {return "Install ADO.NET 2.0 SP2 update for TLS 1.1 and TLS 1.2 support"}
        strongCyptographyEnabled4       {return "Enable strong cryptography in .NET Framework 4.6 or higher"}
        strongCyptographyEnabled2       {return "Enable strong cryptography in .NET Framework 3.5"}
        netDefaultTlsVersion            {return "Install .Net Framework 3.5 update for TLS 1.1 and TLS 1.2 support"}
        odbc11Updated                   {return "Install OBDC Driver 11 for SQL Server update for TLS 1.2 support"}
        net46orHigherInstalled          {return "Install .Net Framework 4.6 or higher"}
    }
    
}

function oldTlsVersionsDisabled
{
    if
    (
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -EA 0).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -EA 0).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -EA 0).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -EA 0).DisabledByDefault -eq 1
    )
    {
        return $true
    }
    
    return $false
}


function tlsEnabledInSchannel
{
    if
    (
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client\TLS 1.2" -EA 0).DisabledByDefault -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client\TLS 1.2" -EA 0).Enabled -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -EA 0).DisabledByDefault -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -EA 0).Enabled -eq 1
    )
    {
        #it's explicitly enabled, return true
        return $true
    }
    elseif 
    (
        $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -EA 0) -or
        (
            $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2\Client" -EA 0) -and
            $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2\Server" -EA 0)
        )
    ) 
    {
        return $true
    }

    return $false
}


function tlsEnabledInWinHTTP
{
    $64value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -EA 0 -Name DefaultSecureProtocols).DefaultSecureProtocols
    $32value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -EA 0 -Name DefaultSecureProtocols).DefaultSecureProtocols

    if
    (
        $64value -band 2048 -gt 0 -and
        $32value -band 2048 -gt 0
    )
    {
        return $true
    }

    return $false
}


function sql2008R2NativeClientUpdated
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft SQL Server 2008 R2 Native Client"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 6560)
    {
        return $true
    }

    return $false
}


function adoNetUpdated
{
    #later... maybe...
}


function strongCyptographyEnabled4
{
    if
    (
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -EA 0).SchUseStrongCrypto -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -EA 0).SchUseStrongCrypto -eq 1
    )
    {
        return $true
    }
    
    return $false
}

function strongCyptographyEnabled2
{
    if
    (
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -EA 0).SchUseStrongCrypto -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -EA 0).SchUseStrongCrypto -eq 1
    )
    {
        return $true
    }
    
    return $false
}


function netDefaultTlsVersion
{
    if
    (
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -EA 0).SystemDefaultTlsVersions -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -EA 0).SystemDefaultTlsVersions -eq 1
    )
    {
        return $true
    }

    return $false
}

## TODO: .NET Framework 4.6 or higher installed

function odbc11Updated
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft ODBC Driver 11 for SQL Server"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 5543)
    {
        return $true
    }

    return $false
}


function sql2012NativeClientUpdated
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft SQL Server 2012 Native Client"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 7001)
    {
        return $true
    }

    return $false
}


function net46orHigherInstalled
{
    if
    (
        (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 393295
    )
    {
        return $true
    }

    return $false
}


function getSPVersion
{
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $build = $farm.BuildVersion

    $version = [string]::Empty
    switch($build.Major)
    {
        14
        {
           return  "2010"
        }

        15
        {
            return "2013"
        }

        16
        {
            if(10000 -gt $build.Build -and $build.Build -gt 4000)
            {
                return "2016"
            }
            elseif(20000 -gt $build.Build -and $build.Build -gt 10000)
            {
                return "2019"
            }
        }
    }
}


function getWindowsVersion
{
    $v = [version](Get-WmiObject Win32_OperatingSystem).Version
    switch ($v.Major) {
        6
        {
            if($v.Minor -eq 1)
            {
                return "2008R2"
            }
            elseif($v.Minor -eq 2)
            {
                return "2012"
            }
            elseif($v.Minor -eq 3)
            {
                return "2012R2"
            }
        }
        10
        {
            return "2016+"
        }
        Default {}
    }
}



function main
{
    Add-PSSnapin Microsoft.SharePoint.PowerShell | Out-Null

    $spVersion = getSPVersion
    $winVersion = getWindowsVersion
    $checks = @()
    switch ($spVersion) {
        2010
        {
            Write-Warning "!!SharePoint 2010 detected!!"
            Write-Host "This script is not configured to report on SharePoint 2010, please manually confirm the configurationg described in the below article:`nhttps://docs.microsoft.com/en-us/previous-versions/office/sharepoint-server-2010/mt773992(v=office.14)?redirectedfrom=MSDN"
            return $null
        }
        2013
        {
            Write-Host "SharePoint 2013 detected, please reference:`nhttps://docs.microsoft.com/en-us/SharePoint/security-for-sharepoint-server/enable-tls-and-ssl-support-in-sharepoint-2013`n"
            switch ($winVersion)
            {
                2008R2
                {
                    $checks+="tlsEnabledInSchannel,True"
                    $checks+="tlsEnabledInWinHTTP,True"
                }
                2012
                {
                    $checks+="tlsEnabledInWinHTTP,True"
                }
                2012R2
                {
                    #
                }
                Default {Write-Warning "Unsupported OS"}
            }
            $checks+="sql2008R2NativeClientUpdated,True"
            $checks+="net46orHigherInstalled,True"
            $checks+="strongCyptographyEnabled4,True"
            $checks+="strongCyptographyEnabled2,False"
            $checks+="oldTlsVersionsDisabled,False"
        }
        2016
        {
            Write-Host "SharePoint 2016 detected, please reference:`nhttps://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016`n"
            $checks+="odbc11Updated,True"
            $checks+="sql2012NativeClientUpdated,True"
            $checks+="strongCyptographyEnabled4,False"
            $checks+="strongCyptographyEnabled2,False"
            $checks+="oldTlsVersionsDisabled,False"
        }
        2019
        {
            Write-Host "SharePoint 2019 detected, please reference:`nhttps://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2019`n"
            $checks+="oldTlsVersionsDisabled,False"
        }
        Default {throw "Uknown version of SharePoint detected"}
    }


    $results = @()
    foreach($check in $checks)
    {
        $results+=[PSCustomObject]@{
            Name = checkFriendlyName $check.Split(",")[0]
            Required = $check.Split(",")[1]
            Configured = (Invoke-Expression $check.Split(",")[0])
        }
    }

    AzureFrontDoorCiphersEnabled
    
    Write-Host "`n`n`nTLS 1.2 Configurations:"
    $results | Format-Table -AutoSize -Property Required, Configured, Name -Wrap
    #return $results
}



function AzureFrontDoorCiphersEnabled
{
    Write-Host "Checking whether ciphers compatible with Azure Front Door are enabled."
    Write-Host "These are required for hybrid functionality such as hybrid search or hybrid taxonomy."
    
    $keys = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL -Recurse
    $keys += Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL -Recurse -ErrorAction SilentlyContinue
    
    $afdCiphers = @(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    $supportedCiphers = @()
    $priorityThreshold = 10
    $priorityWarning = $false

    foreach($key in $keys)
    {
        if($key.Name.EndsWith("00010002"))
        {
            $cipherString = $key.GetValue("Functions")
            if(![String]::IsNullOrEmpty($cipherString))
            {
                $ciphers = $cipherString.Split(",")
                foreach($afdCipher in $afdCiphers)
                {
                    if($ciphers.Contains($afdCipher) -and !$supportedCiphers.Contains($afdCipher))
                    {
                        $supportedCiphers+=$afdCipher
                        $idx = $ciphers.IndexOf($afdCipher)
                        if($idx -gt $priorityThreshold-1)
                        {
                            $priorityWarning = $true
                        }
                    }
                }
            }
        }
    }
    if($supportedCiphers -le 0)
    {
        Write-Warning "No ciphers supported by Azure Front Door were found!!!"
        Write-Host "If you are not using hybrid features or reaching out to Azure or other online hosted services you can ignore this"
    }
    else
    {
        Write-Host ("Found {0} ciphers supported by Azure Front Door" -f $supportedCiphers.Count, $afdCiphers.Count) -ForegroundColor Green
        foreach($supportedCipher in $supportedCiphers)
        {
            Write-Host $supportedCipher.ToString() -ForegroundColor Green
        }

        if($priorityWarning)
        {
            Write-Warning "Priority of Azure Front Door compatible ciphers may be too low"
        }
    }

    if((Get-WmiObject Win32_OperatingSystem).Version.StartsWith("6."))
    {
        Write-Warning "Pre windows 2016 detected, even with proper ciphers enabled there may still be intermittent issues.`nPlease refer to this article:`nhttps://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/apps-forcibly-closed-tls-connection-errors"
    }
}


cls
main
