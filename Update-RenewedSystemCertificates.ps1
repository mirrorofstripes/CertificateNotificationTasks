# Based on https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx
# Update any certificates used by the relevant services - will be passed $OldCertHash, $NewCertHash and $EventRecordId
# Passing only NewCertHash will install the relevant certificate for Microsoft SQL Server Database Engine instances

Param(
    [String]$OldCertHash,
    [Parameter(Mandatory=$true)]
    [String]$NewCertHash,
    [Int32]$EventRecordId
)

if ($null -eq $OldCertHash) { $OldCertHash = '' } # Allow missing OldCertHash to be passed to trigger configuring a new certificate (only works on Microsoft SQL Server Database Engine instances)

$NewCertificate = Get-Item -Path Cert:\LocalMachine\My\$NewCertHash

# If the new certificate template information shows it is an SQL Server certificate - prevent the incorrect certificate template from being selected when passing NewCertHash only
if ($NewCertificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "^Template=SQL Server\(" }) {
    # Look for any Microsoft SQL Server instances using the old certificate thumbprint
    foreach ($SuperSocketNetLibKey in Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*\MSSQLSERVER\SuperSocketNetLib" | Where-Object { $_.GetValue('Certificate') -eq $OldCertHash }) { # Based on https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption?view=sql-server-ver16
        # Get the instance name, service name and account of this SQL Server - based on https://dba.stackexchange.com/questions/56045/any-relation-between-sql-server-service-name-and-instance-name
        $SQLServerRegKey = Get-Item ($SuperSocketNetLibKey | Split-Path | Split-Path)
        $SQLServerInstanceName = $SQLServerRegKey.GetValue($null) # SQL Server registry key default value is instance name
        $SQLServiceName = @('MSSQLSERVER', $("MSSQL`$$SQLServerInstanceName"))[!($SQLServerInstanceName -eq 'MSSQLSERVER')]
        $SQLServiceObject = Get-CimInstance -ClassName Win32_Service -Filter "Name='$SQLServiceName'" -Property StartName

        # Set permissions on the private key for certificate - based on https://blog.wicktech.net/update-sql-ssl-certs/
        Write-Output "Setting ACL on SQL Server Certificate Thumbprint '$NewCertHash' for SQL Server instance '$SQLServerInstanceName' running as '$($SQLServiceObject.StartName)'..."
        $NewCertificatePrivateKeyPath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$($NewCertificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"
        $NewCertificatePrivateKeyAcl = Get-Acl -Path $NewCertificatePrivateKeyPath
        $NewCertificatePrivateKeyAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $SQLServiceObject.StartName, 'Read', 'Allow'
        $NewCertificatePrivateKeyAcl.AddAccessRule($NewCertificatePrivateKeyAccessRule)
        Set-Acl -Path $NewCertificatePrivateKeyPath -AclObject $NewCertificatePrivateKeyAcl

        # Update the certificate thumbprint with this certificate on this SQL Server and restart - for SQL Server 2019, must be in lower case https://stackoverflow.com/a/74285913
        Write-Output "Updating Certificate Thumbprint for SQL Server instance '$SQLServerInstanceName' to '$($NewCertHash.ToLower())'..."
        $SuperSocketNetLibKey | Set-ItemProperty -Name "Certificate" -Value $NewCertHash.ToLower()

        # Restart the SQL Server instance
        Write-Output "Restarting SQL Server instance '$SQLServerInstanceName'..."
        Restart-Service -Name $SQLServiceName -Force
    }
}

# Get this device's Windows system locale for use with SQL Server Reporting Services WMI methods
$SystemLocale = Get-WinSystemLocale

# If there is an instance of the SQL Server Reporting Services service installed
if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SQLServerReportingServices" -PathType Container) {
    # Look for any SQL Server Reporting Services instances using the old certificate thumbprint - based on https://community.certifytheweb.com/t/sql-server-reporting-services-ssrs/332
    # Also based on https://learn.microsoft.com/en-us/answers/questions/924375/ssrs-pbi-report-server-still-linked-to-old-certifi
    foreach ($SQLServerRSInstance in Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer -ClassName __Namespace) {
        $SQLServerRSVersion = Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer\$($SQLServerRSInstance.Name) -ClassName __Namespace
        $SQLServerRSConfigurationSetting = Get-CimInstance -Namespace root\Microsoft\SqlServer\ReportServer\$($SQLServerRSInstance.Name)\$($SQLServerRSVersion.Name)\Admin -ClassName MSReportServer_ConfigurationSetting
        $SQLServerRSReservedURLs = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName ListReservedURLs
        $SQLServerRSSSLCertificateBindings = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName ListSSLCertificateBindings -Arguments @{Lcid=$SystemLocale.LCID}

        # If the old certificate hash is used by the Web Service URL (ReportServerWebService) of this SQL Server Reporting Services instance (NB only check this application since the Web Portal URL application appears to depend on it)
        if ($SQLServerRSSSLCertificateBindings.CertificateHash[$SQLServerRSSSLCertificateBindings.Application.IndexOf('ReportServerWebService')] -eq $OldCertHash) {
            # Find the existing HTTPS port of the Web Service URL (ReportServerWebService)
            for ($i = 0; $i -lt $SQLServerRSSSLCertificateBindings.Application.Count; $i++) {
                if ($SQLServerRSSSLCertificateBindings.Application[$i] -eq 'ReportServerWebService' -and $SQLServerRSSSLCertificateBindings.CertificateHash[$i] -eq $OldCertHash) {
                    $SQLServerRSHTTPSPort = $SQLServerRSSSLCertificateBindings.Port[$i]
                }
            }

            # Delete the bindings for the Web Portal URL (ReportServerWebApp) first, then delete the bindings for the Web Service URL (ReportServerWebService) second
            foreach ($SQLServerRSApplication in 'ReportServerWebApp', 'ReportServerWebService') {
                # Remove any existing reserved HTTPS URLs for this application
                for ($i = 0; $i -lt $SQLServerRSReservedURLs.Application.Count; $i++) {
                    if ($SQLServerRSReservedURLs.Application[$i] -eq $SQLServerRSApplication -and $SQLServerRSReservedURLs.UrlString[$i] -match "^https:") {
                        Write-Output "Removing reserved URL for SQL Server Reporting Services '$SQLServerRSApplication': '$($SQLServerRSReservedURLs.UrlString[$i])'..."
                        $SQLRemoveWMIMethodResult = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName RemoveURL -Arguments @{Application=$SQLServerRSApplication;UrlString=$SQLServerRSReservedURLs.UrlString[$i];Lcid=$SystemLocale.LCID}
                        if ($SQLRemoveWMIMethodResult.HRESULT -ne 0) {
                            Write-Error "Error $($SQLRemoveWMIMethodResult.HRESULT) removing reserved URL for SQL Server Reporting Services: $($SQLRemoveWMIMethodResult.Error)"
                        }
                    }
                }
                # Remove any existing SSL certificate bindings for this application
                for ($i = 0; $i -lt $SQLServerRSSSLCertificateBindings.Application.Count; $i++) {
                    if ($SQLServerRSSSLCertificateBindings.Application[$i] -eq $SQLServerRSApplication -and $SQLServerRSSSLCertificateBindings.CertificateHash[$i] -eq $OldCertHash) {
                        Write-Output "Removing SSL Certificate Binding for SQL Server Reporting Services '$SQLServerRSApplication' with IP Address '$($SQLServerRSSSLCertificateBindings.IPAddress[$i])' and port '$($SQLServerRSSSLCertificateBindings.Port[$i])': $($SQLServerRSSSLCertificateBindings.CertificateHash[$i]).."
                        $SQLRemoveWMIMethodResult = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName RemoveSSLCertificateBindings -Arguments @{Application=$SQLServerRSApplication;CertificateHash=$SQLServerRSSSLCertificateBindings.CertificateHash[$i];IPAddress=$SQLServerRSSSLCertificateBindings.IPAddress[$i];Port=$SQLServerRSSSLCertificateBindings.Port[$i];Lcid=$SystemLocale.LCID}
                        if ($SQLRemoveWMIMethodResult.HRESULT -ne 0) {
                            Write-Error "Error $($SQLRemoveWMIMethodResult.HRESULT) removing SSL Certificate Binding for SQL Server Reporting Services: $($SQLRemoveWMIMethodResult.Error)"
                        }
                    }
                }
            }
            # Add the bindings for the Web Service URL (ReportServerWebService) third, then add the bindings for the Web Portal URL (ReportServerWebApp) fourth
            foreach ($SQLServerRSApplication in 'ReportServerWebService', 'ReportServerWebApp') {
                # Reserve each HTTPS URL of the Subject Alternate Name(s) of the new certificate
                foreach ($NewCertificateDNSSubjectAlternateName in $NewCertificate.Extensions.Where({$_.Oid.Value -eq '2.5.29.17'}).Format(1) -split [System.Environment]::NewLine | Where-Object { $_ -match "^DNS Name=" }) {
                    $NewSQLServerRSUrlString = "https://$($NewCertificateDNSSubjectAlternateName -replace "^DNS Name="):$SQLServerRSHTTPSPort"
                    Write-Output "Adding reserved URL for SQL Server Reporting Services '$SQLServerRSApplication': '$NewSQLServerRSUrlString'..."
                    $SQLCreateWMIMethodResult = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName ReserveURL -Arguments @{Application=$SQLServerRSApplication;UrlString=$NewSQLServerRSUrlString;Lcid=$SystemLocale.LCID}
                    if ($SQLCreateWMIMethodResult.HRESULT -ne 0) {
                        Write-Error "Error $($SQLCreateWMIMethodResult.HRESULT) adding reserved URL for SQL Server Reporting Services: $($SQLCreateWMIMethodResult.Error)"
                    }
                }
                # Add the SSL certificate bindings back with the new certificate thumbprint - to avoid error use lower case https://ruiromanoblog.wordpress.com/2010/05/08/configure-reporting-services-ssl-binding-with-wmi-powershell/
                for ($i = 0; $i -lt $SQLServerRSSSLCertificateBindings.Application.Count; $i++) {
                    if ($SQLServerRSSSLCertificateBindings.Application[$i] -eq $SQLServerRSApplication -and $SQLServerRSSSLCertificateBindings.CertificateHash[$i] -eq $OldCertHash) {
                        Write-Output "Creating SSL Certificate Binding for SQL Server Reporting Services '$SQLServerRSApplication' with IP Address '$($SQLServerRSSSLCertificateBindings.IPAddress[$i])' and port '$SQLServerRSHTTPSPort': $($NewCertHash.ToLower())..."
                        $SQLCreateWMIMethodResult = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName CreateSSLCertificateBinding -Arguments @{Application=$SQLServerRSApplication;CertificateHash=$NewCertHash.ToLower();IPAddress=$SQLServerRSSSLCertificateBindings.IPAddress[$i];Port=$SQLServerRSHTTPSPort;Lcid=$SystemLocale.LCID}
                        if ($SQLCreateWMIMethodResult.HRESULT -ne 0) {
                            Write-Error "Error $($SQLCreateWMIMethodResult.HRESULT) adding SSL Certificate Binding for SQL Server Reporting Services: $($SQLCreateWMIMethodResult.Error)"
                        }
                    }
                }
            }
            # Enforce redirecting HTTP sessions to SSL in SQL Server Reporting Services
            Write-Output "Setting secure connection level for SQL Server Reporting Services to '1'..."
            $SQLSetSecureMethodResult = $SQLServerRSConfigurationSetting | Invoke-CimMethod -MethodName SetSecureConnectionLevel -Arguments @{Level=1}
            if ($SQLSetSecureMethodResult.HRESULT -ne 0) {
                Write-Error "Error $($SQLSetSecureMethodResult.HRESULT) setting secure connection level for SQL Server Reporting Services: $($SQLSetSecureMethodResult.Error)"
            }

            # Restart SQL Server Reporting Services instance
            Write-Output "Restarting SQL Server Reporting Services 'SQLServerReportingServices'..."
            Restart-Service -Name 'SQLServerReportingServices' -Force
        }
    }
}
