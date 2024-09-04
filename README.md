# Modifications done
- The scripts deploy to C:\_scripts
- The script looks for a certificate based on a template called "zs-cert-SRV-SQL-Server"

# Original readme.md
These scripts allow the use of Windows 8+ and Windows Server 2012+ Certificate Services Lifecycle Notifications to automatically deploy new certificates after they are renewed - see https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

Supported products:
 - SQL Server Database Engine
 - SQL Server Reporting Services

They will work with certificates autorenewed via Active Directory Certificate Services if you use the Certificate Template name of 'SQL Server' and 'Internal Web Server' respectively (to use other names, update the script!)

If you are using a third-party Certificate Authority e.g. Let's Encrypt you can still use the Certificate Services Lifecycle Notifications feature

To use, review and download both files .ps1 files to a folder, then run Deploy-CertificateRenewalTasks.ps1

Then either perform a certificate autorenewal using ADCS, or when using a third-party Certificate Authority, use the PowerShell command Switch-Certificate -OldCert <thumbprint> -NewCert <thumbprint> to mark the certificate as 'replaced' and trigger the task - see https://learn.microsoft.com/en-us/powershell/module/pki/switch-certificate?view=windowsserver2022-ps
