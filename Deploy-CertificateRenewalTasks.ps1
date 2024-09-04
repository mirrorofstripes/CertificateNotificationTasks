# Based on https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx
# Look for any certificates with relevant 'Certificate Template Information', and deploy a new task to be triggered when the certificate is replaced
# If the script deployed is updated, recreate the task - will also re-trigger the task to update any existing certificates

$CertificateNotificationTaskName = "Internal-SystemCertificateRenewalTask"
$NotificationScriptFile = "Update-RenewedSystemCertificates.ps1"
$ScriptDestinationPath = "$env:SystemDrive\_scripts"

$SQLServerCertificates = Get-ChildItem Cert:\LocalMachine\My\ | Where-Object { $_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -and $_.Format(0) -match "^Template=SQL Server\(" } }

if ($null -ne $SQLServerCertificates) {
    if (-not (Test-Path -Path $ScriptDestinationPath -PathType Container)) { # Create the destination directory if it does not already exist
        New-Item $ScriptDestinationPath -Type Directory | Out-Null
    }

    # If the destination script file does not yet exist, or is not up to date
    if (-not (Test-Path -Path "$ScriptDestinationPath\$NotificationScriptFile" -PathType Leaf) -or (Get-FileHash -Path "$PSScriptRoot\$NotificationScriptFile").Hash -ne (Get-FileHash -Path "$ScriptDestinationPath\$NotificationScriptFile").Hash) {
        Write-Output "Deploying certificate notification script '$ScriptDestinationPath\$NotificationScriptFile'..."
        Copy-Item -Path "$PSScriptRoot\$NotificationScriptFile" -Destination $ScriptDestinationPath -Force
        Unblock-File -Path "$ScriptDestinationPath\$NotificationScriptFile" # Unblock the file if it is still marked as downloaded from the Internet

        if (Get-CertificateNotificationTask | Where-Object { $_.Name -eq $CertificateNotificationTaskName }) { Remove-CertificateNotificationTask -Name $CertificateNotificationTaskName } # If the named certificate notification task already exists, first remove it
        Write-Output "Deploying certificate notification task '$CertificateNotificationTaskName'..."
        New-CertificateNotificationTask -Type Replace -RunTaskForExistingCertificates -PSScript "$ScriptDestinationPath\$NotificationScriptFile" -Name $CertificateNotificationTaskName -Channel System | Out-Null
    }
}
