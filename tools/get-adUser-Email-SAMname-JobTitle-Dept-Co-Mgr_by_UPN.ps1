Import-Module ActiveDirectory

# List of UPNs (one per line)
$Upns = @"

user1@domain.com 
user2@domain.com 
user3@domain.com 

"@ -split "\r?\n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }   # removes blanks

$Results = foreach ($Upn in $Upns) {

    $User = Get-ADUser -Filter "UserPrincipalName -eq '$Upn'" -Properties `
        SamAccountName, Mail, Title, Department, Company, Manager, UserPrincipalName

    if ($null -ne $User) {

        $ManagerName = if ($User.Manager) {
            try {
                (Get-ADUser -Identity $User.Manager -Properties DisplayName).DisplayName
            } catch {
                "N/A"
            }
        } else {
            "N/A"
        }

        [PSCustomObject]@{
            Input          = $Upn
            UPN            = $User.UserPrincipalName
            SamAccountName = $User.SamAccountName
            Email          = $User.Mail
            JobTitle       = $User.Title
            Department     = $User.Department
            Company        = $User.Company
            Manager        = $ManagerName
        }

    } else {
        Write-Warning "User '$Upn' not found in AD."

        [PSCustomObject]@{
            Input          = $Upn
            UPN            = $null
            SamAccountName = $null
            Email          = $null
            JobTitle       = $null
            Department     = $null
            Company        = $null
            Manager        = $null
        }
    }
}

# Display results
if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $Results | Out-GridView -Title "AD Users by UPN"
} else {
    $Results | Format-Table -AutoSize
}
