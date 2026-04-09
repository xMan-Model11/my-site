Import-Module ActiveDirectory

# List of users upns. Replace with your list:
$Usernames = @"

user1@domain.com #<--upn of user goes here
user2@domain.com 
user3@domain.com 

"@ -split "\r?\n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }   # removes blanks

# Collect results (one row per user-group)
$results = foreach ($u in $Usernames) {
    try {
        $user = Get-ADUser -Filter "UserPrincipalName -eq '$u'" -ErrorAction Stop

        # Memberships (generally includes nested membership)
        $groups = Get-ADPrincipalGroupMembership -Identity $user |
                  Select-Object -ExpandProperty Name |
                  Sort-Object

        foreach ($g in $groups) {
            [PSCustomObject]@{
                UserSamAccountName = $u
                GroupName          = $g
            }
        }
    }
    catch {
        # Preserve failures in output so your report is complete
        [PSCustomObject]@{
            UserSamAccountName = $u
            GroupName          = $null
            Error              = $_.Exception.Message
        }
    }
}

# Display
$results | Sort-Object UserSamAccountName, GroupName | Format-Table -AutoSize

# Optional export
# $results | Export-Csv ".\UserGroupMemberships.csv" -NoTypeInformation -Encoding UTF8
