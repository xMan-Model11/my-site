Import-Module ActiveDirectory

$GroupName = "Enter_Group_Name" # <-- put group name here 
$OuDn      = "OU=,OU=,DC="   # <-- put your OU DN here 

$users =
    Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction Stop |
    Where-Object { $_.objectClass -eq "user" } |
    ForEach-Object {
        # Resolve to full AD user object (DN is available for filtering)
        Get-ADUser -Identity $_.DistinguishedName -Properties DistinguishedName
    } |
    Where-Object {
        # Match users anywhere under that OU (including child OUs)
        $_.DistinguishedName -like "*$OuDn"
    } |
    Select-Object Name, SamAccountName, DistinguishedName

$users | Out-GridView -Title "Users in $GroupName under $OuDn"
