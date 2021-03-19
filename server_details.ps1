$X = READ-HOST("ENTER COMPUTER NAME")
Get-ADcomputer -identity $x -Properties *