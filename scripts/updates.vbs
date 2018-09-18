Dim pcengine
pcengine = LCase(Mid(WScript.Fullname, InstrRev(WScript.FullName, "\") + 1))
If Not pcengine = "cscript.exe" Then
    WScript.Echo "Lancer avec cscript.exe"
    WScript.Quit
End If

Set args = Wscript.Arguments

If args.Count = 0 Then
    WScript.Echo "Usage: updates.vbs [FILE]"
    WScript.Echo "  Le fichier provient de http://go.microsoft.com/fwlink/p/?LinkID=74689"
    WScript.Echo "  Il faut passer le chemin complet du fichier"
    WScript.Quit
End If

Set UpdateSession = CreateObject("Microsoft.Update.Session")
Set UpdateServiceManager = CreateObject("Microsoft.Update.ServiceManager")
Set UpdateService = UpdateServiceManager.AddScanPackageService("Offline Sync Service", args.Item(0))
Set UpdateSearcher = UpdateSession.CreateUpdateSearcher()

WScript.Echo "Searching for updates..." & vbCRLF

UpdateSearcher.ServerSelection = 3 ' ssOthers

UpdateSearcher.ServiceID = UpdateService.ServiceID

Set SearchResult = UpdateSearcher.Search("IsInstalled=0")

Set Updates = SearchResult.Updates

If searchResult.Updates.Count = 0 Then
    WScript.Echo "There are no applicable updates."
    WScript.Quit
End If

WScript.Echo "List of applicable items on the machine when using wssuscan.cab:" & vbCRLF

For I = 0 to searchResult.Warnings.Count-1
    Set warn = searchResult.Warnings.Item(I)
    WScript.Echo warn.Message
Next

For I = 0 to searchResult.Updates.Count-1
    Set update = searchResult.Updates.Item(I)
    Set bids = ""
    For J = 0 to update.SecurityBulletinIDs.Count-1
        Set bid = update.SecurityBulletinIDs.Item(J)
        bids = bids & " " & bid
    Next
    WScript.Echo update.Title & vbTab & update.MsrcSeverity & vbTab & update.Identity.UpdateID & "/" & update.Identity.RevisionNumberA & vbTab & bids
Next

WScript.Quit
