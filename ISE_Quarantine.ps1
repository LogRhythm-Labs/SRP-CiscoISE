# Mark Vankempen
# 15-10-13
# Modified script to handle terminating and non-terminating exceptions. 
# Added URL error checking to see if the ip supplied is correct
#
# Test that the API is working by using this url in a browser
# .\ISE_Quarantine.ps1 -NoProfile "<ISE IP Address>" "QuarantineByMAC_S" "<Test MAC Address with no colons>" 

# Set up a trap to properly exit on terminating exceptions
trap [Exception] 
{
	write-error $("TRAPPED: " + $_)
	exit 1
}


# Read in the parameters passed by the SmartResponse action
#args[0] = the switch -NoProfile. -NoProfile Tells the PowerShell console not to load the current user’s profile. 
$QuarantineMethod = $args[1]  #either "QuarantineByMAC_S" or "QuarantineByIP_S" or "QuarantineByID_S"
$monitoring_node = $args[2]   #ipaddress or hostname of the ISE node
$QuarantineType = $args[3]    #the physical mac address, ip address, or sessionID
$User = $args[4]              #User with Cisco ISE administrator privileges
$Pass = $args[5]              #Password

#"args[0] = $args[0], args[1] = $args[1], args[2] = $args[2], args[3] = $args[3]" 

$BaseAuthUrl = "https://$monitoring_node/ise/eps/"
#$AuthUrl = "https://afblrise.afbins.net/ise/eps/QuarantineByMAC/98:FE:94:1D:65:10"

switch ($QuarantineMethod)
{
    "QuarantineByMAC_S" 
    {
        $UrlSuffix = "QuarantineByMAC_S/$QuarantineType"
    }
    
    "QuarantineByIP_S"
    {
        $UrlSuffix = "QuarantineByIP_S/$QuarantineType"
    }
    
    "QuarantineByID_S"
    {
        $UrlSuffix = "QuarantineByID_S/$QuarantineType"    
    }
    "QuarantineByMAC" 
    {
        $UrlSuffix = "QuarantineByMAC/$QuarantineType"
    }
    
    "QuarantineByIP"
    {
        $UrlSuffix = "QuarantineByIP/$QuarantineType"
    }
    
    "QuarantineByID"
    {
        $UrlSuffix = "QuarantineByID/$QuarantineType"    
    }    

} 

# Ignore invalid SSL certification warning
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Echo the URL back to the SmartResponse Status viewer
$AuthUrl = $BaseAuthUrl + $UrlSuffix
"AuthUrl : $AuthUrl"


######################################
# Execute API Call & Quarantine Host #
######################################
try 
{

    $webrequest = [System.Net.WebRequest]::Create("$AuthUrl")    
    $auth = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($User+":"+$Pass ))
    $webrequest.Headers.Add('Authorization', $auth )

    Write-Host $webrequest.RequestUri
    $webrequest.PreAuthenticate = $true
    #$webrequest.Headers.Add("UserAgent","LogRhythm SmartResponse Cisco ISE API Powershell Script")
    $webrequest.Credentials = new-object system.net.networkcredential("$User", "$Pass")
    $response = $webrequest.GetResponse()
    $sr = [Io.StreamReader]($response.GetResponseStream()) 
    [xml]$xmlout = $sr.ReadToEnd()

    [System.Xml.XmlElement] $FullXML = $xmlout.get_DocumentElement()
    $ReturnMessage = $FullXML.returnMesg

    $ReturnMessage
      
}
catch [System.Exception]
{
    "*** Error Quarantining Host ***`n"
    Write-Host $_.Exception.ToString()
    $error[0]
    Exit 1
}
if($ReturnMessage -match "No Active Session found for this MAC Address")
{
    "*** Error Quarantining Host ***`n"
    Write-Host $ReturnMessage
    Exit 1
}


#########################################
# Handle any non-terminating exceptions #
#########################################
if(-not $?)
{
    Write-Error "Could not quarantine host`n$?"
	exit 10
}
else
{
    # Successfully finished
    "Host $QuarantineType quarantined via $QuarantineMethod"
    Exit 0
}






####################Attempt 5(ALMOST WORKS RETURNS THIS ERROR: System.Net.WebException: The remote server returned an error: (401) Unauthorized.)
<#$client = New-Object Net.WebClient
    
    $auth = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($User+":"+$Pass ))

    $client.Headers.Add('Authorization', $auth )
    # Create the authentication object
    $credCache = new-object System.Net.CredentialCache
    $creds = new-object System.Net.NetworkCredential("$User","$Pass")
    $credCache.Add("$AuthUrl", "Basic", $creds)
    # Add the authentication object to the webclient object
    $client.Credentials = $credCache
    [xml]$webpage = $client.DownloadString($AuthUrl)#>
    

##################attempt 4 (ALMOST WORKS RETURNS THIS ERROR: System.Net.WebException: The remote server returned an error: (401) Unauthorized.)
<#  #$auth = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($User+":"+$Pass ))
    $req = New-Object System.Net.WebClient
    $req.Headers.Add('Content-Type', 'application/xml')
    $req.Headers.Add('Accept', 'application/xml')
    #$req.Headers.Add('Authorization', $auth )
    
    $credCache = new-object System.Net.CredentialCache
    $creds = new-object System.Net.NetworkCredential("$User",$Pass)
    $credCache.Add("https://$monitoring_node", "Basic", $creds)

    # Add the authentication object to the webclient object
    $req.Credentials = $credCache
    
    [xml]$webpage = $req.DownloadString($AuthUrl)#>

#######################attempt 3 (ALMOST WORKS RETURNS THIS ERROR: System.Net.WebException: The remote server returned an error: (401) Unauthorized.)
 <#$webrequest = [System.Net.WebRequest]::Create("$AuthUrl")
    Write-Host $webrequest.RequestUri
    $webrequest.PreAuthenticate = $true
    #$webrequest.Headers.Add("UserAgent","LogRhythm SmartResponse Cisco ISE API Powershell Script")
    $webrequest.Credentials = new-object system.net.networkcredential("$User", "$Pass")
    $response = $webrequest.GetResponse()
    $sr = [Io.StreamReader]($response.GetResponseStream()) 
    [xml]$xmlout = $sr.ReadToEnd()  #>


########attempt 2
    <#$webclient = new-object System.Net.WebClient
    $credCache = new-object System.Net.CredentialCache
    $creds = new-object System.Net.NetworkCredential($username,$password)
    $credCache.Add("$AuthUrl", "Basic", $creds)
    $webclient.Credentials = $credCache
    $webpage = $webclient.DownloadString("$AuthUrl")#>


############attempt 1
   <# $webRequest = [System.Net.WebRequest]::Create($url)
    $webRequest.ContentType = "text/html"
    $PostStr = [System.Text.Encoding]::UTF8.GetBytes($Post)
    $webrequest.ContentLength = $PostStr.Length
    $webRequest.ServicePoint.Expect100Continue = $false
    $webRequest.Credentials = New-Object System.Net.NetworkCredential -ArgumentList $username, $password
    
    $webRequest.PreAuthenticate = $true
    $webRequest.Method = "POST"
 
    $requestStream = $webRequest.GetRequestStream()
    $requestStream.Write($PostStr, 0,$PostStr.length)
    $requestStream.Close()
 
    [System.Net.WebResponse] $resp = $webRequest.GetResponse()
    $rs = $resp.GetResponseStream()
    [System.IO.StreamReader] $sr = New-Object System.IO.StreamReader -argumentList $rs
    [string] $results = $sr.ReadToEnd() #>