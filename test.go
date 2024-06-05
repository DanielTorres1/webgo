package main

import (
    "fmt"
    "regexp"
)

func main() {
    headers := ` Request-Id: 3ea82fa1-4724-d0c7-fa79-1f2337824f88
	X-Powered-By: ASP.NET
	Www-Authenticate: NTLM
	Cache-Control: private
	Content-Type: text/plain; charset=utf-8
	Sprequestguid: 3ea82fa1-4724-d0c7-fa79-1f2337824f88
	X-Aspnet-Version: 4.0.30319
	X-Content-Type-Options: nosniff
	Content-Length: 16
	X-Frame-Options: SAMEORIGIN
	Spiislatency: 10
	Date: Wed, 05 Jun 2024 12:19:29 GMT
	Sprequestduration: 10
	X-Ms-Invokeapp: 1; RequireReadOnly
	Microsoftsharepointteamservices: 15.0.0.4420
	
	401 UNAUTHORIZED`

	re := regexp.MustCompile(`Microsoftsharepointteamservices: ([\d.]+)\r?\n`)
    matches := re.FindStringSubmatch(headers)

    if len(matches) > 1 {
        version := matches[1]
        fmt.Printf("SharePoint Team Services version: %s\n", version)
    } else {
        fmt.Println("Version not found")
    }
}