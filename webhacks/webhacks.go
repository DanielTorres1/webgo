package webhacks

import (
	"crypto/tls"
    "bufio"
	"math/rand"
	"unicode"
    "fmt"
    "net/http"
	"net/url"
    "os"
    "sync"
	"regexp"
	"time"
	"io/ioutil"
    "strings"
)

type WebHacks struct {
    // Add the necessary fields based on your requirements
    Debug       bool
    Show404		bool
    Rhost       string
    Rport       string
    Path        string
	MaxRedirect int
	Timeout 	int
    Error404    string
    Threads     int
    Proto       string
    Cookie      string
    Ajax        bool
    Client      *http.Client
	Headers     http.Header
}


func NewWebHacks(timeoutInSeconds, MaxRedirect int) *WebHacks {
    // Initialize the random number generator.
    rand.Seed(time.Now().UnixNano())

    // List of the most used User-Agents.
    userAgents := []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 13_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Mobile/15E148 Safari/604.1",
    }

    // Select a User-Agent randomly.
    selectedUserAgent := userAgents[rand.Intn(len(userAgents))]

	// Create a custom HTTP transport that ignores SSL certificate errors
    httpTransport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
            MinVersion: tls.VersionTLS10,
			//MaxVersion: tls.VersionTLS12,
        },
    }

    httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   time.Duration(timeoutInSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirect {
				return http.ErrUseLastResponse // Stop after MaxRedirect
			}
			return nil // Allow the redirect
		},
	}

    wh := &WebHacks{
        Client:  httpClient,
        Headers: http.Header{},
        Timeout: timeoutInSeconds,
		MaxRedirect: MaxRedirect,
    }

    // Configure headers
    wh.Headers.Set("User-Agent", selectedUserAgent)
	wh.Headers.Set("Cache-Control", "max-age=0")
	wh.Headers.Set("Accept", "*/*")
	wh.Headers.Set("DNT", "1")

	if wh.Ajax {
		wh.Headers.Set("X-Requested-With", "XmlHttpRequest")
	}

    return wh
}


func (wh *WebHacks) GetData(logFile string) (map[string]string, error) {
	debug := wh.Debug
	rhost := wh.Rhost
	rport := wh.Rport
	proto := wh.Proto
	path := wh.Path

	// if debug {
	// 	fmt.Printf("Configuracion:  proto:%s timeout %s debug %s MaxRedirect %s \n\n", proto,timeout, debug, MaxRedirect)
	// }

	poweredBy := ""
	var urlOriginal string
	if rport == "80" || rport == "443" {
		urlOriginal = proto + "://" + rhost + path
	} else {
		urlOriginal = proto + "://" + rhost + ":" + rport + path
	}

	redirectURL := "no"
	currentURL := urlOriginal
	var finalURLRedirect string
	var decodedResponse string
	var resp *http.Response 
	var err error
	status := ""
	newDomain := ""
	lastURL := ""
	vulnerability := ""

	for redirectURL != "" {
		if debug {
			fmt.Printf("currentURL (%s)\n", currentURL)
			fmt.Printf("redirect_url en WHILE1 (%s)\n", redirectURL)
		}
		resp, err = wh.Dispatch(currentURL, "GET", wh.Headers)
		if err != nil {			
			fmt.Printf("Error %s \n", err)
		}
		lastURL = resp.Request.URL.String()
		status = resp.Status

		

		if urlOriginal != lastURL {
			poweredBy += "|301 Moved"
		}

		
		// Check redirection from http to https
		origURL, _ := url.Parse(urlOriginal)
		finalURL, _ := url.Parse(lastURL)
		if origURL.Scheme != finalURL.Scheme {
			poweredBy += "|HTTPSredirect"
		}
	
		// Check domain redirect
		domainOriginal := origURL.Hostname()
		domainFinal := finalURL.Hostname()
		if debug {
			fmt.Printf("domain_original %s domain_final %s\n", domainOriginal, domainFinal)
			fmt.Printf("url_original %s last_url %s\n", urlOriginal, lastURL)
		}

		if domainOriginal != domainFinal {
			poweredBy += "|301 Moved"
			newDomain = domainFinal
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		decodedResponse = string(body)
		decodedResponse = strings.ReplaceAll(decodedResponse, "'", "\"")
		decodedResponse = strings.ReplaceAll(decodedResponse, "<noscript>.*?</noscript>", "")
		decodedResponse = regexp.MustCompile(".*\\/logout.*\\n").ReplaceAllString(decodedResponse, "")
		decodedResponse = regexp.MustCompile(".*sclogin.html*").ReplaceAllString(decodedResponse, "")
		decodedResponse = regexp.MustCompile(".*index.html*").ReplaceAllString(decodedResponse, "")
		decodedResponse = regexp.MustCompile(".*?console*").ReplaceAllString(decodedResponse, "")

		
		
		//###### check redirect with content ##########
		responseLength := len(decodedResponse)
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 && responseLength > 900 {
			vulnerability = "Redirect with content|"
			//break
		}
		if debug {
			fmt.Printf("responseLength %d \n", responseLength)
		}
		//#####################################
		
		redirectURL = getRedirect(decodedResponse)
		if debug {
			fmt.Printf("redirect_url (%s)\n", redirectURL)
		}

		if redirectURL != "" {
			// redirect is URL complete
			if strings.Contains(redirectURL, "http") {
				finalURLRedirect = redirectURL
			} else { // redirect is only url part 
				firstChar := redirectURL[:1]
				if debug {
					fmt.Printf("firstChar %s\n", firstChar)
				}
				if firstChar == "/" {
					finalURLRedirect = urlOriginal + redirectURL[1:]
				} else {
					finalURLRedirect = urlOriginal + redirectURL
				}
			}
			if debug {
				fmt.Printf("final_url_redirect %s\n", finalURLRedirect)
			}
			currentURL = finalURLRedirect
		}
		if debug {
			fmt.Printf("currentURL en WHILE2 %s\n", currentURL)
		}
	} //end for

	responseHeaders := headerToString(resp.Header)
	decodedHeaderResponse := responseHeaders + "\n" + decodedResponse
	decodedResponse = strings.ReplaceAll(decodedResponse, "'", "\"")
	decodedResponse = regexp.MustCompile("[^\\x00-\\x7f]").ReplaceAllString(decodedResponse, "")
	decodedResponse = regexp.MustCompile("/index.php").ReplaceAllString(decodedResponse, "")
	decodedResponse = strings.ReplaceAll(decodedResponse, "https", "http")
	decodedResponse = strings.ReplaceAll(decodedResponse, "www.", "")
	decodedResponse = regexp.MustCompile("admin@example.com").ReplaceAllString(decodedResponse, "")
	decodedResponse = regexp.MustCompile("postmaster@example.com").ReplaceAllString(decodedResponse, "")

	// ######## vulnerability ######
	vulnerability = vulnerability + checkVuln(decodedResponse)
	
	if debug {
		fmt.Printf("vulnerability %s\n", vulnerability)
	}
	//###########

	// ######## write log ######
	// Open the file in append mode. If it doesn't exist, create it with permissions 0644
	file, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()

	// Write the decoded response to the file
	if _, err := file.WriteString(decodedResponse + "\n"); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: No puedo escribir en el fichero %v\n", err)
		os.Exit(1) // Exit the program with a non-zero status code
	}
	// #################


	// ############### title ########
	title := ""
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	titleMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(titleMatch) > 1 {
		title = titleMatch[1]
	}

	if title == "" {
		re = regexp.MustCompile(`(?i)<title>\s*(.*?)\s*</title>`)
		titleMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(titleMatch) > 1 {
			title = titleMatch[1]
		}
	}

	if title == "" {
		re = regexp.MustCompile(`(?i)<title(.*?)\n`)
		titleMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(titleMatch) > 1 {
			title = titleMatch[1]
		}
	}

	if title == "" {
		re = regexp.MustCompile(`(?i)Title:(.*?)\n`)
		titleMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(titleMatch) > 1 {
			title = titleMatch[1]
		}
	}

	if title == "" {
		re = regexp.MustCompile(`(?i)>(.*?)</title>`)
		titleMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(titleMatch) > 1 {
			title = titleMatch[1]
		}
	}

	if title == "" {
		re = regexp.MustCompile(`(?i)\n(.*?)\n</title>`)
		titleMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(titleMatch) > 1 {
			title = titleMatch[1]
		}
	}

	title = regexp.MustCompile(`>|\n|\t|\r`).ReplaceAllString(title, "")
	title = onlyAscii(title)
	if len(title) > 50 {
		title = title[:50]
	}

	if debug {
		fmt.Printf("title %s\n", title)
	}


	boaPattern := regexp.MustCompile(`(?i)Boa\/0.9`)
    idracPattern := regexp.MustCompile(`(?i)idrac`)
    accessDeniedPattern := regexp.MustCompile(`(?i)Acceso no autorizado`)
    hikvisionPattern := regexp.MustCompile(`(?i)Hikvision Digital`)
    hikvisionErrorPattern := regexp.MustCompile(`(?i)szErrorTip`)
    freeNASPattern := regexp.MustCompile(`(?i)FreeNAS`)
    ciscoUserPattern := regexp.MustCompile(`(?i)ciscouser`)
    pfsensePattern := regexp.MustCompile(`(?i)pfsense-logo`)
    sapPattern := regexp.MustCompile(`(?i)servletBridgeIframe`)
    bodyCamPattern := regexp.MustCompile(`(?i)content="Babelstar"`)
    dellIdracPattern := regexp.MustCompile(`(?i)login to iDRAC`)
    ciscoPattern := regexp.MustCompile(`(?i)Cisco`)
    peplinkPattern := regexp.MustCompile(`(?i)portal.peplink.com`)

    // Check for patterns and update title
    if boaPattern.MatchString(decodedHeaderResponse) {
        if title == "" {
            title = "Broadband device web server"
        }
    }
    if idracPattern.MatchString(decodedHeaderResponse) {
        title = "Dell iDRAC"
    }
    if accessDeniedPattern.MatchString(decodedHeaderResponse) {
        if title == "" {
            title = "Acceso no autorizado"
        }
    }
    if hikvisionPattern.MatchString(decodedHeaderResponse) || hikvisionErrorPattern.MatchString(decodedHeaderResponse) {
        title = "Hikvision Digital"
    }
    if freeNASPattern.MatchString(decodedHeaderResponse) {
        title = "FreeNAS"
    }
    if ciscoUserPattern.MatchString(decodedHeaderResponse) {
        title = "Cisco switch"
    }
    if pfsensePattern.MatchString(decodedHeaderResponse) {
        title = "Pfsense"
    }
    if sapPattern.MatchString(decodedHeaderResponse) {
        title = "SAP Business Objects"
    }
    if bodyCamPattern.MatchString(decodedHeaderResponse) {
        title = "Body Cam"
    }
    if dellIdracPattern.MatchString(decodedHeaderResponse) && !ciscoPattern.MatchString(decodedHeaderResponse) {
        title = "Dell iDRAC"
    }
    if peplinkPattern.MatchString(decodedHeaderResponse) {
        title = "Web Admin PepLink"
    }
	// ##############
	
	// ########## server ########
	server := ""
	re = regexp.MustCompile(`(?i)Server:(.*?)\n`)
	serverMatch := re.FindStringSubmatch(responseHeaders)
	if len(serverMatch) > 1 {
		server = serverMatch[1]
		if debug {
			fmt.Printf("server %s\n", server)
		}
	}

	ciscoLogoutPattern := regexp.MustCompile(`(?i)You have logged out of the Cisco Router|Cisco RV340 Configuration Utility`)
    ciscoUnifiedPattern := regexp.MustCompile(`(?i)Cisco Unified Communications`)
    ciscoASAPattern := regexp.MustCompile(`(?i)CSCOE`)
    ciscoEPNPattern := regexp.MustCompile(`(?i)Cisco EPN Manage`)
    oltPattern := regexp.MustCompile(`(?i)OLT Web Management Interface`)
    janusPattern := regexp.MustCompile(`(?i)Janus WebRTC Server`)
    huaweiPattern := regexp.MustCompile(`(?i)ui_huawei_fw_ver`)
    tpLinkPattern := regexp.MustCompile(`(?i)mbrico N 300Mbps WR840N`)
    dahuaPattern1 := regexp.MustCompile(`(?i)custom_logo/web_logo.png|baseProj/images/favicon.ico`)
    dahuaPattern2 := regexp.MustCompile(`(?i)webplugin.exe|BackUpBeginTimeChanged|playback_bottom_bar`)
    dahuaPattern3 := regexp.MustCompile(`(?i)WEB SERVICE`)
    hpPrinterPattern := regexp.MustCompile(`(?i)pgm-theatre-staging-div`)
    mdsOrbitPattern := regexp.MustCompile(`(?i)login/bower_components/requirejs/require.js`)
    atenPattern := regexp.MustCompile(`(?i)ATEN International Co`)
    juniperPattern := regexp.MustCompile(`(?i)Juniper Web Device Manager`)
    ciscoWebUIPattern := regexp.MustCompile(`(?i)by Cisco Systems, Inc`)
    routerOSPattern := regexp.MustCompile(`(?i)RouterOS router`)
	headerTitlePattern := regexp.MustCompile(`\<h1\>(.*?)\<\/h1\>`)

    if ciscoLogoutPattern.MatchString(decodedHeaderResponse) || ciscoUnifiedPattern.MatchString(decodedHeaderResponse) {
        server = "Cisco Router"
    } else if ciscoUnifiedPattern.MatchString(decodedHeaderResponse) {
        server = "Cisco Unified Communications"
    } else if ciscoASAPattern.MatchString(decodedHeaderResponse) {
        server = "ciscoASA"
    } else if ciscoEPNPattern.MatchString(decodedHeaderResponse) {
        server = "Cisco EPN Manage"
    } else if oltPattern.MatchString(decodedHeaderResponse) {
        server = "OLT Web Management Interface"
    } else if janusPattern.MatchString(decodedHeaderResponse) {
        server = "Janus WebRTC Server"
    } else if huaweiPattern.MatchString(decodedHeaderResponse) {
        server = "Huawei"
    } else if tpLinkPattern.MatchString(decodedHeaderResponse) {
        server = "TL-WR840N"
        title = "Router inalámbrico N 300Mbps WR840N"
    } else if (dahuaPattern1.MatchString(decodedHeaderResponse) || dahuaPattern2.MatchString(decodedHeaderResponse)) && dahuaPattern3.MatchString(decodedHeaderResponse) {
        server = "Dahua"
    } else if dahuaPattern2.MatchString(decodedHeaderResponse) {
        server = "Dahua"
    } else if hpPrinterPattern.MatchString(decodedHeaderResponse) {
        server = "printer HP laser"
    } else if mdsOrbitPattern.MatchString(decodedHeaderResponse) {
        server = "MDS Orbit Device Manager "
    } else if atenPattern.MatchString(decodedHeaderResponse) {
        server = "Super micro"
    } else if juniperPattern.MatchString(decodedHeaderResponse) {
        server = "Juniper Web Device Manager"
    } else if ciscoWebUIPattern.MatchString(decodedHeaderResponse) {
        server = "Cisco WebUI"
    } else if routerOSPattern.MatchString(decodedHeaderResponse) {
        matches := headerTitlePattern.FindStringSubmatch(decodedHeaderResponse)
        if len(matches) > 1 {
            server = matches[1]
        }
    }
	//###########
	

	// ############# powered by ##############
	re = regexp.MustCompile(`(?i)X-Powered-By:(.*?)\n`)
	poweredByMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(poweredByMatch) > 1 {
		pwdby := poweredByMatch[1]
		//fmt.Printf("pwdby %s\n", pwdby)
		poweredBy += pwdby
	}

	if strings.Contains(decodedHeaderResponse, "laravel_session") {
		poweredBy += "|Laravel"
	}

	re = regexp.MustCompile(`(?i)name="geo.placename" content="(.*?)"`)
	geoMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(geoMatch) > 1 {
		geo := geoMatch[1]
		if len(geo) > 1 {
			poweredBy += "| geo=" + geo
		}
	}

	re = regexp.MustCompile(`(?i)<meta name="generator" content="([^"]+)"`)
	generatorMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(generatorMatch) > 1 {
		generator := generatorMatch[1]

		re = regexp.MustCompile(`(?i)name="Version" content="(.*?)"`)
		versionMatch := re.FindStringSubmatch(decodedHeaderResponse)
		if len(versionMatch) > 1 {
			version := versionMatch[1]
			generator += " " + version
		}

		if len(generator) > 3 {
			poweredBy += "| Generator=" + generator
		}
	}

	re = regexp.MustCompile(`(?i)name="description" content="(.*?)"`)
	descriptionMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(descriptionMatch) > 1 {
		description := descriptionMatch[1]
		description = onlyAscii(description)
		if len(description) > 1 {
			poweredBy += "| description=" + description
		}
	} else {
		re = regexp.MustCompile(`(?i)X-Meta-Description:(.*?)\n`)
		descriptionMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(descriptionMatch) > 1 {
			description := descriptionMatch[1]
			description = onlyAscii(description)
			if len(description) > 1 {
				poweredBy += "| description=" + description
			}
		}
	}

	re = regexp.MustCompile(`(?i)name="author" content="(.*?)"`)
	authorMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(authorMatch) > 1 {
		author := authorMatch[1]
		author = onlyAscii(author)
		if len(author) > 1 {
			poweredBy += "| author=" + author
		}
	} else {
		re = regexp.MustCompile(`(?i)X-Meta-Author:(.*?)\n`)
		authorMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(authorMatch) > 1 {
			author := authorMatch[1]
			author = onlyAscii(author)
			if len(author) > 1 {
				poweredBy += "| author=" + author
			}
		}
	}

	re = regexp.MustCompile(`(?i)X-AspNet-Version:(.*?)\n`)
	langVersionMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(langVersionMatch) > 1 {
		langVersion := langVersionMatch[1]
		if len(langVersion) > 1 {
			poweredBy += "| langVersion=" + langVersion
		}
	}

	re = regexp.MustCompile(`(?i)Via:(.*?)\n`)
	proxyMatch := re.FindStringSubmatch(responseHeaders)
	if len(proxyMatch) > 1 {
		proxy := proxyMatch[1]
		if len(proxy) > 1 {
			poweredBy += "| proxy=" + proxy
		}
	}

	re = regexp.MustCompile(`(?i)WWW-Authenticate:(.*?)\n`)
	authenticateMatch := re.FindStringSubmatch(responseHeaders)
	if len(authenticateMatch) > 1 {
		authenticate := authenticateMatch[1]
		if len(authenticate) > 1 {
			poweredBy += "| proxy=" + authenticate
		}
	}

	re = regexp.MustCompile(`(?i)jquery.js\?ver=(.*?)"`)
	jqueryMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(jqueryMatch) > 1 {
		jquery := jqueryMatch[1]
		if debug {
			fmt.Printf("jquery %s\n", jquery)
		}
		poweredBy += "| JQuery " + jquery
	} else {
		re = regexp.MustCompile(`(?i)jquery/(\d+).(\d+).`)
		jqueryMatch = re.FindStringSubmatch(decodedHeaderResponse)
		if len(jqueryMatch) > 2 {
			jquery1 := jqueryMatch[1]
			jquery2 := jqueryMatch[2]
			if debug {
				fmt.Printf("jquery %s.%s\n", jquery1, jquery2)
			}
			poweredBy += "| JQuery " + jquery1 + "." + jquery2
		} else {
			re = regexp.MustCompile(`jquery-(\d+).(\d+).`)
			jqueryMatch = re.FindStringSubmatch(decodedHeaderResponse)
			if len(jqueryMatch) > 2 {
				jquery1 := jqueryMatch[1]
				jquery2 := jqueryMatch[2]
				if debug {
					fmt.Printf("jquery %s.%s\n", jquery1, jquery2)
				}
				poweredBy += "| JQuery " + jquery1 + "." + jquery2
			}
		}
	}

	re = regexp.MustCompile(`<h1[^>]*>(.*?)</h1>`)
	h1Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h1Match) > 1 {
		h1 := strings.ReplaceAll(h1Match[1], "\n", " ")
		h1 = strings.TrimSpace(h1)
		h1 = onlyAscii(h1)
		if len(h1) > 2 {
			poweredBy += "| H1=" + h1
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h2>`)
	h2Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h2Match) > 1 {
		h2 := strings.ReplaceAll(h2Match[1], "\n", " ")
		h2 = strings.TrimSpace(h2)
		h2 = onlyAscii(h2)
		if len(h2) > 2 {
			poweredBy += "| H2=" + h2
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h3>`)
	h3Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h3Match) > 1 {
		h3 := strings.ReplaceAll(h3Match[1], "\n", " ")
		h3 = strings.TrimSpace(h3)
		h3 = onlyAscii(h3)
		if len(h3) > 2 {
			poweredBy += "| H3=" + h3
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h4>`)
	h4Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h4Match) > 1 {
		h4 := strings.ReplaceAll(h4Match[1], "\n", " ")
		h4 = strings.TrimSpace(h4)
		h4 = onlyAscii(h4)
		if len(h4) > 2 {
			poweredBy += "| H4=" + h4
		}
	}

	if strings.Contains(decodedHeaderResponse, "GASOLINERA") {
        poweredBy += "|GASOLINERA"
    }
    if strings.Contains(decodedHeaderResponse, "<FORM") {
        poweredBy += "|formulario-login"
    }
    if strings.Contains(decodedHeaderResponse, "2008-2017 ZTE Corporation") {
        poweredBy += "|ZTE-2017"
    }
    if strings.Contains(decodedHeaderResponse, "2008-2018 ZTE Corporation") {
        poweredBy += "|ZTE-2018"
    }
    if regexp.MustCompile(`X-OWA-Version`).MatchString(decodedHeaderResponse) {
        poweredBy += "|owa"
    }
    if regexp.MustCompile(`AMLC COMPLIANCE`).MatchString(decodedHeaderResponse) {
        poweredBy += "|AMLC COMPLIANCE"
    }
    if regexp.MustCompile(`FortiGate`).MatchString(decodedHeaderResponse) {
        poweredBy += "|FortiGate"
        server = "FortiGate"
    }
    if regexp.MustCompile(`www.drupal.org`).MatchString(decodedHeaderResponse) {
        poweredBy += "|drupal"
    }
    if regexp.MustCompile(`laravel_session`).MatchString(decodedHeaderResponse) {
        poweredBy += "|laravel"
    }
    if regexp.MustCompile(`wp-content|wp-admin|wp-caption`).MatchString(decodedHeaderResponse) {
        poweredBy += "|wordpress"
    }
    if regexp.MustCompile(`Powered by Abrenet`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Powered by Abrenet"
    }
    if regexp.MustCompile(`csrfmiddlewaretoken`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Django"
    }
    if regexp.MustCompile(`IP Phone`).MatchString(decodedHeaderResponse) {
        poweredBy += "| IP Phone "
    }
    if regexp.MustCompile(`X-Amz-`).MatchString(decodedHeaderResponse) {
        poweredBy += "|amazon"
    }
    if regexp.MustCompile(`X-Planisys-`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Planisys"
    }
    if regexp.MustCompile(`phpmyadmin.css`).MatchString(decodedHeaderResponse) {
        poweredBy += "|phpmyadmin"
    }
    if regexp.MustCompile(`Set-Cookie: webvpn`).MatchString(decodedHeaderResponse) {
        poweredBy += "|ciscoASA"
    }
    if regexp.MustCompile(`WVRTM-127ACN`).MatchString(decodedHeaderResponse) {
        poweredBy += "|WVRTM-127ACN"
    }
    if regexp.MustCompile(`<div id="app">`).MatchString(decodedHeaderResponse) {
        poweredBy += "|javascriptFramework"
    }
    if regexp.MustCompile(`connect.sid|X-Powered-By: Express`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Express APP"
    }
    if regexp.MustCompile(`X-ORACLE-DMS`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Oracle Dynamic Monitoring"
    }
    if regexp.MustCompile(`www.enterprisedb.com"><img src="images\\/edblogo.png"`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Postgres web"
    }
    if regexp.MustCompile(`src="app\\//`).MatchString(decodedHeaderResponse) {
        poweredBy += "|AngularJS"
    }
    if regexp.MustCompile(`roundcube_sessid`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Roundcube"
    }
    if regexp.MustCompile(`MoodleSession|content="moodle"`).MatchString(decodedHeaderResponse) {
        poweredBy += "|moodle"
    }
    if regexp.MustCompile(`ftnt-fortinet-grid icon-xl`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Fortinet"
        server = "Fortinet"
    }
    if regexp.MustCompile(`theme-taiga.css`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Taiga"
    }
    if regexp.MustCompile(`X-Powered-By-Plesk`).MatchString(decodedHeaderResponse) {
        poweredBy += "|PleskWin"
    }
    if regexp.MustCompile(`Web Services`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Web Service"
        if title == "" {
            title = "Web Service"
        }
    }
    if regexp.MustCompile(`login__block__header`).MatchString(decodedHeaderResponse) {
        poweredBy += "|login"
        if title == "" {
            title = "Panel de logueo"
        }
    }


	if regexp.MustCompile(`(?i)Huawei Technologies Co`).MatchString(decodedHeaderResponse) {
		title, server = "optical network terminal (ONT)", "Huawei"
		productNameRegex := regexp.MustCompile(`(?i)var ProductName = "(.*?)"`)
		if matches := productNameRegex.FindStringSubmatch(decodedHeaderResponse); len(matches) > 1 {
			poweredBy += "|" + matches[1]
		}
	}

	if debug {
		fmt.Printf("poweredBy %s\n", poweredBy)
	}
	// ##################

	data := map[string]string{
		"title":         title,
		"server":        server,
		"status":        status,
		"redirect_url":  finalURLRedirect,
		"last_url":      lastURL,
		"newdomain":     newDomain,
		"poweredBy":     poweredBy,
		"vulnerability": vulnerability,
	}

	return data, nil
}


func (wh *WebHacks) Dirbuster(urlFile, extension string) {

	headers := wh.Headers
    debug := wh.Debug
    show404 := wh.Show404
    rhost := wh.Rhost
    rport := wh.Rport
    path := wh.Path
    error404 := wh.Error404
    threads := wh.Threads
    proto := wh.Proto
	ajax := wh.Ajax
	timeout := wh.Timeout
	MaxRedirect := wh.MaxRedirect

	if debug {
		fmt.Printf("Usando archivo: %s con extension (%s)\n", urlFile, extension)
		fmt.Printf("Configuracion: Hilos:%s  proto:%s  Ajax: %s error404:%s show404 %s timeout %s debug %s MaxRedirect %s \n\n", threads, proto, ajax, error404, show404,timeout, debug, MaxRedirect)
	}


	file, err := os.Open(urlFile)
	if err != nil {
		fmt.Printf("ERROR: Cannot open the file %s\n", urlFile)
		return
	}
	defer file.Close()

	var links []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urlLine := scanner.Text()

		//si hay que reemplazar extension
		if extension != "" {
			switch extension {
				case "php":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "php")
				case "html":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "html")
				case "asp":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "asp")
				case "aspx":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "aspx")
				case "htm":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "htm")
				case "jsp":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "jsp")
				case "pl":
					urlLine = strings.ReplaceAll(urlLine, "EXT", "pl")
				}
		}

		//Si  directorio adicionar "/"
		if strings.Contains(urlFile, "directorios") {
			urlLine += "/"
		}
		
		urlFinal := proto + "://" + rhost + ":" + rport + path + urlLine
		links = append(links, urlFinal)
	}


	var wg sync.WaitGroup
	wg.Add(threads)

	urlsChan := make(chan string, len(links))

	// Start a pool of worker goroutines.
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for urlLine := range urlsChan {				
				resp, err := wh.Dispatch(urlLine, "GET", headers)
				if err != nil {
					fmt.Printf("Failed to get URL %s: %v\n", urlLine, err)
					return // Or 'continue' if inside a loop.
				}
				defer resp.Body.Close()

				current_status := resp.StatusCode
				bodyBytes, _ := ioutil.ReadAll(resp.Body)
				bodyContent := string(bodyBytes)

				//check if return a custom 404 error but 200 OK
				if error404 != "" {
					if strings.Contains(bodyContent, error404) {
						current_status = 404
					} 
				}

				
				if (show404 && current_status == 404) || current_status != 404 {
					if  current_status == 200 {
						vuln := checkVuln(bodyContent)
					}
					
					if vuln != "" {
						fmt.Printf("%d \t %s (%s)\n", current_status, urlLine, vuln)
					} else {
						fmt.Printf("%d \t %s\n", current_status, urlLine)
					}

				}
			}
		}()
	}

	// Send URLs to the channel for processing by the workers.
	for _, urlLine := range links {
		urlsChan <- urlLine
	}
	close(urlsChan)

	wg.Wait() // Wait for all goroutines to finish.
}


func onlyAscii(text string) string {
	replacements := map[rune]rune{
		'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n',
		'Á': 'A', 'É': 'E', 'Í': 'I', 'Ó': 'O', 'Ú': 'U', 'Ñ': 'N',
	}
	var result strings.Builder
	for _, r := range text {
		if newR, ok := replacements[r]; ok {
			result.WriteRune(newR)
		} else if r <= unicode.MaxASCII && unicode.IsPrint(r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (wh *WebHacks) Backupbuster(urlFile string) {
	debug := wh.Debug
	show404 := wh.Show404
	rhost := wh.Rhost
	rport := wh.Rport
	path := wh.Path
	proto := wh.Proto
	threads := wh.Threads

	file, err := os.Open(urlFile)
	if err != nil {
		fmt.Printf("ERROR: Cannot open the file %s\n", urlFile)
		return
	}
	defer file.Close()

	var links []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urlLine := strings.TrimSpace(scanner.Text())
		links = append(links, urlLine)
	}

	var wg sync.WaitGroup
	urlsChan := make(chan string, 100) // Buffer can be adjusted

	// Function to process URLs
	processURL := func() {
		defer wg.Done()
		for urlLine := range urlsChan {
			backups := []string{
				"%s.inc", "%s~", "%s.bak", "%s.tmp", "%s.temp", "%s.old", 
				"%s.bakup", "%s-bak", "%s~", "%s.save", "%s.swp", "%s.old", 
				"Copy of %s", "%s (copia 1)", "%s::$DATA",
			}
			for _, backup := range backups {
				backupURL := fmt.Sprintf(backup, urlLine)
				backupURL = url.PathEscape(backupURL)
				finalURL := proto + "://" + rhost + ":" + rport + path + backupURL

				resp, err := http.Get(finalURL) // Simplified HTTP GET request
				if debug {
					if err != nil {
						fmt.Println("Error fetching URL:", finalURL)
						continue
					}
				}
				
				status := resp.StatusCode
				resp.Body.Close()

				if show404 || status != 404 {
					fmt.Printf("%d\t%s\n", status, finalURL)
				}
			}
		}
	}

	// Start a pool of goroutines based on the configured number of threads
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go processURL()
	}

	// Send URLs to the channel
	for _, link := range links {
		urlsChan <- link
	}
	close(urlsChan)

	wg.Wait() // Wait for all goroutines to finish
}


// getRedirect extracts a redirect URL from the decoded HTML response.
func getRedirect(decodedResponse string) string {
	// Define patterns to search for redirect URLs
	patterns := []string{
		`meta http-equiv="Refresh" content="0;URL=(.*?)"`,
		`meta http-equiv="Refresh" content="1;URL="(.*?)"`,
		`window.onload=function\(\) urlLine ="(.*?)"`,
		`meta http-equiv="Refresh" content="1;URL=(.*?)"`,
		`meta http-equiv="Refresh" content="0;URL=(.*?)"`,
		`window.location="(.*?)"`,
		`location.href="(.*?)"`,
		`window.location.href = "(.*?)"`,
		`window.location = "(.*?)"`,
		`top.location="(.*?)"`,
		`location.replace\("(.*?)"`,
		`jumpUrl = "(.*?)"`,
		`top.document.location.href = "(.*?)"`,
		`http-equiv="refresh" content="0.1;urlLine=(.*?)"`,
		`parent.location="(.*?)"`,
		`redirect_suffix = "(.*?)"`,
	}

	// Iterate over patterns to find a match
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(decodedResponse)
		if len(matches) > 1 {
			redirectURL := matches[1]
			// Check if the redirect URL is incomplete, if so, ignore it
			if redirectURL == "https:" || redirectURL == "http:" {
				continue
			}
			// Check for specific conditions to ignore the redirect URL
			if re.MatchString(`webfig|\.\.\//`) {
				// Detected patterns that should be ignored
				continue
			}
			// Remove double quotes from the redirect URL
			redirectURL = regexp.MustCompile(`"`).ReplaceAllString(redirectURL, "")
			return redirectURL
		}
	}

	// Return empty string if no redirect URL is found
	return ""
}


func (wh *WebHacks) Dispatch(urlLine string, method string, headers http.Header) (*http.Response, error) {
    // Prepare the request
    req, err := http.NewRequest(method, urlLine, nil)
    if err != nil {
        return nil, err
    }

    // Add headers
    for key, values := range headers {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }

    // Send the request
    resp, err := wh.Client.Do(req)
    if err != nil {
        return nil, err
    }

    return resp, nil
}


func checkVuln(decodedContent string) string {
	vuln := ""

	if regexp.MustCompile(`(?m)Lorem ipsum`).MatchString(decodedContent) {
		vuln = "contenidoPrueba"
	}

	if regexp.MustCompile(`(?i)DEBUG = True|app/controllers|SERVER_ADDR|REMOTE_ADDR|DOCUMENT_ROOT/|TimeoutException|vendor/laravel/framework/src/Illuminate`).MatchString(decodedContent) {
		vuln = "debugHabilitado"
	}

	if regexp.MustCompile(`(?i) RAT |C99Shell|b374k| r57 | wso | pouya | Kacak | jsp file browser |vonloesch.de|Upload your file|Cannot execute a blank command|fileupload in`).MatchString(decodedContent) {
		vuln = "backdoor"
	}

	if regexp.MustCompile(`(?i)db=information_schema`).MatchString(decodedContent) {
		vuln = "OpenPhpMyAdmin"
	}

	if regexp.MustCompile(`(?i)var user = "admin";`).MatchString(decodedContent) {
		vuln = "OpenMikrotik"
	}

	if regexp.MustCompile(`(?i)undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information|E_WARNING`).MatchString(decodedContent) {
		vuln = "MensajeError"
	}

	if regexp.MustCompile(`(?i)Access denied for`).MatchString(decodedContent) {
		vuln = "ExposicionUsuarios"
	}

	if regexp.MustCompile(`(?i)Directory of|Index of|Parent directory`).MatchString(decodedContent) {
		vuln = "ListadoDirectorios"
	}

	if regexp.MustCompile(`(?i)HTTP_X_FORWARDED_HOST|HTTP_X_FORWARDED_SERVER|phpinfo\(\)`).MatchString(decodedContent) {
		vuln = "divulgacionInformacion"
	}

	if regexp.MustCompile(`(?i)Client IP:`).MatchString(decodedContent) {
		vuln = "IPinterna"
	}

	if regexp.MustCompile(`(?i)r=usuario/create`).MatchString(decodedContent) {
		vuln = "ExposicionUsuarios"
	}

	if regexp.MustCompile(`(?m)/user/register|registerform|member-registration`).MatchString(decodedContent) {
		vuln = "RegistroHabilitado"
	}

	if decodedContent == "" {
		vuln = "ArchivoVacio"
	}

	return vuln
}

func headerToString(header http.Header) string {
    var headerStr strings.Builder

    for key, values := range header {
        headerStr.WriteString(key)
        headerStr.WriteString(": ")
        headerStr.WriteString(strings.Join(values, ", "))
        headerStr.WriteString("\n")
    }

    return headerStr.String()
}