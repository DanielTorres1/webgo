package webhacks
// TODO configApache not checking 302 redirect
import (
	"context"
	"crypto/md5"
	"bytes"
	"path"
	"log"
	"encoding/hex"
	"golang.org/x/net/html"
	"crypto/tls"
	"compress/gzip"
	"bufio"
	"math/rand"
	"strconv"
	"unicode"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"regexp"
	"time"
	"io"
	"io/ioutil"
	"strings"
	"net/http/cookiejar"
	"github.com/fatih/color"
	"golang.org/x/net/proxy"
)

var debug bool


type Client struct {
    *http.Client
    LastURL string
}

type Result struct {
	Status        int
	URL           string
	Vulnerability string
	ContentLength int
}	

type WebHacks struct {
	Debug       bool
	Filter       bool
	Show404		bool
	Rhost       string
	Rport       string
	Path        string
	MaxRedirect int
	Timeout     int
	Error404    string
	Threads     int
	Proto       string
	Cookie      string
	Ajax        bool
	Client      *Client
	Headers     http.Header
}

func NewWebHacks(timeoutInSeconds, MaxRedirect int) *WebHacks {
    // Initialize the random number generator
    rand.Seed(time.Now().UnixNano())

    userAgents := []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    }

    selectedUserAgent := userAgents[rand.Intn(len(userAgents))]

    // Create the transport based on whether we're running under proxychains
    var httpTransport *http.Transport

    // Check if running under proxychains by looking for the LD_PRELOAD environment variable
    if ldPreload := os.Getenv("LD_PRELOAD"); strings.Contains(ldPreload, "proxychains") {
        // Create a SOCKS5 dialer for proxychains
        dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
        if err != nil {
            log.Printf("Warning: Failed to create SOCKS5 dialer: %v", err)
            // Fall back to direct connection if SOCKS5 setup fails
            httpTransport = &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                    MinVersion:         tls.VersionTLS10,
                },
                ForceAttemptHTTP2: false,
            }
        } else {
            // Use SOCKS5 proxy
            httpTransport = &http.Transport{
                DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                    return dialer.Dial(network, addr)
                },
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                    MinVersion:         tls.VersionTLS10,
                },
                ForceAttemptHTTP2: false,
            }
        }
    } else {
        // Direct connection when not using proxychains
        //proxyURL, _ := url.Parse("http://127.0.0.1:8081") // burpsuite
        httpTransport = &http.Transport{
            //Proxy: http.ProxyURL(proxyURL), //burpsuite
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
                MinVersion: tls.VersionTLS10,
            },
            ForceAttemptHTTP2: false,
        }
    }

    // Create a cookie jar to handle cookies automatically
    cookieJar, _ := cookiejar.New(nil)

    // Create and initialize our custom Client - FIXED THIS PART
    client := &Client{
        Client: &http.Client{},  // Initialize the embedded http.Client
    }
    
    // Initialize the http.Client fields
    client.Transport = httpTransport
    client.Timeout = time.Duration(timeoutInSeconds) * time.Second
    client.Jar = cookieJar
    client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
        client.LastURL = req.URL.String()
        if len(via) >= MaxRedirect {
            return http.ErrUseLastResponse
        }
        return nil
    }

    wh := &WebHacks{
        Client:      client,
        Headers:     http.Header{},
        Timeout:     timeoutInSeconds,
        MaxRedirect: MaxRedirect,
    }

    // Configure headers
    wh.Headers.Set("User-Agent", selectedUserAgent)
    wh.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    wh.Headers.Set("Accept-Language", "en-US,en;q=0.5")
    wh.Headers.Set("Upgrade-Insecure-Requests", "1")
    wh.Headers.Set("Sec-Fetch-Dest", "document")
    wh.Headers.Set("Sec-Fetch-Mode", "navigate")
    wh.Headers.Set("Sec-Fetch-Site", "none")

    if wh.Ajax {
        wh.Headers.Set("X-Requested-With", "XmlHttpRequest")
    }

    return wh
}


func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func ObtenerHashMD5(cadena string) string {
	hash := md5.Sum([]byte(cadena))
	return hex.EncodeToString(hash[:])
}



// convertHash takes a map and converts it to a URL-encoded query string
func ConvertHash(hashData map[string]string) string {
	var postData strings.Builder

	for key, value := range hashData {
		postData.WriteString(url.QueryEscape(key))
		postData.WriteString("=")
		postData.WriteString(url.QueryEscape(value))
		postData.WriteString("&")
	}

	// Convert the Builder to a string and remove the trailing '&' character if necessary
	result := postData.String()
	if len(result) > 0 {
		result = result[:len(result)-1]
	}

	return result
}

func (wh *WebHacks) Dispatch(urlLine string, method string, postData string, headers http.Header) (*http.Response, string, error) {
    // Prepare the request
    var req *http.Request
    var err error

    if method == "POST" {
        req, err = http.NewRequest(method, urlLine, strings.NewReader(postData))
        if err != nil {
            return nil, "", err
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    } else {
        req, err = http.NewRequest(method, urlLine, nil)
        if err != nil {
            return nil, "", err
        }
    }

    // Add default headers from WebHacks
    for key, values := range wh.Headers {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }

    // Add custom headers passed to the method
    for key, values := range headers {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }

    // Send the request
    resp, err := wh.Client.Do(req)
    if err != nil {
        return nil, "", err
    }

    // Update LastURL with the final URL after potential redirects
    finalURL := resp.Request.URL.String()
    wh.Client.LastURL = finalURL
    
    return resp, finalURL, nil
}

	

// getRedirect extracts a redirect URL from the decoded HTML response.
func getRedirect(decodedResponse string) string {
	// Define patterns to search for redirect URLs
	//fmt.Printf("decodedResponse (%s)\n", decodedResponse)
	
	patterns := []string{
		`(?i)content=["']0; URL=(.*?)['"]`,
		`(?i)content=["']0; ?URL= ?['"](.*?)['"]`,
		`(?i)content=["']1; ?URL= ?['"](.*?)['"]`,
		`(?i)content=["']0.1;urlLine=['"](.*?)['"]`,
		`(?i)content=["']0; ?URL=(.*?)["']`,
		`(?i)content=["']1; ?URL=(.*?)["']`,
		`(?i)window.onload=function\(\) urlLine ?= ?['"](.*?)['"]`,
		`(?i)window.location ?= ?['"](.*?)['"]`,
		`(?i)location.href ?= ?['"](.*?)['"]`,
		`(?i)window.location.href ?= ?['"](.*?)['"]`,
		`(?i)window.location ?= ?['"](.*?)['"]`,
		`(?i)top.location ?= ?['"](.*?)['"]`,
		`(?i)location.replace\(['"](.*?)['"]\)`,
		`(?i)location ?= ?['"](.*?)['"]`,
		`(?i)jumpUrl ?= ?['"](.*?)['"]`,
		`(?i)top.document.location.href ?= ?['"](.*?)['"]`,
		`(?i)parent.location ?= ?['"](.*?)['"]`,
		`(?i)redirect_suffix ?= ?['"](.*?)['"]`,
		`(?i)The document has moved ?<a href=['"](.*?)['"]`,
		`(?i)Location: (.*?)\r?\n`,
		`(?i)window\.open\(['"](.*?)['"]`,
		
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

			if redirectURL == "login.html" || redirectURL == "../" || redirectURL == "/" || redirectURL == "/public/launchSidebar.jsp" || redirectURL == "/webfig/" || strings.Contains(redirectURL, "Valida") || strings.Contains(redirectURL, "error") || strings.Contains(redirectURL, "microsoftonline") {
				redirectURL = ""
			}
			return redirectURL
		}
	}

	return ""
}


func checkVuln(decodedContent string,title string) string {
	vuln := ""

	//fmt.Printf("decodedContent %s\n", decodedContent)
	// if regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.16\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`).MatchString(decodedContent) {
	// 	vuln = "IPinterna"
	// }
	

	if regexp.MustCompile(`(?m)Lorem ipsum`).MatchString(decodedContent) {
		vuln = "contenidoPrueba"
	}

	if regexp.MustCompile(`(?i)DEBUG = True|app/controllers|TimeoutException|vendor/laravel/framework/src/Illuminate|phpdebugbar`).MatchString(decodedContent) {
		vuln = "debugHabilitado"
	}

	if regexp.MustCompile(`(?i) RAT |C99Shell|b374k| r57 | wso | pouya | Kacak | jsp file browser |vonloesch.de|Upload your file|Cannot execute a blank command|fileupload in`).MatchString(decodedContent) {
		vuln = "backdoor"
	}

	if regexp.MustCompile(`(?i)db=information_schema`).MatchString(decodedContent) {
		vuln = "OpenPhpMyAdmin"
	}

	
	if regexp.MustCompile(`(?i)var user = "admin";`).MatchString(decodedContent) {

		if !strings.Contains(decodedContent, `INCLUDE_USER_RESTRICTION`) { //negaticvo
			vuln = "OpenMikrotik"
		}
		
	}

	if regexp.MustCompile(`(?i)(undefined function|already sent by|Undefined offset|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Exception in thread|Exception information)`).MatchString(decodedContent) {
		vuln = "MensajeError"
	}

	if regexp.MustCompile(`E_WARNING`).MatchString(decodedContent) { //mayuscula
		vuln = "MensajeError"
	}

	if regexp.MustCompile(`(?i)(Access denied for|r=usuario|r=user)`).MatchString(decodedContent) {
		vuln = "ExposicionUsuarios"
	}
	

	if regexp.MustCompile(`(?i)(?:^|[^a-z])(?:index of|directory of|Index of|Parent directory)(?:[^a-z]|$)`).MatchString(decodedContent) {
		
		if regexp.MustCompile(`(?i)(?:^|[^a-z])(?:moodle)(?:[^a-z]|$)`).MatchString(decodedContent) {
			vuln = "ListadoDirectorios~moodle"
		}else{
			vuln = "ListadoDirectorios"
		}

	}

	

	if regexp.MustCompile(`(?i)HTTP_X_FORWARDED_HOST|HTTP_X_FORWARDED_SERVER\(\)`).MatchString(decodedContent) {
		vuln = "divulgacionInformacion"
	}

	if regexp.MustCompile(`(?i)/var/www/html|/usr/local/apache2/htdocs/|C:/xampp/htdocs/|C:/wamp64/www/|/var/www/nginx-default|/usr/share/nginx/html`).MatchString(decodedContent) &&
		!regexp.MustCompile(`(?i)Default Page`).MatchString(decodedContent) &&
		!regexp.MustCompile(`(?i)Server Manager`).MatchString(decodedContent) &&
		!regexp.MustCompile(`(?i)TEST PAGE`).MatchString(decodedContent) {
		vuln = "FPD"
	}

	decodedContentLower := strings.ToLower(decodedContent)

	patterns := `(?i)("password":\$|password": password|"password":{"type|SLACK_CLIENT_SECRET|password': password|password="+pass|password='+pass|"password":"password|"password=" \+ encodeuricomponent|"password":"http|"password":"Contrase|"password":{required|"passwords":{"password|"password":{"enforced|"password":{"enabled|case "password":|tac@cisco.com|password=pass|password=trial|'password':{'enforced|'password':{'enabled|'passwords':{'password|'password':{required|'password':\$|'password':'password|'password=' \+ encodeuricomponent|'password':'clave|'password':'http|"password":{"laravelValidation")|'&password=' + passHASH`
	excludedTitles := `(?i)GPON|Cisco switch|Huawei|Terminal|TP-LINK|Zentyal Webmail|Serv-U|dlink`
	mustMatchPattern := `(?i)"password":|'password':|\&password=|DB_PASSWORD|MAIL_PASSWORD|AUTH_KEY|client_secret`

	contentMatch, _ := regexp.MatchString(patterns, decodedContentLower)
	titleMatch, _ := regexp.MatchString(excludedTitles, title)
	mustMatch, _ := regexp.MatchString(mustMatchPattern, decodedContentLower)

	if !contentMatch && !titleMatch && mustMatch {
		vuln = "PasswordDetected"
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

func (wh *WebHacks) PasswordTest(options map[string]string) {
	module := options["module"]
	user := options["user"]
	password := options["password"]
	passwordsFile := options["passwords_file"]

	rhost := wh.Rhost
	rport := wh.Rport
	proto := wh.Proto
	debug := wh.Debug
	webpath := wh.Path
	headers := wh.Headers

	if debug {
		color.Set(color.FgBlue, color.Bold)
		fmt.Printf("######### Testendo: %s ##################### \n\n", module)
		color.Unset()
	}

	
	var url string
	if rport == "80" || rport == "443" {
		url = fmt.Sprintf("%s://%s%s", proto, rhost, webpath)
	} else {
		url = fmt.Sprintf("%s://%s:%s%s", proto, rhost, rport, webpath)
	}

	if debug {
	
		fmt.Printf("user: %s \n", user)
		fmt.Printf("password: %s \n", password)
		fmt.Printf("passwordsFile: %s \n", passwordsFile)
		fmt.Printf("path: %s \n", webpath)
		fmt.Printf("url: %s \n", url)
	}

	

	passwordsList := []string{}
	if passwordsFile != "" {
		file, err := os.Open(passwordsFile)
		if err != nil {
			fmt.Printf("ERROR: Cannot open the file %s\n", passwordsFile)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			passwordsList = append(passwordsList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("ERROR: Reading file %s\n", passwordsFile)
		}
	} else {
		passwordsList = append(passwordsList, password)
	}

	///////////
	if module == "HUAWEI-AR" {
		headers.Set("Origin", url)
		headers.Set("Referer", url)
		headers.Set("Upgrade-Insecure-Requests", "1")

		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				"UserName":     user,
				"Password":     password,
				"frashnum":     "",
				"LanguageType": "0",
			}

			postData := ConvertHash(hashData)
			resp, _, err := wh.Dispatch(url, "POST", postData, headers)
			
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			status := resp.Status
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if !strings.Contains(string(body), "ErrorMsg") {
				fmt.Printf("Password encontrado: [HUAWEI-AR] %s Usuario:%s Password:%s \n", url, user, password)
				break
			}
		}
	} //HUAWI-AR


	if module == "ZTE-ONT-4G" {
		headers.Set("Origin", url)
		headers.Set("Referer", url)
		headers.Set("Upgrade-Insecure-Requests", "1")

		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			resp, _, err := wh.Dispatch(url, "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			tokenRegex := regexp.MustCompile(`getObj\("Frm_Logintoken"\).value = "(.*?)"`)
			matches := tokenRegex.FindStringSubmatch(string(body))
			if len(matches) < 2 {
				fmt.Printf("Failed to find Frm_Logintoken in response")
			}
			Frm_Logintoken := matches[1]

			hashData := map[string]string{
				"Username":      user,
				"Password":      password,
				"frashnum":      "",
				"action":        "login",
				"Frm_Logintoken": Frm_Logintoken,
			}

			postData := ConvertHash(hashData)
			resp, _, err = wh.Dispatch(url, "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			//status := resp.Status
			lastURL := resp.Request.URL.String()
			fmt.Printf("[+] user:%s password:%s lastURL:%s\n", user, password, lastURL)

			if strings.Contains(lastURL, "start.ghtml") {
				resp, _, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlan_basic_t1.gch", "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
				}

				decodedResponse := string(body)
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2e", ".")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x20", " ")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x5f", "_")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2d", "-")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x22", "\"")

				keyPassphraseRegex := regexp.MustCompile(`Transfer_meaning\('KeyPassphrase','(\w+)'\);`)
				keyPassphraseMatches := keyPassphraseRegex.FindStringSubmatch(decodedResponse)
				var KeyPassphrase string
				if len(keyPassphraseMatches) >= 2 {
					KeyPassphrase = keyPassphraseMatches[1]
				}

				essidRegex := regexp.MustCompile(`Transfer_meaning\('ESSID','(.*?)'\)`)
				essidMatches := essidRegex.FindAllStringSubmatch(decodedResponse, -1)
				var ESSID string
				if len(essidMatches) > 0 {
					ESSID = essidMatches[len(essidMatches)-1][1]
				}

				fmt.Printf("Password encontrado: [ZTE ZTE-ONT-4G] %s Usuario:%s Password:%s ESSID %s KeyPassphrase %s \n", url, user, password, ESSID, KeyPassphrase)
				break
			}
		}
	}//ZTE-ONT-4G

	if module == "ZTE-F6XX-2017" {
		headers.Set("Referer", url)
		headers.Set("Upgrade-Insecure-Requests", "1")
		headers.Set("Cookie", "_TESTCOOKIESUPPORT=1")
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			resp, _, err := wh.Dispatch(url, "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			tokenRegex := regexp.MustCompile(`getObj\("Frm_Logintoken"\).value = "(.*?)"`)
			matches := tokenRegex.FindStringSubmatch(string(body))
			if len(matches) < 2 {
				fmt.Printf("Failed to find Frm_Logintoken in response")
			}
			Frm_Logintoken := matches[1]

			hashData := map[string]string{
				"frashnum":      "",
				"action":        "login",
				"Frm_Logintoken": Frm_Logintoken,
				"Username":      user,
				"Password":      password,
			}

			postData := ConvertHash(hashData)
			resp, _, err = wh.Dispatch(url, "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			//status := resp.Status
			lastURL := resp.Request.URL.String()
			fmt.Printf("[+] user:%s password:%s lastURL:%s\n", user, password, lastURL)

			if strings.Contains(lastURL, "start.ghtml") {
				cookieValue := resp.Header.Get("Set-Cookie")
				if cookieValue != "" {
					headers.Set("Cookie", fmt.Sprintf("_TESTCOOKIESUPPORT=1; %s", cookieValue))
				}

				headers.Set("Origin", url)

				resp, _, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch", "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
				}

				decodedResponse := string(body)
				decodedResponse = strings.ReplaceAll(decodedResponse, "Transfer_meaning('ESSID',''", "")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2e", ".")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x20", " ")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x5f", "_")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2d", "-")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x22", "\"")

				essidRegex := regexp.MustCompile(`Transfer_meaning\('ESSID','(.*?)'\)`)
				essidMatches := essidRegex.FindStringSubmatch(decodedResponse)
				var ESSID string
				if len(essidMatches) >= 2 {
					ESSID = essidMatches[1]
				}

				resp, _, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch", "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
				}

				decodedResponse = string(body)
				decodedResponse = strings.ReplaceAll(decodedResponse, "Transfer_meaning('KeyPassphrase',''", "")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2e", ".")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x20", " ")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x5f", "_")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2d", "-")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x22", "\"")

				keyPassphraseRegex := regexp.MustCompile(`Transfer_meaning\('KeyPassphrase','(.*?)'\)`)
				keyPassphraseMatches := keyPassphraseRegex.FindStringSubmatch(decodedResponse)
				var KeyPassphrase string
				if len(keyPassphraseMatches) >= 2 {
					KeyPassphrase = keyPassphraseMatches[1]
				}

				fmt.Printf("Password encontrado: [ZTE F6XX] %s Usuario:%s Password:%s ESSID %s KeyPassphrase %s \n", url, user, password, ESSID, KeyPassphrase)
				break
			}
		}
	}//ZTE-F6XX-2017


	if module == "ZTE-F6XX-2018" {
		headers.Set("Referer", url)
		headers.Set("Upgrade-Insecure-Requests", "1")
		headers.Set("Cookie", "_TESTCOOKIESUPPORT=1")
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			resp, _, err := wh.Dispatch(url, "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			tokenRegex := regexp.MustCompile(`getObj\("Frm_Logintoken"\).value = "(.*?)"`)
			matches := tokenRegex.FindStringSubmatch(string(body))
			if len(matches) < 2 {
				fmt.Printf("Failed to find Frm_Logintoken in response")
			}
			Frm_Logintoken := matches[1]

			randomNumber := rand.Intn(89999999-10000000) + 10000000
			hashedPassword := ObtenerHashMD5(password + strconv.Itoa(randomNumber))

			hashData := map[string]string{
				"frashnum":      "",
				"action":        "login",
				"Frm_Logintoken": Frm_Logintoken,
				"UserRandomNum": strconv.Itoa(randomNumber),
				"Username":      user,
				"Password":      hashedPassword,
			}

			postData := ConvertHash(hashData)
			resp, _, err = wh.Dispatch(url, "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			//status := resp.Status
			lastURL := resp.Request.URL.String()
			fmt.Printf("[+] user:%s password:%s lastURL:%s\n", user, password, lastURL)

			if strings.Contains(lastURL, "start.ghtml") {
				cookieValue := resp.Header.Get("Set-Cookie")
				if cookieValue != "" {
					headers.Set("Cookie", fmt.Sprintf("_TESTCOOKIESUPPORT=1; %s", cookieValue))
				}

				headers.Set("Origin", url)

				resp, _, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch", "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
				}

				decodedResponse := string(body)
				decodedResponse = strings.ReplaceAll(decodedResponse, "Transfer_meaning('ESSID',''", "")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2e", ".")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x20", " ")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x5f", "_")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2d", "-")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x22", "\"")

				essidRegex := regexp.MustCompile(`Transfer_meaning\('ESSID','(.*?)'\)`)
				essidMatches := essidRegex.FindStringSubmatch(decodedResponse)
				var ESSID string
				if len(essidMatches) >= 2 {
					ESSID = essidMatches[1]
				}

				resp, _, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch", "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
				}

				decodedResponse = string(body)
				decodedResponse = strings.ReplaceAll(decodedResponse, "Transfer_meaning('KeyPassphrase',''", "")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2e", ".")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x20", " ")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x5f", "_")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x2d", "-")
				decodedResponse = strings.ReplaceAll(decodedResponse, "\\x22", "\"")

				keyPassphraseRegex := regexp.MustCompile(`Transfer_meaning\('KeyPassphrase','(.*?)'\)`)
				keyPassphraseMatches := keyPassphraseRegex.FindStringSubmatch(decodedResponse)
				var KeyPassphrase string
				if len(keyPassphraseMatches) >= 2 {
					KeyPassphrase = keyPassphraseMatches[1]
				}

				fmt.Printf("Password encontrado: [ZTE F6XX] %s Usuario:%s Password:%s ESSID %s KeyPassphrase %s \n", url, user, password, ESSID, KeyPassphrase)
				break
			}
		}
	}//ZTE-F6XX-2018

	if module == "ZKSoftware" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				"username": user,
				"userpwd":  password,
			}

			postData := ConvertHash(hashData)

			resp, _, err := wh.Dispatch(url+"csl/check", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			status := resp.Status
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if status == "200 OK" {
				decodedResponse := string(body)
				if strings.Contains(strings.ToLower(decodedResponse), "department") ||
					strings.Contains(strings.ToLower(decodedResponse), "departamento") ||
					strings.Contains(strings.ToLower(decodedResponse), "frame") ||
					strings.Contains(strings.ToLower(decodedResponse), "menu") ||
					strings.Contains(strings.ToLower(decodedResponse), "self.location.href='/") {
					fmt.Printf("Password encontrado: [ZKSoftware] %s Usuario:%s Password:%s\n", url, user, password)
					break
				}
			}
		}
	}//ZKSOFTWARE

	if module == "zabbix" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				"name": user,
				"password":  password,
				"autologin":  "1",
				"enter": "Sign+in",
			}


			postData := ConvertHash(hashData)

			resp, _, err := wh.Dispatch(url+"index.php", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
			}

			decodedResponse := string(body)
			status := resp.Status
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if strings.Contains(strings.ToLower(decodedResponse), "dashboard")  {
				fmt.Printf("Password encontrado: [zabbix] %s Usuario:%s Password:%s\n", url, user, password)
				break
			}
		}
	}//zabbix

	if module == "AMLC" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				"usu_login":       user,
				"usu_password":    password,
				"aj001sr001qwerty": "3730329decdf984212942a59de68a819",
			}

			postData := ConvertHash(hashData)

			headers.Set("Content-Type", "application/x-www-form-urlencoded")
			headers.Set("Cookie", "aj001sr001qwertycks=3730329decdf984212942a59de68a819")

			resp, _, err := wh.Dispatch(url+"login", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			status := resp.Status
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if status == "303 See Other" {
				fmt.Printf("Password encontrado: [AMLC] %s Usuario:%s Password:%s\n", url, user, password)
				break
			}
		}
	}//AMLC

	if module == "owa" {
		_, _, err := wh.Dispatch(url , "GET", "", headers)
		if err != nil {
			fmt.Printf("Request failed: %v", err)
		}

		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			hashData := map[string]string{
				"destination": url,
				"passwordText":   "",
				"isUtf8":"1",
				"flags": "4",
				"forcedownlevel": "0",
				"username": user,
				"password": password,
			}


			postData := ConvertHash(hashData)

			headers.Set("Sec-Fetch-User", "?1")
			headers.Set("Origin", url)
			headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			resp, _, err := wh.Dispatch(url + "auth.owa", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			//status := resp.Status
			decodedResponse := string(body)

			if strings.Contains(strings.ToLower(decodedResponse), "error en el servicio de red") ||
				strings.Contains(strings.ToLower(decodedResponse), "network service error") {
				fmt.Println("El servidor OWA esta bloqueando nuestra IP :(")
				break
			}

			lastURL := resp.Request.URL.String()
			fmt.Printf("[+] user:%s password:%s lastURL:%s\n", user, password, lastURL)

			if !strings.Contains(lastURL, "logon.aspx") {
				fmt.Printf("Password encontrado: [owa] %s (Usuario:%s Password:%s)\n", url, user, password)
				break
			}
		}
	}//OWA

	if module == "zimbra" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			resp, _, err := wh.Dispatch(url, "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse := string(body)
			loginCSRFRegex := regexp.MustCompile(`name="login_csrf" value="(.*?)"`)
			matches := loginCSRFRegex.FindStringSubmatch(decodedResponse)
			if len(matches) < 2 {
				fmt.Println("Failed to find login_csrf in response")
				continue
			}
			loginCSRF := matches[1]

			hashData := map[string]string{
				"loginOp":     "login",
				"client":      "preferred",
				"login_csrf":  loginCSRF,
				"username":    user,
				"password":    password,
			}

			postData := ConvertHash(hashData)

			headers.Set("Content-Type", "application/x-www-form-urlencoded")
			headers.Set("Cookie", "ZM_TEST=true; ZM_LOGIN_CSRF="+loginCSRF)
			headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

			resp, _, err = wh.Dispatch(url, "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			status := resp.Status
			decodedResponse = string(body)

			if strings.Contains(strings.ToLower(decodedResponse), "error en el servicio de red") ||
				strings.Contains(strings.ToLower(decodedResponse), "network service error") {
				fmt.Println("El servidor Zimbra esta bloqueando nuestra IP :(")
				break
			}

			fmt.Printf("[+] user:%s password:%s status:%s \n", user, password, status)

			if status == "302 Found" {
				fmt.Printf("Password encontrado: [zimbra] %s (Usuario:%s Password:%s)\n", url, user, password)
				break
			}
		}
	}//zimbra

	if module == "pentaho" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			headers.Set("Accept", "text/plain, */*; q=0.01")
			headers.Set("X-Requested-With", "XMLHttpRequest")

			hashData := map[string]string{
				"locale":     "en_US",
				"j_username": user,
				"j_password": password,
			}

			postData := ConvertHash(hashData)

			resp, _, err := wh.Dispatch(url+"pentaho/j_spring_security_check", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			status := resp.Status
			responseHeaders := resp.Header.Get("Location")
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if strings.Contains(strings.ToLower(responseHeaders), "home") {
				fmt.Printf("Password encontrado: [Pentaho] %s (Usuario:%s Password:%s)\n", url, user, password)
				break
			}
		}
	}//pentaho

	if module == "PRTG" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				"username":  user,
				"password":  password,
				"guiselect": "radio",
			}

			postData := ConvertHash(hashData)

			resp, _, err := wh.Dispatch(url+"/public/checklogin.htm", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			status := resp.Status
			responseHeaders := resp.Header.Get("Location")
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if !strings.Contains(strings.ToLower(responseHeaders), "error") && status != "500 read timeout" {
				fmt.Printf("Password encontrado: [PRTG] %s \nUsuario:%s Password:%s\n", url, user, password)
				break
			}
		}
	}//PRTG

	if module == "phpmyadmin" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			resp, _, err := wh.Dispatch(url, "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse := string(body)
			if strings.Contains(strings.ToLower(decodedResponse), "navigation.php") || strings.Contains(strings.ToLower(decodedResponse), "logout.php") || strings.Contains(strings.ToLower(decodedResponse), "information_schema") {
				fmt.Printf("[phpmyadmin] %s (Sistema sin password)\n", url)
				break
			}

			tokenRegex := regexp.MustCompile(`name="token" value="(.*?)"`)
			matches := tokenRegex.FindStringSubmatch(decodedResponse)
			var token string
			if len(matches) >= 2 {
				token = matches[1]
			}

			if strings.Contains(strings.ToLower(decodedResponse), "respondiendo") ||
				strings.Contains(strings.ToLower(decodedResponse), "not responding") ||
				strings.Contains(strings.ToLower(decodedResponse), "Please check your PHP configuration") ||
				strings.Contains(strings.ToLower(decodedResponse), "please check PHP Configuration") ||
				strings.Contains(strings.ToLower(decodedResponse), "is not readable") ||
				strings.Contains(strings.ToLower(decodedResponse), "<h1>error</h1>") {
				fmt.Println("ERROR: El servidor no está respondiendo")
				continue
			}

			hashData := map[string]string{
				"pma_username": user,
				"pma_password": password,
				"token":        token,
				"target":       "index.php",
				"server":       "1",
			}

			postData := ConvertHash(hashData)
			headers.Set("Content-Type", "application/x-www-form-urlencoded")

		GET:
			resp, _, err = wh.Dispatch(url+"index.php", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			status := resp.Status
			responseHeaders := resp.Header.Get("Location")
			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse = string(body)
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)

			if status == "500 Internal Server Error" {
				goto GET
			}

			if strings.Contains(status, "30") || strings.Contains(responseHeaders, "Refresh: ") {
				newURLRegex := regexp.MustCompile(`Location:(.*?)\n`)
				newURLMatches := newURLRegex.FindStringSubmatch(responseHeaders)
				var newURL string
				if len(newURLMatches) >= 2 {
					newURL = newURLMatches[1]
				}

				if newURL == "" {
					refreshRegex := regexp.MustCompile(`Refresh: 0; (.*?)\n`)
					refreshMatches := refreshRegex.FindStringSubmatch(responseHeaders)
					if len(refreshMatches) >= 2 {
						newURL = refreshMatches[1]
					}
				}

				resp, _, err = wh.Dispatch(newURL, "GET", "", headers)
				if err != nil {
					fmt.Printf("Request failed: %v", err)
					continue
				}
				defer resp.Body.Close()

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Failed to read response body: %v", err)
					continue
				}

				decodedResponse = string(body)
			}
			

			if strings.Contains(strings.ToLower(decodedResponse), "navigation.php") || strings.Contains(strings.ToLower(decodedResponse), "logout.php") || strings.Contains(strings.ToLower(decodedResponse), "information_schema") {
				fmt.Printf("Password encontrado: [phpmyadmin] %s Usuario:%s Password:%s\n", url, user, password)
				
				re := regexp.MustCompile(`db_operations\.php\?[^>]*?db=([^&]+)`)
				matches := re.FindAllStringSubmatch(decodedResponse, -1)
				for _, match := range matches {
					if len(match) > 1 {
						fmt.Println("db =", match[1])
					}
				}

				break
			}
		}

	}//phpmyadmin


	if module == "phpPgadmin" {
		for _, password := range passwordsList {
			password = strings.TrimSpace(password)

			resp, _, err := wh.Dispatch(url + "redirect.php?subject=server&server=postgres%3A5432%3Aallow&", "GET", "", headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse := string(body)
			if strings.Contains(strings.ToLower(decodedResponse), "You are logged in as user") || strings.Contains(strings.ToLower(decodedResponse), "toplink_logout") {
				fmt.Printf("[phpPgadmin] %s (Sistema sin password)\n", url)
				continue
			}
			//<input id="loginPassword" type="password" name="loginPassword_b300d5512fec862b7adb71f2c9bbba3c"
			loginPasswordRegex := regexp.MustCompile(`<input id="loginPassword" type="password" name="(.*?)"`)
			matches := loginPasswordRegex.FindStringSubmatch(decodedResponse)
			var loginPassword string
			if len(matches) >= 2 {
				loginPassword = matches[1]
			}

		
			hashData := map[string]string{
				"loginUsername": user,
				loginPassword : password,
				"loginSubmit":    "Login",
				"subject":       "server",
				"server":       "postgres:5432:allow",
				"loginServer":       "postgres:5432:allow",
			}

			postData := ConvertHash(hashData)
			headers.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, _, err = wh.Dispatch(url+"redirect.php", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			status := resp.Status
			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse = string(body)
			fmt.Printf("[+] user:%s password:%s status:%s\n", user, password, status)


			if strings.Contains(strings.ToLower(decodedResponse), "You are logged in as user") || strings.Contains(strings.ToLower(decodedResponse), "toplink_logout") {
				fmt.Printf("Password encontrado: [phpPgadmin] %s Usuario:%s Password:%s\n", url, user, password)
				break
			}
		}

	}//phpPgadmin

	if module == "joomla" { //3.10
		resp, _, err := wh.Dispatch(url + "index.php", "GET", "", headers)
		if err != nil {
			fmt.Printf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		decodedResponse := string(body)		

		var csrf string
		//  <input type="hidden" name="a9ef04c13c3150f6055aeb52a58b6e15" value="1" />
		tokenRegex := regexp.MustCompile(`"csrf.token":"(.*?)"`)
		matches := tokenRegex.FindStringSubmatch(decodedResponse)
		if len(matches) >= 2 {
			csrf = matches[1]
		}

		if csrf == "" {
			tokenRegex2 := regexp.MustCompile(`type="hidden" name="([a-f0-9]+)"`)
			matches2 := tokenRegex2.FindStringSubmatch(decodedResponse)
			
			if len(matches2) >= 2 {
				csrf = matches2[1]
			}
		}

	
		var ret string
		//	        <input type="hidden" name="return" value="aW5kZXgucGhw"/> 
		tokenRegex = regexp.MustCompile(`name="return" value="(.*?)"`)
		matches = tokenRegex.FindStringSubmatch(decodedResponse)
		if len(matches) >= 2 {
			ret = matches[1]
		}

		for _, password := range passwordsList {
			password = strings.TrimSpace(password)
			hashData := map[string]string{
				csrf:   "1",
				"return":ret,
				"task": "login",
				"option": "com_login",
				"username": user,
				"passwd": password,
			}


			postData := ConvertHash(hashData)

			headers.Set("Upgrade-Insecure-Requests", "1")
			headers.Set("Origin", url)
			headers.Set("Referer", url )
			headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			resp, _, err := wh.Dispatch(url + "index.php", "POST", postData, headers)
			if err != nil {
				fmt.Printf("Request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Failed to read response body: %v", err)
				continue
			}

			decodedResponse := string(body)

			
			title := extractTitle(decodedResponse)
			fmt.Printf("[+] user:%s password:%s title:%s\n", user, password, title)

			if strings.Contains(title, "Control Panel") {
				fmt.Printf("Password encontrado: [joomla] %s (Usuario:%s Password:%s)\n", url, user, password)
				break
			}
		}
	}//joomla

}//passwordTest


func extractTitle(html string) string {
    // First attempt: match multiline title with whitespace
    re := regexp.MustCompile(`(?is)<title>\s*(.*?)\s*</title>`)
    match := re.FindStringSubmatch(html)
    if len(match) > 1 {
        // Clean up the extracted title
        title := match[1]
        // Remove newlines, tabs, and extra spaces
        title = regexp.MustCompile(`[\n\t\r]+`).ReplaceAllString(title, " ")
        // Collapse multiple spaces into single space
        title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
        // Trim leading/trailing spaces
        title = strings.TrimSpace(title)
        return title
    }
    return ""
}

func ExtractFooterText(htmlContent string) string {
    doc, _ := html.Parse(strings.NewReader(htmlContent))

    var footerText string
    var findFooterText func(*html.Node)

    findFooterText = func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "footer" {
            var buf bytes.Buffer
            // Extract all text from footer and its children
            var extractText func(*html.Node)
            extractText = func(n *html.Node) {
                if n.Type == html.TextNode {
                    text := strings.TrimSpace(n.Data)
                    if text != "" {
                        if buf.Len() > 0 {
                            buf.WriteString(" ")
                        }
                        buf.WriteString(text)
                    }
                }
                for c := n.FirstChild; c != nil; c = c.NextSibling {
                    extractText(c)
                }
            }
            extractText(n)
            footerText = strings.TrimSpace(buf.String())
            return
        }

        for c := n.FirstChild; c != nil; c = c.NextSibling {
            findFooterText(c)
        }
    }

    findFooterText(doc)

    // Remove newlines and carriage returns
    footerText = strings.ReplaceAll(footerText, "\n", " ")
    footerText = strings.ReplaceAll(footerText, "\r", " ")

    // Truncate to max 200 characters
    if len(footerText) > 200 {
        footerText = footerText[:200]
    }

    return footerText
}


func stripPort(url string) string {
    parts := strings.Split(url, ":")
    if len(parts) == 3 {
        // Case: https://181.188.147.65:443/login
        return parts[0] + ":" + parts[1] + parts[2]
    }
    // Case: https://181.188.147.65/login
    return url
}
func getBody(resp *http.Response) (string, int) {
    if resp == nil {
        return "", 0
    }
    
    // Always close the original response body when done
    defer resp.Body.Close()
    
    var bodyReader io.ReadCloser
    switch resp.Header.Get("Content-Encoding") {
    case "gzip", "x-gzip":
        bodyReader, err := gzip.NewReader(resp.Body)
        if err != nil {
            return "", 0
        }
        defer bodyReader.Close()
    default:
        bodyReader = resp.Body
    }
    
    // Read the entire body using ioutil.ReadAll
    body, _ := ioutil.ReadAll(bodyReader)
    
    // Process the response
    decodedResponse := string(body)
    decodedResponse = strings.ReplaceAll(decodedResponse, "'", "\"")
    decodedResponse = regexp.MustCompile(".*\\/logout.*\\n").ReplaceAllString(decodedResponse, "")
    decodedResponse = regexp.MustCompile(".*sclogin.html*").ReplaceAllString(decodedResponse, "")
    decodedResponse = regexp.MustCompile(".*index.html*").ReplaceAllString(decodedResponse, "")
    decodedResponse = regexp.MustCompile(".*?console*").ReplaceAllString(decodedResponse, "")
    responseLength := len(decodedResponse)

	decodedResponse = strings.ReplaceAll(decodedResponse, "'", "\"")
	decodedResponse = regexp.MustCompile("[^\\x00-\\x7f]").ReplaceAllString(decodedResponse, "")
	decodedResponse = regexp.MustCompile("/index.php").ReplaceAllString(decodedResponse, "")
	decodedResponse = strings.ReplaceAll(decodedResponse, "https", "http")
	decodedResponse = strings.ReplaceAll(decodedResponse, "www.", "")
	decodedResponse = regexp.MustCompile("admin@example.com").ReplaceAllString(decodedResponse, "")
	decodedResponse = regexp.MustCompile("postmaster@example.com").ReplaceAllString(decodedResponse, "")


	responseHeaders := headerToString(resp.Header)
	decodedHeaderResponse := responseHeaders + "\n" + decodedResponse
	// Fix location.href='https://192.168.111.95:8443/index.do"+showPreLogin;
	decodedHeaderResponse = strings.ReplaceAll(decodedHeaderResponse, "\"+\"", "")


    return decodedHeaderResponse, responseLength
}


func (wh *WebHacks) GetData(logFile string) (map[string]string, error) {
	debug := wh.Debug
	rhost := wh.Rhost
	rport := wh.Rport
	proto := wh.Proto
	webpath := wh.Path



	poweredBy := ""
	redirectURL := "no"
	var urlOriginal string
	var urlOriginal_nonexist string
	if rport == "443" || rport == "80" {
		urlOriginal = proto + "://" + rhost + webpath
		urlOriginal_nonexist = proto + "://" + rhost + webpath + "acsfsefes.php"
	} else {
		urlOriginal = proto + "://" + rhost + ":" + rport + webpath
		urlOriginal_nonexist = proto + "://" + rhost + ":" + rport + webpath + "acsfsefes.php"
	}
	var finalURLRedirect string
	var decodedResponse string
	var resp *http.Response
	var err error
	var StatusCode int
	var vulnerability0 string
	var poweredBy0 string
	var redirect_url string
	//status := ""
	newDomain := ""
	lastURL := ""
	vulnerability := ""
	decodedHeaderResponse:=""
	responseLength:=0

	origURL, _ := url.Parse(urlOriginal)
	domainOriginal := origURL.Hostname()

	for redirectURL != "" {
		if debug {
			fmt.Printf("urlOriginal (%s)\n", urlOriginal)
			fmt.Printf("redirect_url en WHILE1 (%s)\n", redirectURL)
		}
		resp, _, err = wh.Dispatch(urlOriginal, "GET", "", wh.Headers)	
		lastURL = resp.Request.URL.String()
		StatusCode = resp.StatusCode
		decodedHeaderResponse, responseLength = getBody(resp)

		resp_nonexist, _, _ := wh.Dispatch(urlOriginal_nonexist, "GET", "", wh.Headers)	
		decodedHeaderResponse_nonexist, _ := getBody(resp_nonexist)

		data0 := ExtractResponseData(decodedHeaderResponse_nonexist,  debug )

		
		vulnerability0 = data0["vulnerability"]
		if vulnerability0 != "" {
			redirect_url = urlOriginal_nonexist
		}
		poweredBy0 = data0["poweredBy"]

		

				
		//////////////////// protocol error ////////		
		if err != nil {
			errStr := err.Error()
			if debug {
			fmt.Printf("Debug - Error string: %s\n", errStr)
			}

			if strings.Contains(decodedHeaderResponse, "server gave HTTPS response to HTTP client") || strings.Contains(decodedResponse, "speaking plain HTTP to an SSL-enabled server port") {
				// Handling protocol mismatch by switching protocol
				fmt.Printf("Handling protocol mismatch by switching protocol HTTP to HTTPS\n")
				urlOriginal = "https://" + rhost + ":" + rport + webpath				
			}

			if strings.Contains(decodedHeaderResponse, "server gave HTTP response to HTTPS client") || strings.Contains(errStr, "first record does not look like a TLS")  {
				// Handling protocol mismatch by switching protocol
				fmt.Printf("Handling protocol mismatch by switching protocol HTTPS to HTTP\n")
				urlOriginal = "http://" + rhost + ":" + rport + webpath				
			}
			resp, _, err = wh.Dispatch(urlOriginal, "GET", "", wh.Headers)
			decodedHeaderResponse, responseLength = getBody(resp)
		}
		///////////////////////////////////
		
		if debug {
			fmt.Printf("statusss: (%d)\n", StatusCode)
			fmt.Printf("Response length: %d\n", responseLength)
		}


		if urlOriginal != lastURL {
			poweredBy += "|301 Moved"
		}

		//###### check redirect with content ##########
		if StatusCode > 300 && StatusCode <400 {
			if responseLength > 700 && !strings.Contains(decodedHeaderResponse, "noscript") {
				vulnerability = "redirectContent"
				//break
			}
		}
		
		if debug {
			fmt.Printf("responseLength %d \n", responseLength)
		}
		//#####################################

		// Check redirection from http to https
		origURL, _ := url.Parse(urlOriginal)
		finalURL, _ := url.Parse(lastURL)
		if origURL.Scheme != finalURL.Scheme {
			poweredBy += "|HTTPSredirect"
		}

		domainFinal := finalURL.Hostname()
		if debug {
			fmt.Printf("domainOriginal %s domain_final %s\n", domainOriginal, domainFinal)
			fmt.Printf("urlOriginal %s last_url %s\n", urlOriginal, lastURL)
		}

		if domainOriginal != domainFinal {
			poweredBy += "|301 Moved"
			newDomain = domainFinal
		}

		//fmt.Printf("decodedResponse (%s)\n", decodedResponse)
		if responseLength < 700 {			

			redirectURL = getRedirect(decodedHeaderResponse)
			if debug {
				fmt.Printf("redirect_url (%s)\n", redirectURL)
				//fmt.Printf("decodedHeaderResponse (%s)\n", decodedHeaderResponse)
			}
		} else {
			redirectURL = ""
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
			urlOriginal = finalURLRedirect
		}
		if debug {
			fmt.Printf("urlOriginal en WHILE2 %s\n", urlOriginal)
		}
	} //end for
	
	if StatusCode == 404 {
        poweredBy += "|404 not found"
    }


	
	// ######## write log ######
	file, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()

	if _, err := file.WriteString(decodedResponse + "\n"); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: No puedo escribir en el fichero %v\n", err)
		os.Exit(1) // Exit the program with a non-zero status code
	}
	// #################



	data := ExtractResponseData(decodedHeaderResponse,  debug )
	poweredBy = data["poweredBy"] 
	if poweredBy != poweredBy0 {
		data["poweredBy"] = poweredBy + poweredBy0
	} else {
		data["poweredBy"] = poweredBy
	}
	
	data["vulnerability"] = vulnerability + vulnerability0
	data["newdomain"] = newDomain            // Final domain after redirects
	data["redirect_url"] = redirect_url

	// fmt.Println("Extracted Data:")
	// for key, value := range data {
	// 	fmt.Printf("  %-12s: %s\n", key, value)
	// }

	return data, nil
}


func ExtractResponseData(decodedHeaderResponse string,  debug bool) map[string]string{

	// ############### title ########	
	title := extractTitle(decodedHeaderResponse)
	footer := ExtractFooterText(decodedHeaderResponse)
	poweredBy := ""
	vulnerability := ""
		
	if debug {
		fmt.Printf("title %s\n", title)
		fmt.Printf("footer %s\n", footer)
	}


	if regexp.MustCompile(`(?i)Boa\/0.9`).MatchString(decodedHeaderResponse) {
		if title == "" {
			title = "Broadband device web server"
		}
	}

	if regexp.MustCompile(`(?i)TP-LINK Technologies Co`).MatchString(decodedHeaderResponse) {
		if title == "" {
			title = "TP-LINK"
		}
	}

	if regexp.MustCompile(`(?i)frmRedirectToTop`).MatchString(decodedHeaderResponse) {
		if title == "" {
			title = "Router cisco"
		}
	}
	
	
	if regexp.MustCompile(`(?i)idrac`).MatchString(decodedHeaderResponse) {
		title = "Dell iDRAC"
	}
	
	

	if regexp.MustCompile(`(?i)Acceso no autorizado`).MatchString(decodedHeaderResponse) {
		if title == "" {
			title = "Acceso no autorizado"
		}
	}
	
	if regexp.MustCompile(`(?i)Hikvision Digital`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)szErrorTip`).MatchString(decodedHeaderResponse) {
		title = "Hikvision Digital"
	}
	
	if regexp.MustCompile(`(?i)FreeNAS`).MatchString(decodedHeaderResponse) {
		title = "FreeNAS"
	}
	
	if regexp.MustCompile(`(?i)ciscouser`).MatchString(decodedHeaderResponse) {
		title = "Cisco switch"
	}
	
	if regexp.MustCompile(`(?i)pfsense-logo|Login to pfSense`).MatchString(decodedHeaderResponse) {
		title = "Pfsense"
	}
	
	if regexp.MustCompile(`(?i)servletBridgeIframe`).MatchString(decodedHeaderResponse) {
		title = "SAP Business Objects"
	}
	
	if regexp.MustCompile(`(?i)content="Babelstar"`).MatchString(decodedHeaderResponse) {
		title = "Body Cam"
	}
	
	if regexp.MustCompile(`(?i)login to iDRAC`).MatchString(decodedHeaderResponse) && !regexp.MustCompile(`(?i)Cisco`).MatchString(decodedHeaderResponse) {
		title = "Dell iDRAC"
	}
	
	if regexp.MustCompile(`(?i)portal.peplink.com`).MatchString(decodedHeaderResponse) {
		title = "Web Admin PepLink"
	}

	if regexp.MustCompile(`(?i)This is the default web page for this server.`).MatchString(decodedHeaderResponse) {
		title = "Apache default page"
	}
	
	server := ""
	re := regexp.MustCompile(`(?i)Server:(.*?)\n`)
	serverMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(serverMatch) > 1 {
		server = serverMatch[1]
		if debug {
			fmt.Printf("server %s\n", server)
		}
	}


	if regexp.MustCompile(`(?i)You have logged out of the Cisco Router|Cisco RV340 Configuration Utility`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		server = "Cisco Router"
	} 

	if regexp.MustCompile(`(?i)Panos.browser|GlobalProtect`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		server = "Palo Alto"
	} 

	if regexp.MustCompile(`(?i)<div id="flashContent">`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		server = "swfobject"
	} 


	if regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		server = "Cisco Unified Communications"
	} 
	
	if regexp.MustCompile(`(?i)CSCOE`).MatchString(decodedHeaderResponse) {
		server = "ciscoASA"
	} 
	
	if regexp.MustCompile(`(?i)Cisco EPN Manage`).MatchString(decodedHeaderResponse) {
		server = "Cisco EPN Manage"
	} 
	
	if regexp.MustCompile(`(?i)OLT Web Management Interface`).MatchString(decodedHeaderResponse) {
		server = "OLT Web Management Interface"
	} 
	
	if regexp.MustCompile(`(?i)Janus WebRTC Server`).MatchString(decodedHeaderResponse) {
		server = "Janus WebRTC Server"
	} 
	
	
	if regexp.MustCompile(`(?i)mbrico N 300Mbps WR840N`).MatchString(decodedHeaderResponse) {
		server = "TL-WR840N"
		title = "Router inalámbrico N 300Mbps WR840N"
	} 

	//fmt.Printf("decodedContent %s\n", decodedHeaderResponse)
	if regexp.MustCompile(`(?i)redirect_suffix\s*=\s*"/cgi-bin/QTS\.cgi\?count="`).MatchString(decodedHeaderResponse) {
		server = "QNAP Server"
		title = "QNAP NAS"
	}

	if regexp.MustCompile(`(?i)metabase.DEVICE`).MatchString(decodedHeaderResponse) {
		title = "Metabase"
	}

	if regexp.MustCompile(`(?i)In order to access the ShareCenter`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		title = "D-Link NAS"
	} 
	
	if (regexp.MustCompile(`(?i)custom_logo/web_logo.png|baseProj/images/favicon.ico`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)webplugin.exe|BackUpBeginTimeChanged|playback_bottom_bar`).MatchString(decodedHeaderResponse)) && regexp.MustCompile(`(?i)WEB SERVICE`).MatchString(decodedHeaderResponse) {
		server = "Dahua"
	} 
	if regexp.MustCompile(`(?i)webplugin.exe|BackUpBeginTimeChanged|playback_bottom_bar`).MatchString(decodedHeaderResponse) {
		server = "Dahua"
	} 
	
	if regexp.MustCompile(`(?i)pgm-theatre-staging-div`).MatchString(decodedHeaderResponse) {
		server = "printer HP laser"
	} 
	
	if regexp.MustCompile(`(?i)login/bower_components/requirejs/require.js`).MatchString(decodedHeaderResponse) {
		server = "MDS Orbit Device Manager "
	} 
	
	if regexp.MustCompile(`(?i)ATEN International Co`).MatchString(decodedHeaderResponse) {
		server = "Super micro"
	} 

	if regexp.MustCompile(`(?i)Comrex ACCESS`).MatchString(decodedHeaderResponse) {
		server = "Audio codec server"
	} 

	//imprimir fmt.Printf("decodedHeaderResponse %s\n", decodedHeaderResponse)
	if regexp.MustCompile(`(?i)javax.faces`).MatchString(decodedHeaderResponse) {
		server = "JavaServer Faces"
	} 
	
	if regexp.MustCompile(`(?i)JSP/`).MatchString(decodedHeaderResponse) {
		server = "JavaServer Pages"
	} 
	
	
	
	if regexp.MustCompile(`(?i)Juniper Web Device Manager`).MatchString(decodedHeaderResponse) {
		server = "Juniper Web Device Manager"
	} 
	
	if regexp.MustCompile(`(?i)by Cisco Systems, Inc`).MatchString(decodedHeaderResponse) {
		server = "Cisco WebUI"
	} 

	if regexp.MustCompile(`(?i)www.tp-link.com/en/Support`).MatchString(decodedHeaderResponse) {
		server = "tp-link"
	} 

	
	
	if regexp.MustCompile(`(?i)fortinet|FortiWeb`).MatchString(decodedHeaderResponse) {
		server = "FortiWeb"
	} 
	
	if regexp.MustCompile(`(?i)RouterOS router`).MatchString(decodedHeaderResponse) {
		matches := regexp.MustCompile(`<h1>(.*?)</h1>`).FindStringSubmatch(decodedHeaderResponse)
		if len(matches) > 1 {
			server = matches[1]
		}
	}

	if regexp.MustCompile(`(?i)airos_logo`).MatchString(decodedHeaderResponse) {
		title = "airOS"
		server = "Ubiquiti"
	}

	if regexp.MustCompile(`(?i)This version of oviyam`).MatchString(decodedHeaderResponse) {
		title = "oviyam"
		poweredBy += "|Medical"
	}

	if regexp.MustCompile(`(?i)moodlesimple`).MatchString(decodedHeaderResponse) {
		poweredBy += "|Moodle"
	}
	
	// ############# powered by ##############
	re = regexp.MustCompile(`(?i)X-Powered-By:(.*?)\n`)
	poweredByMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(poweredByMatch) > 1 {
		pwdby := poweredByMatch[1]
		//fmt.Printf("pwdby %s\n", pwdby)
		poweredBy += pwdby
	}

	if strings.Contains(decodedHeaderResponse, "laravel_session") ||strings.Contains(decodedHeaderResponse, "laravel CRUD") || strings.Contains(decodedHeaderResponse, "Laravel Client") {
		re := regexp.MustCompile(`framework_version":"([\d.]+)`)
		matches := re.FindStringSubmatch(decodedHeaderResponse)
		if len(matches) >= 2 {
			version := matches[1]
			poweredBy += "|Laravel "+version
		} else {
			poweredBy += "|Laravel"
		}
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
	proxyMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(proxyMatch) > 1 {
		proxy := proxyMatch[1]
		if len(proxy) > 1 {
			poweredBy += "| proxy=" + proxy
		}
	}

	re = regexp.MustCompile(`(?i)WWW-Authenticate:(.*?)\n`)
	authenticateMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(authenticateMatch) > 1 {
		authenticate := authenticateMatch[1]
		if len(authenticate) > 1 {
			poweredBy += "| proxy=" + authenticate
		}
	}

	re = regexp.MustCompile(`<img src="(.*?)" class="logo">`)
    match := re.FindStringSubmatch(decodedHeaderResponse)
    if len(match) > 1 {
        logo := match[1]
		poweredBy += "|" + logo
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
		if len(h1) > 2 && len(h1) < 100 {
			poweredBy += "| H1=" + h1
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h2>`)
	h2Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h2Match) > 1 {
		h2 := strings.ReplaceAll(h2Match[1], "\n", " ")
		h2 = strings.TrimSpace(h2)
		h2 = onlyAscii(h2)
		if len(h2) > 2 && len(h2) < 100 {
			poweredBy += "| H2=" + h2
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h3>`)
	h3Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h3Match) > 1 {
		h3 := strings.ReplaceAll(h3Match[1], "\n", " ")
		h3 = strings.TrimSpace(h3)
		h3 = onlyAscii(h3)
		if len(h3) > 2 && len(h3) < 100 {
			poweredBy += "| H3=" + h3
		}
	}

	re = regexp.MustCompile(`>([\w\s]+)</h4>`)
	h4Match := re.FindStringSubmatch(decodedHeaderResponse)
	if len(h4Match) > 1 {
		h4 := strings.ReplaceAll(h4Match[1], "\n", " ")
		h4 = strings.TrimSpace(h4)
		h4 = onlyAscii(h4)
		if len(h4) > 2 && len(h4) < 100 {
			poweredBy += "| H4=" + h4
		}
	}

	if strings.Contains(decodedHeaderResponse, "GASOLINERA") {
        poweredBy += "|GASOLINERA"
    }


	if strings.Contains(decodedHeaderResponse, "</app>")  || strings.Contains(decodedHeaderResponse, "<app-root>")  || strings.Contains(decodedHeaderResponse, `div id="root"`) || strings.Contains(decodedHeaderResponse, "angular.bootstrap")   {
        poweredBy += "|JavascriptFramework"
    }

	if strings.Contains(decodedHeaderResponse, "Powered by VESTA")  {
        poweredBy += "|VESTA"
    }

	

	if strings.Contains(decodedHeaderResponse, "Please ensure that the other VPN client pages ") {
        poweredBy += "|VPN"
    }

	

	if strings.Contains(decodedHeaderResponse, "nucleo/vendor/js/") || strings.Contains(decodedHeaderResponse, "nucleo/src/css") {
		poweredBy += "|Nucleo"
	}
	

	
	

	if regexp.MustCompile(`Microsoftsharepointteamservices`).MatchString(decodedHeaderResponse) {
		server = "Microsoft SharePoint"
		re := regexp.MustCompile(`Microsoftsharepointteamservices: ([\d.]+)\r?\n`)
		matches := re.FindStringSubmatch(decodedHeaderResponse)

		if len(matches) > 1 {
			version := matches[1]
			poweredBy += "|SharePoint v" + version
		} else {
			poweredBy += "|SharePoint"
		}
	}

	if regexp.MustCompile(`GeoServer`).MatchString(decodedHeaderResponse) {
		//re := regexp.MustCompile(`GeoServer ([\d.]+)\r?\n`)
		re := regexp.MustCompile(`GeoServer\s*([\d.]+)`)
		matches := re.FindStringSubmatch(decodedHeaderResponse)

		if len(matches) > 1 {
			version := matches[1]
			poweredBy += "|GeoServer v" + version
		} else {
			poweredBy += "|GeoServer"
		}
	}

	if regexp.MustCompile(`Liferay-Portal`).MatchString(decodedHeaderResponse) {
		re := regexp.MustCompile(`Liferay-Portal: (.*?)\r?\n`)
		matches := re.FindStringSubmatch(decodedHeaderResponse)

		if len(matches) > 1 {
			version := matches[1]
			poweredBy += "|" + version
		} else {
			poweredBy += "|Liferay-Portal"
		}
	}


	if strings.Contains(decodedHeaderResponse, "/assets/erpnext") {
        poweredBy += "|erpnext"
    }

	if strings.Contains(decodedHeaderResponse, "Payara Server Open Source") {
        poweredBy += "|Payara"
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

	if regexp.MustCompile(`Set-Cookie: CHATBOT=`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Botpress"
		server = "Botpress"
    }

	if regexp.MustCompile(`XSRF-TOKEN|_session`).MatchString(decodedHeaderResponse) {
		poweredBy += "|api-endpoint"
	}

	if regexp.MustCompile(`wp-content/themes/`).MatchString(decodedHeaderResponse) {
		poweredBy += "|wordpress"
	}

	if regexp.MustCompile(`Chamilo LMS stylesheet `).MatchString(decodedHeaderResponse) {
		poweredBy += "|Chamilo"
	}

	
	
	
	//fmt.Printf("decodedHeaderResponse: %s\n", decodedHeaderResponse)
    if regexp.MustCompile(`FortiGate|FortiGate for inclusion in the httpsd debug log`).MatchString(decodedHeaderResponse) {
        poweredBy += "|FortiGate"
        server = "FortiGate"
    }
    if regexp.MustCompile(`yii-debug-toolbar|yii.css`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Yii"
    }
	if regexp.MustCompile(`www.drupal.org`).MatchString(decodedHeaderResponse) {
        poweredBy += "|drupal"
    }
    if regexp.MustCompile(`laravel_session`).MatchString(decodedHeaderResponse) {
        poweredBy += "|laravel"
    }
    if regexp.MustCompile(`content="WordPress|wp-json`).MatchString(decodedHeaderResponse) {
		re := regexp.MustCompile(`content="WordPress ([\d.]+)"`)
		match := re.FindStringSubmatch(decodedHeaderResponse)
		if len(match) > 1 {
			version := match[1]
			poweredBy += "|wordpress v" + version
		} else {
			poweredBy += "|wordpress"
		}
	}

    if regexp.MustCompile(`Powered by Abrenet`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Powered by Abrenet"
    }
    if regexp.MustCompile(`csrfmiddlewaretoken|Django`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Django"
    }
    if regexp.MustCompile(`IP Phone`).MatchString(decodedHeaderResponse) {
        poweredBy += "| IP Phone "
    }
    if regexp.MustCompile(`X-Amz-`).MatchString(decodedHeaderResponse) {
        poweredBy += "|amazon"
    }

	if regexp.MustCompile(`please visit <a href="https://portal.azure.com/"`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Azure"
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
    if regexp.MustCompile(`fortinet-grid`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Fortinet"
        server = "Fortinet"
    }

	if regexp.MustCompile(`Sophos UTM Manager`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Sophos UTM"
        server = "Sophos"
    }

	if regexp.MustCompile(`(?i)name="password"`).MatchString(decodedHeaderResponse) {
		poweredBy += "|login"
	}
	

    if regexp.MustCompile(`theme-taiga.css`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Taiga"
    }
    if regexp.MustCompile(`X-Powered-By-Plesk`).MatchString(decodedHeaderResponse) {
        poweredBy += "|PleskWin"
    }

	if regexp.MustCompile(`Observium`).MatchString(decodedHeaderResponse) {
        poweredBy += "|networkMonitoring"
    }


	
    if regexp.MustCompile(`Web Services`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Web Service"
		server = "Dahua"
        if title == "" {
            title = "Web Service"
        }
    }

	if regexp.MustCompile(`DHVideoWHMode`).MatchString(decodedHeaderResponse) {
		server = "Dahua"
        if title == "" {
            title = "Web Service"
        }
    }
	

	if regexp.MustCompile(`logoTyco`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Tyco"
    }

	if regexp.MustCompile(`X-Magento-Vary`).MatchString(decodedHeaderResponse) {
        poweredBy += "|magento"
    }

	if regexp.MustCompile(`workspaceSkin=`).MatchString(decodedHeaderResponse) {
        poweredBy += "|processmaker"
    }
	

    if regexp.MustCompile(`login__block__header`).MatchString(decodedHeaderResponse) {
        poweredBy += "|login"
        if title == "" {
            title = "Panel de logueo"
        }
    }

	
	if regexp.MustCompile(`(?i)waiting\.\.\.|ui_huawei_fw_ver|CertInstallFF`).MatchString(decodedHeaderResponse) {
		server = "Huawei"
		if title == "</title" {
			title = "Huawei"
		}
	}

	if regexp.MustCompile(`(?i)Serv-U`).MatchString(decodedHeaderResponse) {
		title = "Serv-U"
	}

	if regexp.MustCompile(`(?i)dlink.com/default.aspx`).MatchString(decodedHeaderResponse) {
		if title == "</title" {
			title = "dlink"
		}
	}	

	
	if regexp.MustCompile(`(?i)TP-Link Corporation Limited`).MatchString(decodedHeaderResponse) {
		
		server = "TP-Link"

		productNameRegex := regexp.MustCompile(`(?i)var modelDesc="(.*?)"`)
		if matches := productNameRegex.FindStringSubmatch(decodedHeaderResponse); len(matches) > 1 {
			title = matches[1]
		}

		productNameRegex = regexp.MustCompile(`(?i)modelName="(.*?)"`)
		if matches := productNameRegex.FindStringSubmatch(decodedHeaderResponse); len(matches) > 1 {
			poweredBy += "|" + matches[1]
		}
	}


	if regexp.MustCompile(`(?i)Huawei Technologies Co|HG8145V5|EG8145X6|WA8021V5`).MatchString(decodedHeaderResponse) {
		
		title, server = "Huawei", "Huawei"
		productNameRegex := regexp.MustCompile(`(?i)var ProductName = "(.*?)"`)
		if matches := productNameRegex.FindStringSubmatch(decodedHeaderResponse); len(matches) > 1 {
			title =  matches[1]
		}
	}

	if debug {
		fmt.Printf("poweredBy %s\n", poweredBy)
	}
	// ##################

	vulnerability = vulnerability + checkVuln(decodedHeaderResponse,title)
	
	
	if debug {
		fmt.Printf("vulnerability %s\n", vulnerability)
	}
	//###########

	data := map[string]string{
		"title":         title,
		"server":        server,
		"poweredBy":     poweredBy,
		"vulnerability": vulnerability,
		"footer": footer,
	}

	return data

}

func (wh *WebHacks) Dirbuster(urlFile, extension string) {
	headers := wh.Headers
	debug := wh.Debug
	filter := wh.Filter
	show404 := wh.Show404
	rhost := wh.Rhost
	rport := wh.Rport
	webpath := wh.Path
	error404 := wh.Error404
	threads := wh.Threads
	proto := wh.Proto
	ajax := wh.Ajax
	timeout := wh.Timeout
	MaxRedirect := wh.MaxRedirect

	var (
		resp    *http.Response
		lastURL string
		err     error
		lastURL404 string
		status404 int

	)

	
	var results []Result

	// Check for always redirect condition
	// Append port only if it's not default
	portStr := ""
	if rport != "80" && rport != "443" {
		portStr = ":" + rport
	}


	if debug {
		fmt.Printf("Usando archivo: %s con extension (%s)\n", urlFile, extension)		
		fmt.Printf("Configuracion: Hilos:%s proto:%s Ajax:%s error404:%s show404:%s timeout:%s debug:%s MaxRedirect:%s \n\n",
			threads, proto, ajax, error404, show404, timeout, debug, MaxRedirect)
		fmt.Printf("lastURL404: %s status404 %s \n", lastURL404,status404)
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

		// Replace extensions if specified
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

		// Append "/" if the URL file suggests directories
		if strings.Contains(urlFile, "folders") {
			urlLine += "/"
		}

		// Append port only if it's not default
		portStr = ""
		if rport != "80" && rport != "443" {
			portStr = ":" + rport
		}

		urlFinal := proto + "://" + rhost + portStr + webpath + urlLine
		links = append(links, urlFinal)
	}

	var wg sync.WaitGroup
	wg.Add(threads)

	urlsChan := make(chan string, len(links))
	// Start a pool of worker goroutines
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for urlLine := range urlsChan {
				if strings.Contains(urlFile, "backups") {
					resp, lastURL, err = wh.Dispatch(urlLine, "HEAD", "", headers)
					// handle resp, lastURL, err if needed
				} else {
					resp, lastURL, err = wh.Dispatch(urlLine, "GET", "", headers)
					// handle resp, lastURL, err if needed
				}				

				lastSegment := path.Base(strings.TrimRight(urlLine, "/")) //extract last part 
				if err != nil {
					fmt.Printf("Failed to get URL %s: %v\n", urlLine, err)
					continue
				}
				defer resp.Body.Close()

				// Handle response body and potential gzip decompression
				var bodyReader io.ReadCloser
				switch resp.Header.Get("Content-Encoding") {
				case "gzip", "x-gzip":
					bodyReader, err = gzip.NewReader(resp.Body)
					if err != nil {
						fmt.Println("Error al descomprimir la respuesta gzip")
						os.Exit(1)
					}
					defer bodyReader.Close()
				default:
					bodyReader = resp.Body
				}

				bodyBytes, _ := ioutil.ReadAll(bodyReader)
				bodyContent := string(bodyBytes)

				current_status := resp.StatusCode
				contentLength := resp.Header.Get("Content-Length")				
				contentLengthInt, err := strconv.ParseInt(contentLength, 10, 64)
				
				if err != nil || contentLengthInt == 0 {
					// Si falla la conversión o es 0, usar longitud del cuerpo leído
					contentLengthInt = int64(len(bodyContent))
				}
				
				 if debug {						
				 	fmt.Printf("lastURL=%s contentLengthIntL=%s resp.StatusCode=%s\n",lastURL,contentLengthInt,resp.StatusCode)
				 }

				 if strings.Contains(strings.ToLower(lastURL), "suspendedpage") ||
				 strings.Contains(strings.ToLower(lastURL), "returnurl") ||
				 strings.Contains(strings.ToLower(lastURL), "/frmLogin.aspx") ||
				 strings.Contains(strings.ToLower(lastURL), "/frmLogin.php") ||
				 strings.Contains(strings.ToLower(lastURL), "/frmLogin.jsp") ||
				 strings.Contains(strings.ToLower(lastURL), "/frmLogin.asp") ||
				 strings.Contains(strings.ToLower(lastURL), "/login.aspx?") ||
				 strings.Contains(strings.ToLower(lastURL), "/login.php?") ||
				 strings.Contains(strings.ToLower(lastURL), "/login.asp?") ||
				 strings.Contains(strings.ToLower(lastURL), "/login.jsp?") ||
				 strings.Contains(strings.ToLower(lastURL), "/login.do?") ||
				 strings.Contains(strings.ToLower(lastURL), "/login?") ||
				 strings.Contains(strings.ToLower(lastURL), "redirec") ||
				 contentLengthInt == 0 || (status404 == 200 && !strings.Contains(lastURL, "404")) {
						if debug {						
							fmt.Printf("Forzando 404 lastURL=%s responseLenght=%d\n", lastURL,contentLengthInt)
						}
						current_status = 404
				}

				// Check for custom 404 errors
				if error404 != "" {
					errorMessages := strings.Split(error404, "|")
					lowerBodyContent := strings.ToLower(bodyContent)
					for _, errorMessage := range errorMessages {
						if strings.Contains(lowerBodyContent, strings.ToLower(errorMessage)) {
							fmt.Printf("custom 404 error \n")
							current_status = 404
							break
						}
					}
				}

				// Handle 30x redirections
				if current_status == 302 || current_status == 301 {
					redirectURL30x := resp.Header.Get("Location")

					if strings.Contains(redirectURL30x, lastSegment) {
						if debug {
							fmt.Printf("simple redireccion sin / \n")
						}

						current_status = 404
						
					}

					if strings.Contains(strings.ToLower(redirectURL30x), "login") || strings.Contains(strings.ToLower(redirectURL30x), "default") {
						if !strings.Contains(redirectURL30x, "#") && !strings.Contains(redirectURL30x, "//") && !strings.Contains(redirectURL30x, "error") {
							current_status = 200
						}
					}
				}

				// Show results based on status
				if (show404 && current_status == 404) || current_status != 404 {
					vuln := ""
					if current_status == 200 {
						vuln = checkVuln(bodyContent, "")
					}

					errors := []string{
						"Your access is denied",
						"error al procesar esta solicitud",
						"&enckey=",
						"This is the default text for a report",
						"Unauthorized Request Blocked",
						"SessionTimeout",
					 	"Error 404",
						"error_description",
						"Undefined offset",
						"Service not found",
						"Syntax Error",
						"currently unavailable",
						"not found",
						"Request Rejected",
						"Error de servidor",
						"no endpoint to handle",
						"Object not found",
						"page_404",
						"not-found",
						"An attack was detected",
						"Page not found",
						"Contact support for additional information",
						"Ingreso por cuenta",
						"Invalid token supplied",
						"No existe el archivo inc.php",
						"content=\"WordPress",
						"unexpected problem occurred while processing the request",
						"intentando ingresar no existe",
						"error\":\"Error en el metodo",
						"nx-react-app",
						"ENTEL S.A.",
						"ManageEngine",
						"ErrorPage",
						"aspxerrorpath",
						"does not exist",
						"moodlesimple",
					}

					if containsAny(bodyContent, errors) && current_status != 500 {
						if vuln == "" {
							if debug {
								fmt.Printf("custom 404 error2 \n")
							}							
							current_status = 404
						}
					}

						results = append(results, Result{
							Status:        current_status,
							URL:           urlLine,
							Vulnerability: vuln,
							ContentLength: int(contentLengthInt),
						})

				}
			}
		}()
	}

	// Send URLs to the channel for processing
	for _, urlLine := range links {
		urlsChan <- urlLine
	}
	close(urlsChan)

	wg.Wait() // Wait for all goroutines to finish

	//Eliminar resultados con la misma longitud de respuesta
	if filter {
		results = RemoveDuplicateContentLengths(results)
	}

	for _, res := range results {

		if res.Vulnerability != "" {					
					fmt.Printf("%d | %s (vulnerabilidad=%s) | %d\n", res.Status, res.URL, res.Vulnerability, res.ContentLength)
				} else {
					fmt.Printf("%d | %s | %d\n", res.Status, res.URL, res.ContentLength)
				}
	}
	
}

func RemoveDuplicateContentLengths(results []Result) []Result {
    // Step 1: Count occurrences of each ContentLength
    countMap := make(map[int]int)
    for _, res := range results {
        countMap[res.ContentLength]++
    }

    // Step 2: Keep only entries with unique ContentLength
    var uniqueResults []Result
    for _, res := range results {
        if countMap[res.ContentLength] == 1 {
            uniqueResults = append(uniqueResults, res)
        }
    }

    return uniqueResults
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

func (wh *WebHacks) ConfigBuster(urlFile string) {
	headers := wh.Headers
	debug := wh.Debug
	show404 := wh.Show404
	error404 := wh.Error404
	rhost := wh.Rhost
	rport := wh.Rport
	webpath := wh.Path
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
				finalURL := proto + "://" + rhost + ":" + rport + webpath + backupURL
				resp, _, err := wh.Dispatch(finalURL, "GET", "", headers)
				if debug {
					if err != nil {
						fmt.Println("Error fetching URL:", finalURL)
						continue
					}
				}

				var bodyReader io.ReadCloser
				switch resp.Header.Get("Content-Encoding") {
				case "gzip":
					bodyReader, err = gzip.NewReader(resp.Body)
					if err != nil {
						fmt.Println("Error al descomprimir la respuesta gzip")
						os.Exit(1)
					}
					defer bodyReader.Close()
				case "x-gzip":
					bodyReader, err = gzip.NewReader(resp.Body)
					if err != nil {
						fmt.Println("Error al descomprimir la respuesta x-gzip")
						os.Exit(1)
					}
					defer bodyReader.Close()
				default:
					bodyReader = resp.Body
				}

				bodyBytes, _ := ioutil.ReadAll(bodyReader)
				status := resp.StatusCode
				bodyContent := string(bodyBytes)

				if error404 != "" {
					// Split error404 into an array of possible error messages
					errorMessages := strings.Split(error404, "|")
				
					// Convert the bodyContent to lowercase for case-insensitive comparison
					lowerBodyContent := strings.ToLower(bodyContent)
				
					// Iterate over each possible error message
					for _, errorMessage := range errorMessages {
						lowerErrorMessage := strings.ToLower(errorMessage)
						//fmt.Printf("%s \n", lowerBodyContent)
						if strings.Contains(lowerBodyContent, lowerErrorMessage) {
							// If any error message is found in the bodyContent, set the status to 404
							status = 404
							break
						}
					}
				}
				
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


