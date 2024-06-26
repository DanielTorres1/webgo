package webhacks

import (
	"crypto/md5"
	"encoding/hex"
	"crypto/tls"
	"compress/gzip"
	"bufio"
	"math/rand"
	"strconv"
	"unicode"
	"fmt"
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
)

type WebHacks struct {
	Debug       bool
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
	}

	// Select a User-Agent randomly.
	selectedUserAgent := userAgents[rand.Intn(len(userAgents))]
	//proxyURL, _ := url.Parse("http://127.0.0.1:8081") // burpsuite
	// Create a custom HTTP transport that ignores SSL certificate errors
	httpTransport := &http.Transport{
		//Proxy: http.ProxyURL(proxyURL), //burpsuite
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	// Create a cookie jar to handle cookies automatically
	cookieJar, _ := cookiejar.New(nil)

	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   time.Duration(timeoutInSeconds) * time.Second, // Set the timeout for individual requests
		Jar:       cookieJar, // Use the cookie jar
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirect {
				return http.ErrUseLastResponse // Stop after MaxRedirect
			}
			return nil // Allow the redirect
		},
	}

	wh := &WebHacks{
		Client:      httpClient,
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


func (wh *WebHacks) Dispatch(urlLine string, method string, postData string, headers http.Header) (*http.Response, error) {
	// Prepare the request
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest(method, urlLine, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, urlLine, nil)
		if err != nil {
			return nil, err
		}
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
	

// getRedirect extracts a redirect URL from the decoded HTML response.

func getRedirect(decodedResponse string) string {
	// Define patterns to search for redirect URLs
	
	patterns := []string{
		`meta http-equiv=["']Refresh["'] content=["']0; ?URL= ?['"](.*?)['"]`,
		`meta http-equiv=["']refresh["'] content=["']0; ?URL= ?['"](.*?)['"]`,
		`meta http-equiv=["']Refresh["'] content=["']1; ?URL= ?['"](.*?)['"]`,
		`meta http-equiv=["']refresh["'] content=["']1; ?URL= ?['"](.*?)['"]`,
		`window.onload=function\(\) urlLine ?= ?['"](.*?)['"]`,
		`window.location ?= ?['"](.*?)['"]`,
		`location.href ?= ?['"](.*?)['"]`,
		`window.location.href ?= ?['"](.*?)['"]`,
		`window.location ?= ?['"](.*?)['"]`,
		`top.location ?= ?['"](.*?)['"]`,
		`location.replace\(['"](.*?)['"]\)`,
		`location ?= ?['"](.*?)['"]`,
		`jumpUrl ?= ?['"](.*?)['"]`,
		`top.document.location.href ?= ?['"](.*?)['"]`,
		`http-equiv=["']refresh["'] content=["']0.1;urlLine=['"](.*?)['"]`,
		`parent.location ?= ?['"](.*?)['"]`,
		`redirect_suffix ?= ?['"](.*?)['"]`,
		`The document has moved ?<a href=['"](.*?)['"]`,
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

	// Return empty string if no redirect URL is found
	return ""
}


func checkVuln(decodedContent string) string {
	vuln := ""

	// if regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.16\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`).MatchString(decodedContent) {
	// 	vuln = "IPinterna"
	// }
	

	if regexp.MustCompile(`(?m)Lorem ipsum`).MatchString(decodedContent) {
		vuln = "contenidoPrueba"
	}

	if regexp.MustCompile(`(?i)DEBUG = True|app/controllers|SERVER_ADDR|REMOTE_ADDR|DOCUMENT_ROOT/|TimeoutException|vendor/laravel/framework/src/Illuminate|phpdebugbar`).MatchString(decodedContent) {
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

	re := regexp.MustCompile(`(?i)(undefined function|already sent by|Undefined offset|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Exception in thread|Exception information)`)
	match := re.FindStringSubmatch(decodedContent)

	// Si hay una coincidencia, imprimir el término que coincide
	if len(match) > 0 {
		fmt.Println("Término que coincide:", match[1])
		vuln = "MensajeError"
	}

	if regexp.MustCompile(`E_WARNING`).MatchString(decodedContent) { //mayuscula
		vuln = "MensajeError"
	}

	if regexp.MustCompile(`(?i)(Access denied for|r=usuario/create)`).MatchString(decodedContent) {
		vuln = "ExposicionUsuarios"
	}
	

	if regexp.MustCompile(`(?i)(?:^|[^a-z])(?:index of|directory of|Index of|Parent directory)(?:[^a-z]|$)`).MatchString(decodedContent) {
		vuln = "ListadoDirectorios"
	}

	if regexp.MustCompile(`(?i)HTTP_X_FORWARDED_HOST|HTTP_X_FORWARDED_SERVER\(\)`).MatchString(decodedContent) {
		vuln = "divulgacionInformacion"
	}

	decodedContentLower := strings.ToLower(decodedContent)
	
	pattern := `(?i)"password":|'password':|\&password=` //positivo
	matched, _ := regexp.MatchString(pattern, decodedContent)
	if matched {
		if !strings.Contains(decodedContentLower, `"password":$`) && //negativo comilla doble
			!strings.Contains(decodedContentLower, `password=**`) &&
			!strings.Contains(decodedContentLower, `"password":"password`) &&
			!strings.Contains(decodedContentLower, `"password=" + encodeuricomponent`) &&
			!strings.Contains(decodedContentLower, `"password":"clave`)&&
			!strings.Contains(decodedContentLower, `"password":"http`)&&
			!strings.Contains(decodedContentLower, `"password":"Contrase`)&&
			!strings.Contains(decodedContentLower, `"password":{required`) &&
			!strings.Contains(decodedContentLower, `"passwords":{"password`) &&
			!strings.Contains(decodedContentLower, `"password":{"enforced`) &&
			!strings.Contains(decodedContentLower, `"password":{"enabled`) &&
			!strings.Contains(decodedContentLower, `case "password":`)&&
			!strings.Contains(decodedContentLower, `tac@cisco.com`)&&
			!strings.Contains(decodedContentLower, `password=pass`)&&
			!strings.Contains(decodedContentLower, `password=trial`)&&
			!strings.Contains(decodedContentLower, `'password':{'enforced`) &&
			!strings.Contains(decodedContentLower, `'password':{'enabled`) &&
			!strings.Contains(decodedContentLower, `'passwords':{'password`) &&
			!strings.Contains(decodedContentLower, `'password':{required`) &&
			!strings.Contains(decodedContentLower, `'password':$`) && //negativo comilla simple
			!strings.Contains(decodedContentLower, `'password':'password`) &&
			!strings.Contains(decodedContentLower, `'password=' + encodeuricomponent`) &&
			!strings.Contains(decodedContentLower, `'password':'clave`) &&
			!strings.Contains(decodedContentLower, `'password':'http`)&&
			!strings.Contains(decodedContentLower, `'password':"Contrase`){
				
			vuln = "PasswordDetected"
		}
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
	path := wh.Path
	headers := wh.Headers

	if debug {
		color.Set(color.FgBlue, color.Bold)
		fmt.Printf("######### Testendo: %s ##################### \n\n", module)
		color.Unset()
	}

	
	var url string
	if rport == "80" || rport == "443" {
		url = fmt.Sprintf("%s://%s%s", proto, rhost, path)
	} else {
		url = fmt.Sprintf("%s://%s:%s%s", proto, rhost, rport, path)
	}

	if debug {
	
		fmt.Printf("user: %s \n", user)
		fmt.Printf("password: %s \n", password)
		fmt.Printf("passwordsFile: %s \n", passwordsFile)
		fmt.Printf("path: %s \n", path)
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
			resp, err := wh.Dispatch(url, "POST", postData, headers)
			
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

			resp, err := wh.Dispatch(url, "GET", "", headers)
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
			resp, err = wh.Dispatch(url, "POST", postData, headers)
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
				resp, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlan_basic_t1.gch", "GET", "", headers)
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

			resp, err := wh.Dispatch(url, "GET", "", headers)
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
			resp, err = wh.Dispatch(url, "POST", postData, headers)
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

				resp, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch", "GET", "", headers)
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

				resp, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch", "GET", "", headers)
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

			resp, err := wh.Dispatch(url, "GET", "", headers)
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
			resp, err = wh.Dispatch(url, "POST", postData, headers)
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

				resp, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch", "GET", "", headers)
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

				resp, err = wh.Dispatch(url+"getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch", "GET", "", headers)
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

			resp, err := wh.Dispatch(url+"csl/check", "POST", postData, headers)
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

			resp, err := wh.Dispatch(url+"login", "POST", postData, headers)
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
		_, err := wh.Dispatch(url , "GET", "", headers)
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
			resp, err := wh.Dispatch(url + "auth.owa", "POST", postData, headers)
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
			resp, err := wh.Dispatch(url, "GET", "", headers)
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

			resp, err = wh.Dispatch(url, "POST", postData, headers)
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

			resp, err := wh.Dispatch(url+"pentaho/j_spring_security_check", "POST", postData, headers)
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

			resp, err := wh.Dispatch(url+"/public/checklogin.htm", "POST", postData, headers)
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

			resp, err := wh.Dispatch(url, "GET", "", headers)
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
			if strings.Contains(strings.ToLower(decodedResponse), "navigation.php") || strings.Contains(strings.ToLower(decodedResponse), "logout.php") {
				fmt.Printf("[phpmyadmin] %s (Sistema sin password)\n", url)
				continue
			}

			tokenRegex := regexp.MustCompile(`name="token" value="(.*?)"`)
			matches := tokenRegex.FindStringSubmatch(decodedResponse)
			var token string
			if len(matches) >= 2 {
				token = matches[1]
			}

			if strings.Contains(strings.ToLower(decodedResponse), "respondiendo") ||
				strings.Contains(strings.ToLower(decodedResponse), "not responding") ||
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
			resp, err = wh.Dispatch(url+"index.php", "POST", postData, headers)
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

				resp, err = wh.Dispatch(newURL, "GET", "", headers)
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

			if !strings.Contains(decodedResponse, "pma_username") &&
				!strings.Contains(status, "403") &&
				!strings.Contains(strings.ToLower(decodedResponse), "cannot log in to the mysql server") &&
				!strings.Contains(strings.ToLower(decodedResponse), "can't connect to mysql server") &&
				!strings.Contains(strings.ToLower(decodedResponse), "1045 el servidor mysql") {
				fmt.Printf("Password encontrado: [phpmyadmin] %s Usuario:%s Password:%s\n", url, user, password)
				break
			}
		}

	}//phpmyadmin

	if module == "joomla" { //3.10
		resp, err := wh.Dispatch(url + "administrator/index.php", "GET", "", headers)
		if err != nil {
			fmt.Printf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		decodedResponse := string(body)		

		var csrf string
		tokenRegex := regexp.MustCompile(`"csrf.token":"(.*?)"`)
		matches := tokenRegex.FindStringSubmatch(decodedResponse)
		if len(matches) >= 2 {
			csrf = matches[1]
		}

		var ret string
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
			headers.Set("Referer", url + "/administrator/")
			headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			resp, err := wh.Dispatch(url + "administrator/index.php", "POST", postData, headers)
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

			title := ""
			re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
			titleMatch := re.FindStringSubmatch(decodedResponse)
			if len(titleMatch) > 1 {
				title = titleMatch[1]
			}

			fmt.Printf("[+] user:%s password:%s title:%s\n", user, password, title)

			if strings.Contains(title, "Control Panel") {
				fmt.Printf("Password encontrado: [joomla] %s (Usuario:%s Password:%s)\n", url, user, password)
				break
			}
		}
	}//joomla

}//passwordTest

func (wh *WebHacks) GetData(logFile string) (map[string]string, error) {
	debug := wh.Debug
	rhost := wh.Rhost
	rport := wh.Rport
	proto := wh.Proto
	path := wh.Path

	poweredBy := ""
	redirectURL := "no"
	var urlOriginal string
	if rport == "443" || rport == "80" {
	 	urlOriginal = proto + "://" + rhost + path
	 } else {
		urlOriginal = proto + "://" + rhost + ":" + rport + path
	}
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
			fmt.Printf("urlOriginal (%s)\n", urlOriginal)
			fmt.Printf("redirect_url en WHILE1 (%s)\n", redirectURL)
		}
		resp, err = wh.Dispatch(urlOriginal, "GET", "",  wh.Headers)
		if err != nil {			
			fmt.Printf("Error1 %s \n", err)
			if strings.Contains(err.Error(), "server gave") {
				// Handling protocol mismatch by switching protocol
				urlOriginal = proto + "://" + rhost  + path
				if debug {
					fmt.Printf("Error: %v. Switching protocol to: %s", err, proto)
				}
				continue
			}
		}
		lastURL = resp.Request.URL.String()
		StatusCode := resp.StatusCode
		if debug {
			fmt.Printf("status: (%s)\n", StatusCode)
		}
		

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

		body, _ := ioutil.ReadAll(bodyReader)
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
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 && responseLength > 700 {
			vulnerability = "Redirect with content|"
			//break
		}
		if debug {
			fmt.Printf("responseLength %d \n", responseLength)
		}
		//#####################################
		
		// Si la respuesta tiene 700 o mas, ya estamos en el destino 
		//fmt.Printf("decodedResponse (%s)\n", decodedResponse)
		if responseLength < 700 {
			redirectURL = getRedirect(decodedResponse)
			if debug {
				fmt.Printf("redirect_url (%s)\n", redirectURL)
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
	if decodedResponse != "" {
		vulnerability = vulnerability + checkVuln(decodedResponse)
	}
	
	
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


	if regexp.MustCompile(`(?i)Boa\/0.9`).MatchString(decodedHeaderResponse) {
		if title == "" {
			title = "Broadband device web server"
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


	if regexp.MustCompile(`(?i)You have logged out of the Cisco Router|Cisco RV340 Configuration Utility`).MatchString(decodedHeaderResponse) || regexp.MustCompile(`(?i)Cisco Unified Communications`).MatchString(decodedHeaderResponse) {
		server = "Cisco Router"
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


	

	// ############# powered by ##############
	re = regexp.MustCompile(`(?i)X-Powered-By:(.*?)\n`)
	poweredByMatch := re.FindStringSubmatch(decodedHeaderResponse)
	if len(poweredByMatch) > 1 {
		pwdby := poweredByMatch[1]
		//fmt.Printf("pwdby %s\n", pwdby)
		poweredBy += pwdby
	}

	if strings.Contains(decodedHeaderResponse, "laravel_session") || strings.Contains(decodedHeaderResponse, "Laravel Client") {
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

	if strings.Contains(decodedHeaderResponse, "<app-root>") {
        poweredBy += "|Angular"
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
	
	//fmt.Printf("decodedHeaderResponse: %s\n", decodedHeaderResponse)
    if regexp.MustCompile(`FortiGate|FortiGate for inclusion in the httpsd debug log`).MatchString(decodedHeaderResponse) {
        poweredBy += "|FortiGate"
        server = "FortiGate"
    }
    if regexp.MustCompile(`yii-debug-toolbar`).MatchString(decodedHeaderResponse) {
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
    if regexp.MustCompile(`csrfmiddlewaretoken`).MatchString(decodedHeaderResponse) {
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
        if title == "" {
            title = "Web Service"
        }
    }

	if regexp.MustCompile(`logoTyco`).MatchString(decodedHeaderResponse) {
        poweredBy += "|Tyco"
    }

    if regexp.MustCompile(`login__block__header`).MatchString(decodedHeaderResponse) {
        poweredBy += "|login"
        if title == "" {
            title = "Panel de logueo"
        }
    }

	
	if regexp.MustCompile(`(?i)waiting\.\.\.|ui_huawei_fw_ver|CertInstallFF`).MatchString(decodedHeaderResponse) {
		server = "Huawei"
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


	if regexp.MustCompile(`(?i)Huawei Technologies Co|HG8145V5|EG8145X6`).MatchString(decodedHeaderResponse) {
		
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
		if strings.Contains(urlFile, "folders") {
			urlLine += "/"
		}
		
		//adicionar puerto solo si es diferente a 80 o 443
		 portStr := ""
		 if rport != "80" && rport != "443" {
		 	portStr = ":" + rport
		 }

		urlFinal := proto + "://" + rhost  + portStr + path + urlLine

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
				resp, err := wh.Dispatch(urlLine, "GET", "", headers)
				if err != nil {
					fmt.Printf("Failed to get URL %s: %v\n", urlLine, err)
					continue
				}
				defer resp.Body.Close()

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
				current_status := resp.StatusCode
				bodyContent := string(bodyBytes)
				//fmt.Printf("%s \n", bodyContent)
				//check if return a custom 404 error but 200 OK
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
							current_status = 404
							break
						}
					}
				}

				//fmt.Printf(" %s\n", bodyContent)
				//time.Sleep(5 * time.Second)
				if current_status == 200 && bodyContent == "" {
					current_status = 404
				}

				if strings.Contains(bodyContent, "Request Rejected") || strings.Contains(bodyContent, "ENTEL S.A."  )  {
					current_status = 404
				}
				
				
				if (show404 && current_status == 404) || current_status != 404 {
					vuln := ""
					if  current_status == 200 {
						vuln = checkVuln(bodyContent)
					}

					errors := []string{
						"Your access is denied",
						"error al procesar esta solicitud",
						"&enckey=",
						"This is the default text for a report",
						"Unauthorized Request Blocked",
						"Undefined offset",
					}
					
					if containsAny(bodyContent, errors) {
						current_status = 404
					}
					
					if vuln != "" {
						fmt.Printf("%d | %s (vulnerabilidad=%s) | %d\n", current_status, urlLine, vuln, len(bodyContent))
					} else {
						fmt.Printf("%d | %s | %d\n", current_status, urlLine, len(bodyContent))
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


// only HEAD requests
func (wh *WebHacks) BackupBuster(urlFile string) {

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
		fmt.Printf("Configuracion: Hilos:%s  proto:%s  Ajax: %s error404:%s show404 %s timeout %s debug %s MaxRedirect %s \n\n", threads, proto, ajax, error404, show404,timeout, debug, MaxRedirect)
	}

	/////// test
	//adicionar puerto solo si es diferente a 80 o 443
	portStr := ""
	if rport != "80" && rport != "443" {
		portStr = ":" + rport
	}

    urlTest := proto + "://" + rhost  + portStr + path + "non-extisss.rar"

	resp_test, err_test := wh.Dispatch(urlTest, "HEAD", "", headers)
	if err_test != nil {
		fmt.Printf("Failed to get URL %s: %v\n", urlTest, err_test)
	}
	status_test := resp_test.StatusCode
				
	if (status_test == 200 ) {
		fmt.Printf("OK 200 to anything")
		return
	}
	////////////////////////

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

		//adicionar puerto solo si es diferente a 80 o 443
		 if rport != "80" && rport != "443" {
		 	portStr = ":" + rport
		 }

		urlFinal := proto + "://" + rhost  + portStr + path + urlLine
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
				resp, err := wh.Dispatch(urlLine, "HEAD", "", headers)
				if err != nil {
					fmt.Printf("Failed to get URL %s: %v\n", urlLine, err)
					continue
				}
				defer resp.Body.Close()
				current_status := resp.StatusCode
				
				if (show404 && current_status == 404) || current_status != 404 {

					fmt.Printf("%d | %s \n", current_status, urlLine)
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

func (wh *WebHacks) ConfigBuster(urlFile string) {
	headers := wh.Headers
	debug := wh.Debug
	show404 := wh.Show404
	error404 := wh.Error404
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
				resp, err := wh.Dispatch(finalURL, "GET", "", headers)
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


