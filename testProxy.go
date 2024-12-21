package main

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

func main() {
	proxyURL, _ := url.Parse("http://127.0.0.1:8081") // Burp Suite proxy
	httpTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		ForceAttemptHTTP2: false,
	}

	cookieJar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
		Jar:       cookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, _ := http.NewRequest("GET", "http://192.168.165.249:8000/CMS/", nil)
	httpClient.Do(req)
}
