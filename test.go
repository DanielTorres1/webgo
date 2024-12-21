package main

import (
	"context"              // For context.Context in the dialer
	"crypto/tls"           // For TLS configuration
	"fmt"                  // For formatted I/O
	"net"                  // For network connections
	"net/http"             // For HTTP client
	"golang.org/x/net/proxy" // For SOCKS5 proxy
)
func main() {
    // Create a SOCKS5 proxy dialer
    dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
    if err != nil {
        panic("Error creating SOCKS5 proxy dialer: " + err.Error())
    }

    // Create a custom dialer for the HTTP transport
    dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
        return dialer.Dial(network, addr)
    }

    httpTransport := &http.Transport{
        //DialContext:       dialContext,
        TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
        ForceAttemptHTTP2: false,
    }

    client := &http.Client{Transport: httpTransport}

    // Test the client
    resp, err := client.Get("http://192.168.56.10")
    if err != nil {
        panic("Request failed: " + err.Error())
    }
    defer resp.Body.Close()

    // Process response
    fmt.Println("Response status:", resp.Status)
}
