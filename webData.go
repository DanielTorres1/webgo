package main

import (
	"flag"
	"fmt"
	"strings"
	"regexp"
	"os"
	"gotest/goweb/webhacks"
)

func main() {
	var target, port, path, proto, logFile string
	var maxRedirect, timeout int
	var debug bool

	flag.StringVar(&target, "target", "", "IP or domain of the web server")
	flag.StringVar(&port, "port", "80", "Port of the web server")
	flag.StringVar(&path, "path", "/", "Path")
	flag.IntVar(&maxRedirect, "maxRedirect", 2, "Max redirects")
	flag.StringVar(&logFile, "logFile", "", "log file")
	flag.StringVar(&proto, "proto", "http", "Protocol (http/https)")
	flag.BoolVar(&debug, "debug", false, "debug (true=true, false=false)")
	flag.IntVar(&timeout, "timeout", 5, "Timeout")
	flag.Parse()

	if target == "" {
		fmt.Println("Usage:")
		fmt.Println("-target : IP or domain of the web server")
		fmt.Println("-port : Web server port")
		fmt.Println("-path : Path to start testing directories")
		fmt.Println("-log : File to write logs")
		fmt.Println("-timeout : ")
		fmt.Println("-redirects : How many redirects to follow")
		fmt.Println("-proto : http/https")
		fmt.Println("\nAuthor: Daniel Torres Sandi")
		fmt.Println("Example 1: webData -target ejemplo.com -port 80 -directory / -log log.txt")
		fmt.Println("Example 2: webData -target 192.168.0.2 -port 80 -directory /phpmyadmin/ -log log.txt -redirects 4")
		os.Exit(1)
	}

	webHacks := webhacks.NewWebHacks(timeout,maxRedirect)

	// Configure webHacks based on flags
	webHacks.Proto = proto
	webHacks.Rhost = target
	webHacks.Rport = port
	webHacks.Path = path
	webHacks.Debug = debug
	
	data, err := webHacks.GetData(logFile)
	if err != nil {
		// Handle error
		return
	}

	title := data["title"]
	server := data["server"]
	status := data["status"]
	redirectURL := data["redirect_url"]
	lastURL := data["last_url"]
	newDomain := data["newdomain"]
	vulnerability := data["vulnerability"]
	poweredBy := data["poweredBy"]

	if len(vulnerability) > 1 {
		vulnerability = "vulnerabilidad=" + vulnerability
	}

	if strings.Contains(status, "Name or service not known") {
		re := regexp.MustCompile(`Can't connect to (.*?):`)
		matches := re.FindStringSubmatch(status)
		if len(matches) > 1 {
			newDomain = matches[1]
		}
	}

	if newDomain != "" {
		fmt.Printf("%s~%s~%s~%s~%s~%s~%s~^Dominio identificado^%s\n", title, server, status, redirectURL, lastURL, poweredBy, vulnerability, newDomain)
	} else {
		fmt.Printf("%s~%s~%s~%s~%s~%s~%s\n", title, server, status, redirectURL, lastURL, poweredBy, vulnerability)
	}

}
