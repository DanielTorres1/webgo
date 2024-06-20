package main

import (
	"flag"
	"fmt"
	"os"
	"gotest/goweb/webhacks"
)

func main() {
	var target, port, path, proto, module, user, password, passfile string
	var maxRedirect, timeout int
	var debug bool

	flag.StringVar(&proto, "proto", "http", "Protocol (http/https)")
	flag.StringVar(&target, "target", "", "IP or domain of the web server")
	flag.StringVar(&port, "port", "80", "Port of the web server")
	flag.StringVar(&path, "path", "/", "Path")
	flag.StringVar(&module, "module", "", "module")
	flag.StringVar(&user, "user", "admin", "user")
	flag.StringVar(&password, "password", "", "single password")
	flag.StringVar(&passfile, "passfile", "", "Password list")
	flag.BoolVar(&debug, "debug", false, "debug (true=true, false=false)")
	flag.IntVar(&timeout, "timeout", 15, "Timeout")
	flag.Parse()

	if target == "" {
		fmt.Println("Usage:")
		fmt.Println("-proto : http/https")
		fmt.Println("-target : IP or domain of the web server")
		fmt.Println("-port : Web server port")
		fmt.Println("-path : Path to start testing directories")
		fmt.Println("-module : module to use")
		fmt.Println("-user : user to hack")
		fmt.Println("-passfile : user to hack")
		fmt.Println("-timeout : ")
		fmt.Println("-redirects : How many redirects to follow")
		fmt.Println("\nAuthor: Daniel Torres Sandi")
		fmt.Println("Example 1: passWeb -proto http -target 192.168.0.2 -port 80 -path / -module ZKSoftware -user administrator -passfile passwords.txt")
		fmt.Println("Example 2: passWeb -proto https -target 192.168.0.2 -port 443 -path /admin/ -module phpmyadmin -user root -passfile passwords.txt")
		fmt.Println("Example 3: passWeb -proto http -target 192.168.0.2 -port 80 -path / -module ZTE-ONT-4G -user admin -password admin")

		
		os.Exit(1)
	}

	maxRedirect = 4
	webHacks := webhacks.NewWebHacks(timeout,maxRedirect)

	// Configure webHacks based on flags
	webHacks.Proto = proto
	webHacks.Rhost = target
	webHacks.Rport = port
	webHacks.Path = path
	webHacks.Debug = debug

	
	options := map[string]string{
		"module":         module,
		"user":           user,
		"password":       password,
		"passwords_file": passfile,
	}

	webHacks.PasswordTest(options)
}
