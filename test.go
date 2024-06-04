package main

import (
	"fmt"
	"regexp"
)

func main() {
	decodedHeaderResponse := "window.RS_MODULES.waiting...= window."
	server := ""

	if regexp.MustCompile(`(?i)waiting\.\.\.`).MatchString(decodedHeaderResponse) {
		server = "Huawei"
	}

	fmt.Println("Server:", server)
}
