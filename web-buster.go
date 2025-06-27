// inicializar proyecto
// go mod init gotest/goweb

// instalar libreria
// cd goweb/webhacks
// go build

// adds missing module requirements for imported packages
// cd goweb/
// go mod tidy

// Instalar
// go build web-tester.go
package main

import (
	"flag"
	"fmt"
	"os"
	"gotest/goweb/webhacks"
)

func main() {
	var target, port, path, cookie, customDir, proto, mode, error404 string
	var maxRedirect, threads, timeout int
	var show404, debug, ajax, filter bool

	flag.StringVar(&target, "target", "", "IP or domain of the web server")
	flag.StringVar(&port, "port", "80", "Port of the web server")
	flag.StringVar(&path, "path", "/", "Path")
	flag.IntVar(&maxRedirect, "redirects", 0, "Max redirects")
	flag.StringVar(&cookie, "cookie", "", "Cookie")
	flag.StringVar(&customDir, "customDir", "", "Custom directory") 
	flag.StringVar(&proto, "proto", "http", "Protocol (http/https)")
	flag.BoolVar(&show404, "show404", false, "Show all 404 errors")
	flag.BoolVar(&ajax, "ajax", false, "AJAX (true=true, false=false)")
	flag.StringVar(&mode, "module", "", "Mode")
	flag.IntVar(&threads, "threads", 1, "Threads")
	flag.IntVar(&timeout, "timeout", 15, "Timeout")
	flag.StringVar(&error404, "error404", "", "Error 404 custom message") 
	flag.BoolVar(&debug, "debug", false, "debug (true=true, false=false)")
	flag.BoolVar(&filter, "filter", false, "filter (true=true, false=false)")
	flag.Parse()

	if target == "" {
		fmt.Println("-target : IP o dominio del servidor web")
		fmt.Println("-port : Puerto del servidor web")
		fmt.Println("-redirects : Seguir n redirecciones")
		fmt.Println("-custom : Directorio personalizado")
		fmt.Println("-timeout : Time out (segundos)")
		fmt.Println("-path : Ruta donde empezará a probar directorios")
		fmt.Println("-ajax : Adicionar header ajax (xmlhttprequest) 1 para habilitar")
		fmt.Println("-threads : Número de hilos (Conexiones en paralelo)")
		fmt.Println("-cookie : cookie con la que hacer el escaneo ej: PHPSESSION=k35234325")
		fmt.Println("-error404 : Busca este patrón en la respuesta para determinar si es una página de error 404")
		fmt.Println("-show404 : mostrar errores 404")
		fmt.Println("-filter : Do not show reapeated response with same lenght")
		fmt.Println("-module : Modo. Puede ser:")
		fmt.Println("    folders: Probar si existen directorios comunes")
		fmt.Println("    files: Probar si existen directorios comunes")
		fmt.Println("    cgi: Probar si existen archivos cgi")
		fmt.Println("    graphQL: Probar si existe un endpoint de graphQL")
		fmt.Println("    php: Probar si existen archivos php")
		fmt.Println("    webservices: Directorios webservices")
		fmt.Println("    archivosPeligrosos: Archivos peligrosos")
		fmt.Println("    default: Archivos por defecto")
		fmt.Println("    information: php info files, error logs")
		fmt.Println("    webserver: Probar si existen archivos propios de un servidor web (server-status, access_log, etc)")
		fmt.Println("    backup: Busca backups de archivos de configuracion comunes (Drupal, wordpress, IIS, etc)")
		fmt.Println("    apacheServer: Probará Todos los módulos de Apache")
		fmt.Println("    tomcatServer: Probará Todos los módulos de Tomcat")
		fmt.Println("    iisServer: Probará Todos los módulos de IIS")
		fmt.Println()
		fmt.Println("Ejemplo 1: Buscar archivos comunes en el directorio raíz (/) del host 192.168.0.2 en el puerto 80 con 10 hilos")
		fmt.Println("    web-buster -r 1 -t 192.168.0.2 -p 80 -d / -m archivos -h 10")
		fmt.Println()
		fmt.Println("Ejemplo 2: Buscar backups de archivos de configuracion en el directorio /wordpress/ del host 192.168.0.2 en el puerto 443 (SSL)")
		fmt.Println("    web-buster -r 1 -t 192.168.0.2 -p 443 -d /wordpress/ -m backup -s https -h 30")
		fmt.Println()
		fmt.Println("Ejemplo 3: Buscar archivos/directorios del host 192.168.0.2 (apache) en el puerto 443 (SSL)")
		fmt.Println("    web-buster -r 1 -t 192.168.0.2 -p 443 -d / -m apache -s https -h 30")
		fmt.Println()
		os.Exit(1)
	}

	webHacks := webhacks.NewWebHacks(timeout,maxRedirect)

	// Configure webHacks based on flags
	webHacks.Rhost = target
	webHacks.Rport = port
	webHacks.Path = path
	webHacks.Cookie = cookie
	webHacks.Proto = proto
	webHacks.Threads = threads
	webHacks.Ajax = ajax
	webHacks.Show404 = show404
	webHacks.Error404 = error404
	webHacks.Debug = debug
	webHacks.Filter = filter
	

	switch mode {
	case "backups":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/backups.txt","")
	case "api":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/api.txt", "")
	case "admin":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/admin.txt", "")
	case "adminCMS":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/adminCMS.txt", "")
	case "archivosPeligrosos":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt", "")
	case "sap":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/sap.txt", "")
    case "folders":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/folders.txt", "")
	case "folders-short":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/folders-short.txt", "")
		
    case "cgi":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/cgi.txt", "")
    case "webserver":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/webserver.txt", "")
    case "webservices":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/webservices.txt", "")
    case "backdoorApache":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/backdoorsApache.txt", "")
    case "backdoorIIS":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/backdoorsIIS.txt", "")
	case "information":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/divulgacionInformacion.txt", "")
	case "iis":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/iis.txt", "")
	case "sharepoint":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/sharepoint.txt", "")
	case "tomcat":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/tomcat.txt", "")
	case "custom":
        webHacks.Dirbuster(customDir, "")
	case "default":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/archivosDefecto.txt", "")
	//fuzz with files (with extension)
	case "php":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt", "php")

	case "files-intranet":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/files-intranet.txt", "php")		
	case "aspx":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt", "aspx")
	case "jsp":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt", "jsp")
	
	case "apacheServer":
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/graphQL.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/admin.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/registroHabilitado.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/folders.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/cgi.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/webserver.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/backdoorsApache.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","php")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","html")

	case "iisServer":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/admin.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/registroHabilitado.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/folders.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/webserver.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/backdoorsIIS.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/sharepoint.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/webservices.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","asp")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","aspx")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","html")
	case "configApache":
		webHacks.ConfigBuster("/usr/share/webhacks/wordlist/configFilesApache.txt")
	case "configIIS":
		webHacks.ConfigBuster("/usr/share/webhacks/wordlist/configFilesIIS.txt")
	case "tomcatServer":
        webHacks.Dirbuster("/usr/share/webhacks/wordlist/admin.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/archivosPeligrosos.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/folders.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/webserver.txt", "")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","jsp")
		webHacks.Dirbuster("/usr/share/webhacks/wordlist/filesEXT.txt","html")
	default:
		fmt.Println("Unknown mode")
	}

}
