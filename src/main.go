package main

import (
	"flag"
	"iptables-api/config"
	"iptables-api/server"
	"log"
)

var (
	savePath *string
)

func main() {

	environment := flag.String("e", "dev", "env file")
	flag.Parse()

	config.Init(*environment)

	listenIP := flag.String("ip", config.GetHost(), "listen on IP")
	listenPort := flag.String("port", config.GetPort(), "listen on port")
	savePath = flag.String("savepath", "/var/backups/iptables-api/", "path for backups file on /save")

	flag.Parse()

	err := server.Init(*listenIP, *listenPort, *savePath)
	if err != nil {
		log.Fatal(err)
	}
}
