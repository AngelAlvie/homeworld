package main

import (
	"log"
	"os"

	"github.com/sipb/homeworld/platform/keysystem/keyserver/keyapi"
)

func main() {
	logger := log.New(os.Stderr, "[keyserver] ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	_, onstop, err := keyapi.Run(":20557", logger)
	if err != nil {
		logger.Fatal(err)
	} else {
		logger.Fatal(<-onstop)
	}
}
