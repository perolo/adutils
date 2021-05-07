package main

import (
	"flag"
	"github.com/perolo/ad-utils/syncadgroup"
)

func main() {
	propPtr := flag.String("prop", "confluence.properties", "a properties file")

	syncadgroup.AdSyncAdGroup(*propPtr)
}
