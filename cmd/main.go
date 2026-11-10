package main

import (
	"context"
	"fmt"
	"os"

	"github.com/flash-software-technology/aos/initiator"
)

func main() {
	// aos app runs one application's engine for its backend. It lives
	// here, not in initiator, because it builds on the embed package.
	if len(os.Args) > 1 && os.Args[1] == "app" {
		if err := runApp(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "aos app:", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(initiator.Run(context.Background(), os.Args[1:]))
}
