package main

import (
	"context"
	"os"

	"github.com/flash-softeware/aos/initiator"
)

func main() {
	os.Exit(initiator.Run(context.Background(), os.Args[1:]))
}
