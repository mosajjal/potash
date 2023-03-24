package main

import (
	"github.com/mosajjal/potash/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
