package main

import (
	"github.com/spf13/cobra"
	"log"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "kwatch",
	Short: "kwatch is an eBPF-powered kernel process monitor",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
