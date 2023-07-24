package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/urfave/cli"
)

func execManpage(sec, page string) {
	if err := syscall.Exec("/usr/bin/env", []string{"/usr/bin/env", "man", sec, page}, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "Exec error:", err)
	}
	os.Exit(1)
}

func main() {
	// Encryption is expensive. We'd rather burn cycles on many cores than wait.
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "keydir, k",
			Value:  "/opt/ejson/keys",
			Usage:  "Directory containing EJSON keys",
			EnvVar: "EJSON_KEYDIR",
		},
	}
	app.Usage = "manage encrypted secrets using public key encryption"
	app.Version = VERSION
	app.Author = "Burke Libbey"
	app.Email = "burke.libbey@shopify.com"
	app.Commands = []cli.Command{
		{
			Name:      "encrypt",
			ShortName: "e",
			Usage:     "(re-)encrypt one or more EJSON files",
			Action: func(c *cli.Context) {
				if err := encryptAction(c.Args()); err != nil {
					fmt.Fprintln(os.Stderr, "Encryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:      "decrypt",
			ShortName: "d",
			Usage:     "decrypt an EJSON file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "o",
					Usage: "print output to the provided file, rather than stdout",
				},
				cli.BoolFlag{
					Name:  "key-from-stdin",
					Usage: "Read the private key from STDIN",
				},
			},
			Action: func(c *cli.Context) {
				var userSuppliedPrivateKey string
				if c.Bool("key-from-stdin") {
					stdinContent, err := ioutil.ReadAll(os.Stdin)
					if err != nil {
						fmt.Fprintln(os.Stderr, "Failed to read from stdin:", err)
						os.Exit(1)
					}
					userSuppliedPrivateKey = strings.TrimSpace(string(stdinContent))
				}
				if err := decryptAction(c.Args(), c.GlobalString("keydir"), userSuppliedPrivateKey, c.String("o")); err != nil {
					fmt.Fprintln(os.Stderr, "Decryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:      "keygen",
			ShortName: "g",
			Usage:     "generate a new EJSON keypair",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "write, w",
					Usage: "rather than printing both keys, print the public and write the private into the keydir",
				},
			},
			Action: func(c *cli.Context) {
				if err := keygenAction(c.Args(), c.GlobalString("keydir"), c.Bool("write")); err != nil {
					fmt.Fprintln(os.Stderr, "Key generation failed:", err)
					os.Exit(1)
				}
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Unexpected failure:", err)
		os.Exit(1)
	}
}
