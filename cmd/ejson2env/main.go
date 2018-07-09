package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli"
)

// fail prints the error message to stderr, then ends execution.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %s\n", err)
	os.Exit(1)
}

// exportSecrets wraps the read, extract, and export steps. Returns
// an error if any step fails.
func exportSecrets(filename, keyDir, privateKey string) error {
	secrets, err := ReadSecrets(filename, keyDir, privateKey)
	if nil != err {
		return (fmt.Errorf("could not load ejson file: %s", err))
	}

	envValues, err := ExtractEnv(secrets)
	if nil != err {
		return fmt.Errorf("could not load environment from file: %s", err)
	}

	ExportEnv(os.Stdout, envValues)
	return nil
}

func main() {
	app := cli.NewApp()
	app.Usage = "get environment variables from ejson files"
	app.Version = VERSION
	app.Author = "Catherine Jones"
	app.Email = "catherine.jones@shopify.com"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "keydir, k",
			Value:  "/opt/ejson/keys",
			Usage:  "Directory containing EJSON keys",
			EnvVar: "EJSON_KEYDIR",
		},
		cli.BoolFlag{
			Name:  "key-from-stdin",
			Usage: "Read the private key from STDIN",
		},
	}

	app.Action = func(c *cli.Context) {
		var filename string

		keydir := c.String("keydir")

		var userSuppliedPrivateKey string
		if c.Bool("key-from-stdin") {
			var err error
			userSuppliedPrivateKey, err = readKey(os.Stdin)
			if err != nil {
				fail(fmt.Errorf("failed to read from stdin: %s", err))
			}
		}

		if 1 <= len(c.Args()) {
			filename = c.Args().Get(0)
		}

		if "" == filename {
			fail(fmt.Errorf("no secrets.ejson filename passed"))
		}

		if err := exportSecrets(filename, keydir, userSuppliedPrivateKey); nil != err {
			fail(err)
		}
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Unexpected failure:", err)
		os.Exit(1)
	}

}
