package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// showUsage prints the usage message and the defaults to standard error.
func showUsage(output io.Writer) {
	flag.CommandLine.SetOutput(output)
	fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [-keydir path] [-key-from-stdin] file.ejson\n\n", os.Args[0])
	flag.CommandLine.PrintDefaults()
}

// failAndShowUsage prints the error message to stderr, followed
// by the usage information, before exiting with an error code.
func failAndShowUsage(err error) {
	fmt.Fprintf(os.Stderr, "%s\n\n", err)
	showUsage(os.Stderr)
	os.Exit(1)
}

// fail prints the error message to stderr, then ends execution.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

func main() {
	var filename string
	var keydir string
	var fromStdin bool
	var showHelp bool

	var err error

	flag.BoolVar(&showHelp, "help", false, "Show this usage message")
	flag.BoolVar(&fromStdin, "key-from-stdin", false, "Read the private key from STDIN")
	flag.StringVar(&keydir, "keydir", "/opt/ejson/keys", "Directory containing EJSON keys")

	flag.Parse()

	if showHelp {
		showUsage(os.Stdout)
		os.Exit(0)
	}

	if 1 <= flag.NArg() {
		filename = flag.Arg(0)
	}

	if "" == filename {
		failAndShowUsage(fmt.Errorf("no secrets.ejson filename passed"))
	}

	var userSuppliedPrivateKey string
	if fromStdin {
		userSuppliedPrivateKey, err = readKey(os.Stdin)
		if err != nil {
			fail(fmt.Errorf("failed to read from stdin: %s", err))
		}
	}

	secrets, err := ReadSecrets(filename, keydir, userSuppliedPrivateKey)
	if nil != err {
		fail(fmt.Errorf("could not load ejson file: %s", err))
	}

	envValues, err := ExtractEnv(secrets)
	if nil != err {
		fail(fmt.Errorf("could not load environment from file: %s", err))
	}

	ExportEnv(os.Stdout, envValues)
}
