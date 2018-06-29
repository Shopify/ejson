package main

import (
	"fmt"
	"io"
)

const (
	errNoEnv     = "environment is not set in ejson"
	errEnvNotMap = "environment is not a map[string]interface{}"
)

// ExtractEnv extracts the environment values from the map[string]interface{}
// containing all secrets, and returns a map[string]string containing the
// key value pairs. If there's an issue (the environment key doesn't exist, for
// example), returns an error.
func ExtractEnv(secrets map[string]interface{}) (map[string]string, error) {
	if nil == secrets["environment"] {
		err := fmt.Errorf(errNoEnv)
		return map[string]string{}, err
	}

	rawEnv, isMap := secrets["environment"].(map[string]interface{})
	if !isMap {
		err := fmt.Errorf(errEnvNotMap)
		return map[string]string{}, err
	}

	envSecrets := make(map[string]string, len(rawEnv))

	for key, rawValue := range rawEnv {
		value, isString := rawValue.(string)

		// Only export values that convert to strings properly.
		if isString {
			envSecrets[key] = value
		}
	}

	return envSecrets, nil
}

// ExportEnv writes the passed environment values to the passed
// io.Writer.
func ExportEnv(output io.Writer, values map[string]string) {
	for key, value := range values {
		fmt.Fprintf(output, "export %s=%s\n", key, value)
	}
}
