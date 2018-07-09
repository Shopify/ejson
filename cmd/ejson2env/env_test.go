package main

import (
	"bytes"
	"testing"
)

const TestKeyValue = "2ed65dd6a16eab833cc4d2a860baa60042da34a58ac43855e8554ca87a5e557d"

func TestLoadSecrets(t *testing.T) {

	rawValues, err := ReadSecrets("test.ejson", "./key", TestKeyValue)
	if nil != err {
		t.Fatal(err)
	}

	envValues, err := ExtractEnv(rawValues)
	if nil != err {
		t.Fatal(err)
	}

	if "test_value" != envValues["test_key"] {
		t.Error("Failed to decrypt")
	}

	var buf bytes.Buffer

	ExportEnv(&buf, envValues)

	if "export test_key=test_value\n" != buf.String() {
		t.Errorf("generated invalid export code: \n---\n%s\n---", buf.String())
	}

}

func TestInvalidEnvironments(t *testing.T) {
	testGood := map[string]interface{}{
		"environment": map[string]interface{}{
			"test_key": "test_value",
		},
	}

	testBad := map[string]interface{}{
		"environment": "bad",
	}

	var testNoEnv map[string]interface{}

	_, err := ExtractEnv(testBad)
	if nil == err {
		t.Errorf("no error when passed a non-map environment")
	} else if errEnvNotMap != err {
		t.Errorf("wrong error when passed a non-map environment: %s", err)
	}

	_, err = ExtractEnv(testNoEnv)
	if nil == err {
		t.Errorf("no error when passed a non-existiant environment")
	} else if errNoEnv != err {
		t.Errorf("wrong error when passed a non-existiant environment: %s", err)
	}

	_, err = ExtractEnv(testGood)
	if nil != err {
		t.Errorf("error when passed correctly formatted environment: %s", err)
	}

}
