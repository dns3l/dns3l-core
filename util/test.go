package util

import (
	"errors"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

func ConfigFromFileEnv(c interface{}) error {
	filename := os.Getenv("DNS3L_TEST_CONFIG")
	if filename == "" {
		return errors.New("no DNS3L_TEST_CONFIG env variable given")
	}
	return ConfigFromFile(c, filename)
}

func ConfigFromFile(c interface{}, filename string) error {
	filebytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return ConfigFromYamlBytes(c, filebytes)
}

func ConfigFromYamlBytes(c interface{}, bytes []byte) error {

	err := yaml.Unmarshal(bytes, c)
	if err != nil {
		return nil
	}
	return nil
}
