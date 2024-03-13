package common

import (
	"github.com/bigzoro/my_simplechain/accounts/keystore"
	"io/ioutil"
	"strings"
)

func GetKey(filename, auth string) (*keystore.Key, error) {
	// Load the key from the keystore and decrypt its contents
	passwdByte, err := ioutil.ReadFile(auth)
	if err != nil {
		return nil, err
	}
	keyjson, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	passwd := strings.Trim(string(passwdByte), "\n")
	passwd = strings.Trim(passwd, "\t")
	passwd = strings.Trim(passwd, "\r")
	passwd = strings.Trim(passwd, " ")
	key, err := keystore.DecryptKey(keyjson, passwd)
	if err != nil {
		return nil, err
	}
	return key, nil
}
