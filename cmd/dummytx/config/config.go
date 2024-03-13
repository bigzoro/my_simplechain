package config

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	ChainId                  string   `json:"chain_id"`
	SipeAddr                 string   `json:"sipe_addr"`
	PrivateKey               string   `json:"private_key"`
	Cert                     string   `json:"cert"`
	CACerts                  []string `json:"ca_certs"`
	SenderPrivateKey         []string `json:"sender_private_key"`
	SenderPrivateKeyPassword []string `json:"sender_private_key_password"`
	Receiver                 string   `json:"receiver"`
	GasPriceLimit            int64    `json:"gas_price_limit"`
	GasPrice                 int64    `json:"gas_price"`
	DummyInternal            int64    `json:"dummy_internal"`
	Monitor                  bool     `json:"monitor"`
}

func LoadConfig(f string) *Config {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	config := Config{}
	if err = json.Unmarshal(raw, &config); err != nil {
		panic(err)
	}

	return &config
}
