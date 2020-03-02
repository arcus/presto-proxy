package main

import "time"

type Config struct {
	HTTP struct {
		Bind      string
		Advertise string
		TLS       struct {
			Crt string
			Key string
		}
	}
	Presto struct {
		Addr string
	}
	LDAP struct {
		Addr    string
		Timeout time.Duration
		TLS     struct {
			CA         string `json:"ca" yaml:"ca"`
			SkipVerify bool   `json:"skipverify" yaml:"skipverify"`
		}
	}
}
