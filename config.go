package main

type Config struct {
	HTTP struct {
		Addr string
		TLS  struct {
			Crt string
			Key string
		}
	}
	Presto struct {
		Addr string
	}
	LDAP struct {
		Addr         string
		Username     string
		Password     string
		SearchDN     string
		SearchFilter string
	}
}
