package main

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
		Addr string
	}
}
