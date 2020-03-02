package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"gopkg.in/ldap.v2"
)

func init() {
	ldap.DefaultTimeout = 10 * time.Second
}

// ldapBackend satisfies the authenticator interface for LDAP-based authentication.
type ldapBackend struct {
	Address   string `json:"address"`
	TLSConfig *tls.Config
}

// Ping ensures a connection can be opened and the bind username and password work.
func (a *ldapBackend) Ping() error {
	conn, err := ldap.DialTLS("tcp", a.Address, a.TLSConfig)
	if err != nil {
		return fmt.Errorf("ping/connect: %s", err)
	}
	defer conn.Close()
	return nil
}

func (a *ldapBackend) Authenticate(cxt context.Context, username, password string) (bool, error) {
	// Open connection.
	conn, err := ldap.DialTLS("tcp", a.Address, a.TLSConfig)
	if err != nil {
		return false, fmt.Errorf("authenticate/connect: %s", err)
	}
	defer conn.Close()

	err = conn.Bind(fmt.Sprintf("%s@chop.edu", username), password)
	// Success.
	if err == nil {
		return true, nil
	}

	// Invalid credentials is not an error.
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return false, nil
	}

	return false, fmt.Errorf("authenticate: %s", err)
}
