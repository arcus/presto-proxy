package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/ldap.v2"
)

var (
	ErrUserDoesNotExist   = errors.New("user does not exist")
	ErrMultipleUsersExist = errors.New("multiple users exist")
)

func init() {
	ldap.DefaultTimeout = 3 * time.Second
}

// ldapBackend satisfies the authenticator interface for LDAP-based authentication.
type ldapBackend struct {
	Address      string `json:"address"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	SearchDN     string `json:"searchdn"`
	SearchFilter string `json:"searchfilter"`
}

// Ping ensures a connection can be opened and the bind username and password work.
func (a *ldapBackend) Ping() error {
	conn, err := ldap.Dial("tcp", a.Address)
	if err != nil {
		return err
	}
	defer conn.Close()

	err = conn.Bind(a.Username, a.Password)
	if err != nil {
		return err
	}

	return nil
}

func (a *ldapBackend) Authenticate(cxt context.Context, username, password string) (bool, error) {
	// Open connection.
	conn, err := ldap.Dial("tcp", a.Address)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	err = conn.Bind(a.Username, a.Password)
	if err != nil {
		return false, err
	}

	req := ldap.NewSearchRequest(
		a.SearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(a.SearchFilter, username),
		nil,
		nil,
	)

	// Lookup the user.
	resp, err := conn.Search(req)
	if err != nil {
		return false, err
	}

	// Ensure there is only one user.
	switch len(resp.Entries) {
	case 0:
		return false, ErrUserDoesNotExist

	case 1:
		break

	default:
		return false, ErrMultipleUsersExist
	}

	// Bind the user and verify their password.
	dn := resp.Entries[0].DN

	err = conn.Bind(dn, password)
	// Success.
	if err == nil {
		return true, nil
	}

	// Invalid credentials is not an error.
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return false, nil
	}

	return false, err
}
