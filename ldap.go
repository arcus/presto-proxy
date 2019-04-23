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

	conn *ldap.Conn
}

func (a *ldapBackend) Dial() error {
	conn, err := ldap.Dial("tcp", a.Address)
	if err != nil {
		return err
	}

	err = conn.Bind(a.Username, a.Password)
	if err != nil {
		return err
	}

	a.conn = conn
	return nil
}

func (a *ldapBackend) Close() error {
	if a.conn != nil {
		a.conn.Close()
	}
	return nil
}

func (a *ldapBackend) Authenticate(cxt context.Context, username, password string) (bool, error) {
	// Re-bind with the search creds.
	err := a.conn.Bind(a.Username, a.Password)
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
	resp, err := a.conn.Search(req)
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

	err = a.conn.Bind(dn, password)
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
