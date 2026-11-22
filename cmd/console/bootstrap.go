package main

import (
	"fmt"
	"os"
	"strings"
)

// seedAccounts creates deployment accounts from the environment, so a public
// console can run with self-registration off and no manual first-run step:
//
//	ASI_ADMIN_LOGIN  + ASI_ADMIN_PASSWORD_FILE (or ASI_ADMIN_PASSWORD)   -> role admin
//	ASI_VIEWER_LOGIN + ASI_VIEWER_PASSWORD_FILE (or ASI_VIEWER_PASSWORD) -> role viewer (read-only)
//
// It is idempotent: an existing account is left untouched (passwords are never
// reset by a restart), so changes made in the UI survive.
func seedAccounts(a *auth) error {
	for _, acc := range []struct{ prefix, name, role string }{
		{"ASI_ADMIN", "Administrator", "admin"},
		{"ASI_VIEWER", "Viewer (read-only)", "viewer"},
	} {
		login := strings.TrimSpace(os.Getenv(acc.prefix + "_LOGIN"))
		if login == "" {
			continue
		}
		pw := os.Getenv(acc.prefix + "_PASSWORD")
		if f := os.Getenv(acc.prefix + "_PASSWORD_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("%s_PASSWORD_FILE: %w", acc.prefix, err)
			}
			pw = strings.TrimSpace(string(b))
		}
		if pw == "" {
			return fmt.Errorf("%s_LOGIN set but no %s_PASSWORD_FILE / %s_PASSWORD", acc.prefix, acc.prefix, acc.prefix)
		}
		if a.roleOf(login) != "" {
			continue
		}
		if _, err := a.create(login, acc.name, pw, acc.role); err != nil {
			return fmt.Errorf("%s: %w", acc.prefix, err)
		}
	}
	return nil
}
