package ldaps

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestGetFilterAttribute(t *testing.T) {
	for _, testInfo := range []struct {
		Filter    string
		Attribute string
		Expected  string
	}{
		{
			Filter:    "(objectClass=*)",
			Attribute: "objectclass",
			Expected:  "",
		},
		{
			Filter:    "(objectClass=posixAccount)",
			Attribute: "objectClass",
			Expected:  "posixaccount",
		},
		{
			Filter:    "(&(cn=awesome)(objectClass=posixGroup))",
			Attribute: "objectClass",
			Expected:  "posixgroup",
		},
	} {
		value, err := GetFilterAttribute(testInfo.Filter, testInfo.Attribute)
		if err != nil {
			t.Errorf("GetFilterAttribute failed: %v", err)
		}
		if value != testInfo.Expected {
			t.Errorf("GetFilterAttribute: Expected %q got %q", testInfo.Expected, value)
		}
	}
}

func TestApplyFilter(t *testing.T) {
	for _, testInfo := range []struct {
		Filter   string
		Entry    *ldap.Entry
		Expected bool
	}{
		{
			Filter:   "(objectClass=*)",
			Entry:    ldap.NewEntry("cn=test,ou=users,dc=example,dc=org", map[string][]string{"objectclass": {"User"}}),
			Expected: true,
		},
		{
			Filter: "(memberOf=cn=*sers,ou=groups,dc=example,dc=org)",
			Entry: ldap.NewEntry("cn=test,ou=users,dc=example,dc=org", map[string][]string{
				"objectclass": {"User"},
				"memberOf":    {"cn=users,ou=groups,dc=example,dc=org"},
			}),
			Expected: true,
		},
		{
			Filter: "(memberOf=cn=*sers,ou=groups,dc=example,dc=org)",
			Entry: ldap.NewEntry("cn=test,ou=users,dc=example,dc=org", map[string][]string{
				"objectclass": {"User"},
				"memberOf":    {"cn=admins,ou=groups,dc=example,dc=org"},
			}),
			Expected: false,
		},
	} {
		berFilter, err := ldap.CompileFilter(testInfo.Filter)
		if err != nil {
			t.Errorf("Compiling the filter failed: %v", err)
		}
		matched, ldapResult := ApplyFilter(berFilter, testInfo.Entry)
		if matched != testInfo.Expected {
			status := "did not match"
			if matched {
				status = "matched"
			}
			t.Errorf("Entry: %v %s: %q return code: %s", testInfo.Entry, status, testInfo.Filter, ldap.LDAPResultCodeMap[ldapResult])
		}
	}
}
