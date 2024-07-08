package ldaps

import (
	"errors"
	"net"
	"runtime/debug"

	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) (res *ldap.SimpleBindResult, resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			resultErr = fmt.Errorf("Bind function panic: %s at %s", r, string(debug.Stack()))
		}
	}()

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading LDAP version: %v", req.Children[0].Value))
	}
	if ldapVersion != 3 {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Unsupported LDAP version: %d. Please use version 3", ldapVersion))
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading bindDN: %v", req.Children[1].Value))
	}

	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		return nil, ldap.NewError(ldap.LDAPResultInappropriateAuthentication, fmt.Errorf("Unknown LDAP authentication method: %v", bindAuth.Tag))

	case LDAPBindAuthSimple:
		if len(req.Children) != 3 {
			return nil, ldap.NewError(ldap.LDAPResultInappropriateAuthentication, fmt.Errorf("Simple bind request has %v packets, expected 3", len(req.Children)))
		}
		fnNames := []string{}
		for k := range fns {
			fnNames = append(fnNames, k)
		}

		fn := routeFunc(bindDN, fnNames)

		ret, err := fns[fn].Bind(bindDN, bindAuth.Data.String(), conn)

		return ret, err

	case LDAPBindAuthSASL:
		return nil, ldap.NewError(ldap.LDAPResultInappropriateAuthentication, errors.New("SASL authentication is not supported"))
	}
}
