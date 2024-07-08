package ldaps

import (
	"errors"
	"log"
	"net"
	"runtime/debug"

	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) (res *ldap.SimpleBindResult, resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			// log.Printf("Recovered from panic in BindFn: %s\n%s", r, string(debug.Stack()))
			resultErr = fmt.Errorf("Bind function panic: %s at %s", r, string(debug.Stack()))
		}
	}()

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		log.Printf("Error reading LDAP version: %v", req.Children[0].Value)

		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading LDAP version: %v", req.Children[0].Value))
	}
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)

		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Only LDAP version 3 is supported: %v", ldapVersion))
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		log.Printf("Error reading bindDN: %v", req.Children[1].Value)

		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Only LDAP version 3 is supported: %v", ldapVersion))
	}

	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")

		return nil, ldap.NewError(ldap.LDAPResultInappropriateAuthentication, fmt.Errorf("Unknown LDAP authentication method: %v", bindAuth.Tag))

	case LDAPBindAuthSimple:
		if len(req.Children) != 3 {
			log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
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
		log.Print("SASL authentication is not supported")

		return nil, ldap.NewError(ldap.LDAPResultInappropriateAuthentication, errors.New("SASL authentication is not supported"))
	}
}
