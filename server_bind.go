package ldaps

import (
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) (resultCode uint16) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = ldap.LDAPResultOperationsError
		}
	}()

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		log.Printf("Error reading LDAP version: %v", req.Children[0].Value)

		return ldap.LDAPResultProtocolError
	}
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)

		return ldap.LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		log.Printf("Error reading bindDN: %v", req.Children[1].Value)

		return ldap.LDAPResultProtocolError
	}

	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")

		return ldap.LDAPResultInappropriateAuthentication

	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			fnNames := []string{}
			for k := range fns {
				fnNames = append(fnNames, k)
			}

			fn := routeFunc(bindDN, fnNames)

			resultCode, err := fns[fn].Bind(bindDN, bindAuth.Data.String(), conn)
			if err != nil {
				log.Printf("BindFn Error %s", err.Error())

				return ldap.LDAPResultOperationsError
			}

			return resultCode
		}
		log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")

		return ldap.LDAPResultInappropriateAuthentication

	case LDAPBindAuthSASL:
		log.Print("SASL authentication is not supported")

		return ldap.LDAPResultInappropriateAuthentication
	}
}

func encodeBindResponse(messageID uint64, LDAPResultCode uint16) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(LDAPResultCode), "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
