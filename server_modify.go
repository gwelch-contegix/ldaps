package ldaps

import (
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleAddRequest(req *ber.Packet, boundDN string, fns map[string]Adder, conn net.Conn) (resultCode uint16) {
	if len(req.Children) != 2 {
		log.Println("Error invalid add request: no attributes sent")

		return ldap.LDAPResultProtocolError
	}
	var ok bool
	addReq := ldap.AddRequest{}
	addReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		log.Printf("Error reading DN: %v", req.Children[0].Value)

		return ldap.LDAPResultProtocolError
	}
	addReq.Attributes = []ldap.Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			log.Println("Error invalid add request: no attributes sent")

			return ldap.LDAPResultProtocolError
		}

		a := ldap.Attribute{}
		a.Type, ok = attr.Children[0].Value.(string)
		if !ok {
			log.Printf("Error reading attribute name: %v", attr.Children[0].Value)

			return ldap.LDAPResultProtocolError
		}
		a.Vals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				log.Printf("Error reading attribute value: %v", attr.Children[1].Value)

				return ldap.LDAPResultProtocolError
			}
			a.Vals = append(a.Vals, v)
		}
		addReq.Attributes = append(addReq.Attributes, a)
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	resultCode, err := fns[fn].Add(boundDN, addReq, conn)
	if err != nil {
		log.Printf("AddFn Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}

func HandleDeleteRequest(req *ber.Packet, boundDN string, fns map[string]Deleter, conn net.Conn) (resultCode uint16) {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Delete(boundDN, deleteDN, conn)
	if err != nil {
		log.Printf("DeleteFn Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}

func HandleModifyRequest(req *ber.Packet, boundDN string, fns map[string]Modifier, conn net.Conn) (resultCode uint16) {
	if len(req.Children) != 2 {
		log.Println("Error invalid modify request: no attributes sent")

		return ldap.LDAPResultProtocolError
	}
	var ok bool
	modReq := ldap.ModifyRequest{}
	modReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.LDAPResultProtocolError
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			log.Println("Error invalid modify request: no attributes sent")

			return ldap.LDAPResultProtocolError
		}

		attr := ldap.PartialAttribute{}

		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			log.Println("Error invalid modify request: no attributes sent")

			return ldap.LDAPResultProtocolError
		}

		attr.Type, ok = attrs[0].Value.(string)
		if !ok {
			log.Printf("Error reading modify attribute name: %v", attrs[0].Value)

			return ldap.LDAPResultProtocolError
		}

		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				log.Printf("Error reading modify attribute value: %v", val.Value)

				return ldap.LDAPResultProtocolError
			}
			attr.Vals = append(attr.Vals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			log.Printf("Error reading modify operation type: %v", change.Children[0].Value)

			return ldap.LDAPResultProtocolError
		}
		switch op {
		default:
			log.Printf("Unrecognized modify attribute %d", op)

			return ldap.LDAPResultProtocolError
		case ldap.AddAttribute:
			modReq.Add(attr.Type, attr.Vals)
		case ldap.DeleteAttribute:
			modReq.Delete(attr.Type, attr.Vals)
		case ldap.ReplaceAttribute:
			modReq.Replace(attr.Type, attr.Vals)
		}
	}

	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	resultCode, err := fns[fn].Modify(boundDN, modReq, conn)
	if err != nil {
		log.Printf("ModifyFn Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}

func HandleCompareRequest(req *ber.Packet, boundDN string, fns map[string]Comparer, conn net.Conn) (resultCode uint16) {
	if len(req.Children) != 2 {
		log.Println("Error invalid compare request: no attributes sent")

		return ldap.LDAPResultProtocolError
	}

	var (
		ok      bool
		compReq ldap.CompareRequest
	)

	compReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		log.Printf("Error reading compare DN: %v", req.Children[0].Value)

		return ldap.LDAPResultProtocolError
	}

	ava := req.Children[1]
	if len(ava.Children) != 2 {
		log.Println("Error invalid compare request: no attributes sent")

		return ldap.LDAPResultProtocolError
	}

	attr, ok := ava.Children[0].Value.(string)
	if !ok {
		log.Printf("Error reading compare attribute name: %v", ava.Children[0].Value)

		return ldap.LDAPResultProtocolError
	}

	val, ok := ava.Children[1].Value.(string)
	if !ok {
		log.Printf("Error reading compare attribute value: %v", ava.Children[1].Value)

		return ldap.LDAPResultProtocolError
	}

	compReq.Attribute = attr
	compReq.Value = val
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	resultCode, err := fns[fn].Compare(boundDN, compReq, conn)
	if err != nil {
		log.Printf("CompareFn Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}

func HandleExtendedRequest(req *ber.Packet, boundDN string, fns map[string]Extender, conn net.Conn) (resultCode uint16) {
	if len(req.Children) != 1 && len(req.Children) != 2 {
		return ldap.LDAPResultProtocolError
	}

	name := ber.DecodeString(req.Children[0].Data.Bytes())

	var val string
	if len(req.Children) == 2 {
		val = ber.DecodeString(req.Children[1].Data.Bytes())
	}

	extReq := ExtendedRequest{name, val}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	resultCode, err := fns[fn].Extended(boundDN, extReq, conn)
	if err != nil {
		log.Printf("ExtendedFn Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}

func HandleAbandonRequest(req *ber.Packet, boundDN string, fns map[string]Abandoner, conn net.Conn) error {
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)
	err := fns[fn].Abandon(boundDN, conn)

	return err
}

func HandleModifyDNRequest(req *ber.Packet, boundDN string, fns map[string]ModifyDNr, conn net.Conn) (resultCode uint16) {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return ldap.LDAPResultProtocolError
	}

	var (
		ok     bool
		mdnReq ldap.ModifyDNRequest
	)

	mdnReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.LDAPResultProtocolError
	}

	mdnReq.NewRDN, ok = req.Children[1].Value.(string)
	if !ok {
		return ldap.LDAPResultProtocolError
	}

	mdnReq.DeleteOldRDN, ok = req.Children[2].Value.(bool)
	if !ok {
		return ldap.LDAPResultProtocolError
	}

	if len(req.Children) == 4 {
		mdnReq.NewSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return ldap.LDAPResultProtocolError
		}
	}

	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	resultCode, err := fns[fn].ModifyDN(boundDN, mdnReq, conn)
	if err != nil {
		log.Printf("ModifyDN Error %s", err.Error())

		return ldap.LDAPResultOperationsError
	}

	return resultCode
}
