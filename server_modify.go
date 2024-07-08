package ldaps

import (
	"errors"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleAddRequest(req *ber.Packet, boundDN string, fns map[string]Adder, conn net.Conn) error {
	if len(req.Children) != 2 {
		return ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid add request: no attributes sent"))
	}
	var ok bool
	addReq := ldap.AddRequest{}
	addReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading DN: %v", req.Children[0].Value))
	}
	addReq.Attributes = []ldap.Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			return ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid add request: no attributes sent"))
		}

		a := ldap.Attribute{}
		a.Type, ok = attr.Children[0].Value.(string)
		if !ok {
			return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading attribute name: %v", attr.Children[0].Value))
		}
		a.Vals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading attribute value: %v", attr.Children[1].Value))
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

	return fns[fn].Add(boundDN, addReq, conn)
}

func HandleDeleteRequest(req *ber.Packet, boundDN string, fns map[string]Deleter, conn net.Conn) error {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Delete(boundDN, deleteDN, conn)
}

func HandleModifyRequest(req *ber.Packet, boundDN string, fns map[string]Modifier, conn net.Conn) (*ldap.ModifyResult, error) {
	if len(req.Children) != 2 {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid modify request: no attributes sent"))
	}
	var ok bool
	modReq := ldap.ModifyRequest{}
	modReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading DN: %v", req.Children[0].Value))
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid modify request: no attributes sent"))
		}

		attr := ldap.PartialAttribute{}

		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid modify request: no attributes sent"))
		}

		attr.Type, ok = attrs[0].Value.(string)
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading modify attribute name: %v", attrs[0].Value))
		}

		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading modify attribute value: %v", val.Value))
			}
			attr.Vals = append(attr.Vals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading modify operation type: %v", change.Children[0].Value))
		}
		switch op {
		default:
			return nil, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Unrecognized modify attribute %d", op))
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

	return fns[fn].Modify(boundDN, modReq, conn)
}

func HandleCompareRequest(req *ber.Packet, boundDN string, fns map[string]Comparer, conn net.Conn) error {
	if len(req.Children) != 2 {

		return ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid compare request: no attributes sent"))
	}

	var (
		ok      bool
		compReq ldap.CompareRequest
	)

	compReq.DN, ok = req.Children[0].Value.(string)
	if !ok {

		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading compare DN: %v", req.Children[0].Value))
	}

	ava := req.Children[1]
	if len(ava.Children) != 2 {

		return ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Error invalid compare request: no attributes sent"))
	}

	attr, ok := ava.Children[0].Value.(string)
	if !ok {

		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading compare attribute name: %v", ava.Children[0].Value))
	}

	val, ok := ava.Children[1].Value.(string)
	if !ok {

		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading compare attribute value: %v", ava.Children[1].Value))
	}

	compReq.Attribute = attr
	compReq.Value = val
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Compare(boundDN, compReq, conn)
}

func HandleAbandonRequest(req *ber.Packet, boundDN string, fns map[string]Abandoner, conn net.Conn) error {
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	return fns[fn].Abandon(boundDN, conn)
}

func HandleModifyDNRequest(req *ber.Packet, boundDN string, fns map[string]ModifyDNr, conn net.Conn) error {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Invalid packet length"))
	}

	var (
		ok     bool
		mdnReq ldap.ModifyDNRequest
	)

	mdnReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading DN: %v", req.Children[0].Value))
	}

	mdnReq.NewRDN, ok = req.Children[1].Value.(string)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading new RDN: %v", req.Children[1].Value))
	}

	mdnReq.DeleteOldRDN, ok = req.Children[2].Value.(bool)
	if !ok {
		return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading DeleteOldRDN: %v", req.Children[2].Value))
	}

	if len(req.Children) == 4 {
		mdnReq.NewSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Error reading NewSuperior: %v", req.Children[3].Value))
		}
	}

	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}

	fn := routeFunc(boundDN, fnNames)

	return fns[fn].ModifyDN(boundDN, mdnReq, conn)
}
