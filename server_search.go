package ldaps

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleSearchRequest(req *ber.Packet, controls *[]ldap.Control, messageID uint64, boundDN string, server *Server, conn net.Conn) (resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in SearchFn: %s\n%s", r, string(debug.Stack()))
			resultErr = ldap.NewError(ldap.LDAPResultOperationsError, fmt.Errorf("Search function panic: %s", r))
		}
	}()

	searchReq, err := parseSearchRequest(req, controls)
	if err != nil {
		log.Printf("Error parsing search request: %v", req.Children[1].Value)
		return err
	}

	filterPacket, err := ldap.CompileFilter(searchReq.Filter)
	if err != nil {
		log.Printf("Error compiling filter: %v", searchReq.Filter)
		return ldap.NewError(ldap.LDAPResultFilterError, err)
	}

	fnNames := []string{}
	for k := range server.SearchFns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(searchReq.BaseDN, fnNames)
	searchResp, err := server.SearchFns[fn].Search(boundDN, searchReq, conn)
	if err != nil {
		log.Printf("SearchFn Error %s", err.Error())
		return ldap.NewError(searchResp.ResultCode, err)
	}

	if server.EnforceLDAP {
		if searchReq.DerefAliases != ldap.NeverDerefAliases { // [-a {never|always|search|find}
			// TODO: Server DerefAliases not supported: RFC4511 4.5.1.3
			server.Stats.countNotImplemented(1)
		}
		if searchReq.TimeLimit > 0 {
			// TODO: Server TimeLimit not implemented
			server.Stats.countNotImplemented(1)
		}
	}

	i := 0
	searchReqBaseDNLower := strings.ToLower(searchReq.BaseDN)
	for _, entry := range searchResp.Entries {
		if server.EnforceLDAP {
			// filter
			keep, resultCode := ApplyFilter(filterPacket, entry)
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Applying filter: %v", searchReq.Filter)
				return ldap.NewError(resultCode, errors.New("ApplyFilter error"))
			}
			if !keep {
				continue
			}

			// constrained search scope
			switch searchReq.Scope {
			case ldap.ScopeWholeSubtree: // The scope is constrained to the entry named by baseObject and to all its subordinates.
			case ldap.ScopeBaseObject: // The scope is constrained to the entry named by baseObject.
				if strings.ToLower(entry.DN) != searchReqBaseDNLower {
					continue
				}
			case ldap.ScopeSingleLevel: // The scope is constrained to the immediate subordinates of the entry named by baseObject.
				entryDNLower := strings.ToLower(entry.DN)
				parts := strings.Split(entryDNLower, ",")
				if len(parts) < 2 && entryDNLower != searchReqBaseDNLower {
					continue
				}
				if dnSuffix := strings.Join(parts[1:], ","); dnSuffix != searchReqBaseDNLower {
					continue
				}
			}

			// filter attributes
			entry = filterAttributes(entry, searchReq.Attributes)

			// size limit
			if searchReq.SizeLimit > 0 && i >= searchReq.SizeLimit {
				break
			}
			i++
		}

		// respond
		responsePacket := encodeSearchResponse(messageID, entry)
		if err = sendPacket(conn, responsePacket); err != nil {
			log.Printf("Error encoding response: %v", searchReq.Filter)
			return ldap.NewError(ldap.LDAPResultOperationsError, err)
		}
	}

	return nil
}

func parseSearchRequest(req *ber.Packet, controls *[]ldap.Control) (ldap.SearchRequest, error) {
	if len(req.Children) != 8 {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("Bad search request: invalid length"))
	}

	// Parse the request
	baseObject, ok := req.Children[0].Value.(string)
	if !ok {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: base object"))
	}
	s, ok := req.Children[1].Value.(int64)
	if !ok {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: scope"))
	}
	scope := int(s)
	d, ok := req.Children[2].Value.(int64)
	if !ok {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: deref aliases"))
	}
	derefAliases := int(d)
	s, ok = req.Children[3].Value.(int64)
	if !ok {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: size limit"))
	}
	sizeLimit := int(s)
	t, ok := req.Children[4].Value.(int64)
	if !ok {
		return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: time limit"))
	}
	timeLimit := int(t)
	typesOnly := false
	if req.Children[5].Value != nil {
		typesOnly, ok = req.Children[5].Value.(bool)
		if !ok {
			return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, errors.New("Bad search request: types only"))
		}
	}
	filter, err := ldap.DecompileFilter(req.Children[6])
	if err != nil {
		return ldap.SearchRequest{}, err
	}
	attributes := []string{}
	for _, attr := range req.Children[7].Children {
		a, ok := attr.Value.(string)
		if !ok {
			return ldap.SearchRequest{}, ldap.NewError(ldap.LDAPResultProtocolError, fmt.Errorf("Bad search request: reading attribute: %v", attr.Value))
		}
		attributes = append(attributes, a)
	}
	searchReq := *ldap.NewSearchRequest(baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes, *controls)

	return searchReq, nil
}

func filterAttributes(entry *ldap.Entry, attributes []string) *ldap.Entry {
	// only return requested attributes
	newAttributes := []*ldap.EntryAttribute{}

	if len(attributes) > 1 || (len(attributes) == 1 && len(attributes[0]) > 0) {
		for _, attr := range entry.Attributes {
			attrNameLower := strings.ToLower(attr.Name)
			for _, requested := range attributes {
				requestedLower := strings.ToLower(requested)
				// You can request the directory server to return operational attributes by adding + (the plus sign) in your ldapsearch command.
				// "+supportedControl" is treated as an operational attribute
				if strings.HasPrefix(attrNameLower, "+") {
					if requestedLower == "+" || attrNameLower == "+"+requestedLower {
						newAttributes = append(newAttributes, ldap.NewEntryAttribute(attr.Name[1:], attr.Values))

						break
					}
				} else {
					if requested == "*" || attrNameLower == requestedLower {
						newAttributes = append(newAttributes, attr)

						break
					}
				}
			}
		}
	} else {
		// remove operational attributes
		for _, attr := range entry.Attributes {
			if !strings.HasPrefix(attr.Name, "+") {
				newAttributes = append(newAttributes, attr)
			}
		}
	}
	entry.Attributes = newAttributes

	return entry
}

func encodeSearchResponse(messageID uint64, res *ldap.Entry) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	searchEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.DN, "Object Name"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes:")
	for _, attribute := range res.Attributes {
		attrs.AppendChild(encodeSearchAttribute(attribute.Name, attribute.Values))
	}

	searchEntry.AppendChild(attrs)
	responsePacket.AppendChild(searchEntry)

	return responsePacket
}

func encodeSearchAttribute(name string, values []string) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))

	valuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
	for _, value := range values {
		valuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Attribute Value"))
	}

	packet.AppendChild(valuesPacket)

	return packet
}

func encodeSearchDone(messageID uint64, LDAPResultCode uint16) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	donePacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "Search result done")
	donePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(LDAPResultCode), "resultCode: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(donePacket)

	return responsePacket
}
