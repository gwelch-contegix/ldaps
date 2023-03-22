package ldaps

import (
	"errors"
	"fmt"
	"log"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func ApplyFilter(f *ber.Packet, entry *ldap.Entry) (bool, uint16) {
	switch ldap.FilterMap[uint64(f.Tag)] {
	default:
		log.Printf("Unknown LDAP filter code: %d", f.Tag)

		return false, ldap.LDAPResultOperationsError
	case "Equality Match":
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultOperationsError
		}

		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, ldap.LDAPResultOperationsError
		}

		value, ok := f.Children[1].Value.(string)
		if !ok {
			return false, ldap.LDAPResultOperationsError
		}

		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					if strings.EqualFold(v, value) {
						return true, ldap.LDAPResultSuccess
					}
				}
			}
		}
	case "Present":
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, f.Data.String()) {
				return true, ldap.LDAPResultSuccess
			}
		}
	case "And":
		for _, child := range f.Children {
			ok, exitCode := ApplyFilter(child, entry)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			}
			if !ok {
				return false, ldap.LDAPResultSuccess
			}
		}

		return true, ldap.LDAPResultSuccess

	case "Or":
		anyOk := false
		for _, child := range f.Children {
			ok, exitCode := ApplyFilter(child, entry)
			if exitCode != ldap.LDAPResultSuccess {
				return false, exitCode
			} else if ok {
				anyOk = true
			}
		}
		if anyOk {
			return true, ldap.LDAPResultSuccess
		}

	case "Not":
		if len(f.Children) != 1 {
			return false, ldap.LDAPResultOperationsError
		}
		ok, exitCode := ApplyFilter(f.Children[0], entry)
		if exitCode != ldap.LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, ldap.LDAPResultSuccess
		}
	case "Substrings":
		if len(f.Children) != 2 {
			return false, ldap.LDAPResultInvalidAttributeSyntax
		}
		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, ldap.LDAPResultOperationsError
		}
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					vLower := strings.ToLower(v)
					matched := true
					for _, search := range f.Children[1].Children {
						valueBytes := search.Data.Bytes()
						valueLower := strings.ToLower(string(valueBytes))
						switch search.Tag {
						case ldap.FilterSubstringsInitial:
							matched = matched && strings.HasPrefix(vLower, valueLower)
						case ldap.FilterSubstringsAny:
							matched = matched && strings.Contains(vLower, valueLower)
						case ldap.FilterSubstringsFinal:
							matched = matched && strings.HasSuffix(vLower, valueLower)
						default:
							matched = false
						}
					}
					if matched {
						return true, ldap.LDAPResultSuccess
					}
				}
			}
		}

	case "FilterGreaterOrEqual": // TODO
		log.Println("FilterGreaterOrEqual not implemented")

		return false, ldap.LDAPResultOperationsError

	case "FilterLessOrEqual": // TODO
		log.Println("FilterLessOrEqual not implemented")

		return false, ldap.LDAPResultOperationsError

	case "FilterApproxMatch": // TODO
		log.Println("FilterApproxMatch not implemented")

		return false, ldap.LDAPResultOperationsError

	case "FilterExtensibleMatch": // TODO
		log.Println("FilterExtensibleMatch not implemented")

		return false, ldap.LDAPResultOperationsError
	}

	return false, ldap.LDAPResultSuccess
}

func GetFilterAttribute(filter string, attr string) (string, error) {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", err
	}

	return parseFilterAttribute(f, attr)
}

func parseFilterAttribute(f *ber.Packet, attr string) (string, error) {
	attr = strings.ToLower(attr)
	objectClass := ""
	switch ldap.FilterMap[uint64(f.Tag)] {
	case "Equality Match":
		if len(f.Children) != 2 {
			return "", errors.New("Equality match must have only two children")
		}
		var (
			attribute string
			value     string
			ok        bool
		)
		attribute, ok = f.Children[0].Value.(string)
		if !ok {
			return "", fmt.Errorf("This should have been a string: %v", f.Children[0].Value)
		}

		value, ok = f.Children[1].Value.(string)
		if !ok {
			return "", fmt.Errorf("This should have been a string: %v", f.Children[1].Value)
		}

		if strings.EqualFold(attribute, attr) {
			objectClass = strings.ToLower(value)
		}
	case "And":
		for _, child := range f.Children {
			subType, err := parseFilterAttribute(child, attr)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Or":
		for _, child := range f.Children {
			subType, err := parseFilterAttribute(child, attr)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Not":
		if len(f.Children) != 1 {
			return "", errors.New("Not filter must have only one child")
		}
		subType, err := parseFilterAttribute(f.Children[0], attr)
		if err != nil {
			return "", err
		}
		if len(subType) > 0 {
			objectClass = subType
		}
	}

	return strings.ToLower(objectClass), nil
}
