package ldaps

import (
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func ApplyFilter(f *ber.Packet, entry *ldap.Entry) (bool, *ldap.Error) {
	switch f.Tag {
	default:

		return false, &ldap.Error{Err: fmt.Errorf("Unknown LDAP filter code: %d", f.Tag), ResultCode: ldap.LDAPResultFilterError}
	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}

		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}

		value, ok := f.Children[1].Value.(string)
		if !ok {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}

		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				for _, v := range a.Values {
					if strings.EqualFold(v, value) {
						return true, nil
					}
				}
			}
		}

	case ldap.FilterPresent:
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, f.Data.String()) {
				return true, nil
			}
		}

	case ldap.FilterAnd:
		for _, child := range f.Children {
			ok, exitCode := ApplyFilter(child, entry)
			if exitCode != nil || !ok {
				return false, exitCode
			}
		}

		return true, nil

	case ldap.FilterOr:
		matched := false
		for _, child := range f.Children {
			ok, exitCode := ApplyFilter(child, entry)
			if exitCode != nil {
				return false, exitCode
			} else if ok {
				matched = true

				break
			}
		}
		if matched {
			return true, nil
		}

	case ldap.FilterNot:
		if len(f.Children) != 1 {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}
		ok, exitCode := ApplyFilter(f.Children[0], entry)
		if exitCode != nil {
			return false, exitCode
		} else if !ok {
			return true, nil
		}

	case ldap.FilterSubstrings:
		if len(f.Children) != 2 {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}
		attribute, ok := f.Children[0].Value.(string)
		if !ok {
			return false, &ldap.Error{Err: errors.New("invalid filter"), ResultCode: ldap.LDAPResultFilterError}
		}
		var attr *ldap.EntryAttribute
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, attribute) {
				attr = a

				break
			}
		}
		if attr == nil {
			break
		}

	matchFail:
		for _, v := range attr.Values { // Check each value to see if it matches. Used for memberOf searches
			value := strings.ToLower(v)
			matched := false

			for _, s := range f.Children[1].Children { // Check each part of the filter ('beg' and 'end' in 'beg*end'). This can't end early because if we are checking group membership the group may not be the first listed group
				search := strings.ToLower(s.Data.String())

				switch s.Tag {
				case ldap.FilterSubstringsInitial:
					matched = strings.HasPrefix(value, search)
				case ldap.FilterSubstringsAny:
					matched = strings.Contains(value, search)
				case ldap.FilterSubstringsFinal:
					matched = strings.HasSuffix(value, search)
				}
				if !matched {
					matched = false
					continue matchFail // This section of the filter failed (eg 'beg' in 'beg*end' doesn't match the value) that means we need to skip the current value we are checking
				}
			}

			if matched {
				return true, nil
			}
		}

	case ldap.FilterGreaterOrEqual: // TODO
		return false, &ldap.Error{Err: fmt.Errorf("%s not implemented", ldap.FilterMap[uint64(f.Tag)]), ResultCode: ldap.LDAPResultFilterError}

	case ldap.FilterLessOrEqual: // TODO
		return false, &ldap.Error{Err: fmt.Errorf("%s not implemented", ldap.FilterMap[uint64(f.Tag)]), ResultCode: ldap.LDAPResultFilterError}

	case ldap.FilterApproxMatch: // TODO
		return false, &ldap.Error{Err: fmt.Errorf("%s not implemented", ldap.FilterMap[uint64(f.Tag)]), ResultCode: ldap.LDAPResultFilterError}

	case ldap.FilterExtensibleMatch: // TODO
		return false, &ldap.Error{Err: fmt.Errorf("%s not implemented", ldap.FilterMap[uint64(f.Tag)]), ResultCode: ldap.LDAPResultFilterError}
	}

	return false, nil
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
