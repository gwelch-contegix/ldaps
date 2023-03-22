package ldaps

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestAdd(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	// time.Sleep(time.Minute *4)
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}

func TestDelete(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.DeleteFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Delete Result: Success (0)") || !strings.Contains(string(out), "Additional info: Success") {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapdelete command timed out")
	}
	quit <- true
}

func TestModify(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.ModifyFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify failed: %v", string(out))
		}
		cmd = exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}

/*
func TestModifyDN(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		//ldapmodrdn -H ldap://localhost:3389 -x "uid=babs,dc=example,dc=com" "uid=babsy,dc=example,dc=com"
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}
*/

type modifyTestHandler struct {
}

func (h modifyTestHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}
func (h modifyTestHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of add.ldif:
	if len(req.Attributes) == 5 && req.DN == "cn=Barbara Jensen,dc=example,dc=com" &&
		req.Attributes[2].Type == "sn" && len(req.Attributes[2].Vals) == 1 &&
		req.Attributes[2].Vals[0] == "Jensen" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Delete(boundDN, deleteDN string, conn net.Conn) (uint16, error) {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of modify.ldif:
	var (
		AddAttributes     []ldap.PartialAttribute
		DeleteAttributes  []ldap.PartialAttribute
		ReplaceAttributes []ldap.PartialAttribute
	)
	for _, change := range req.Changes {
		switch change.Operation {
		case ldap.AddAttribute:
			AddAttributes = append(AddAttributes, change.Modification)
		case ldap.DeleteAttribute:
			DeleteAttributes = append(DeleteAttributes, change.Modification)
		case ldap.ReplaceAttribute:
			ReplaceAttributes = append(ReplaceAttributes, change.Modification)
		default:
			return ldap.LDAPResultOperationsError, fmt.Errorf("Unknown Operation: %v", change.Operation)
		}
	}
	if req.DN == "cn=testy,dc=example,dc=com" && len(AddAttributes) == 1 &&
		len(DeleteAttributes) == 3 && len(ReplaceAttributes) == 2 &&
		DeleteAttributes[2].Type == "details" && len(DeleteAttributes[2].Vals) == 0 {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) (uint16, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}
