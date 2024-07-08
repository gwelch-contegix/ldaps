package ldaps

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestAdd(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.AddFunc("", modifyTestHandler{})
	go func() {
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
	s.Close()
}

func TestDelete(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.DeleteFunc("", modifyTestHandler{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != 0 {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() == 0 || strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapdelete command timed out")
	}
	s.Close()
}

func TestModify(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", modifyTestHandler{})
	s.ModifyFunc("", modifyTestHandler{})
	go func() {
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
	s.Close()
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

type modifyTestHandler struct{}

func (h modifyTestHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (*ldap.SimpleBindResult, error) {
	if bindDN == "" && bindSimplePw == "" {
		return nil, nil
	}

	return nil, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New(""))
}

func (h modifyTestHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) error {
	// only succeed on expected contents of add.ldif:
	if len(req.Attributes) == 5 && req.DN == "cn=Barbara Jensen,dc=example,dc=com" && req.Attributes[2].Type == "sn" && len(req.Attributes[2].Vals) == 1 && req.Attributes[2].Vals[0] == "Jensen" {
		return nil
	}

	return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New(""))
}

func (h modifyTestHandler) Delete(boundDN, deleteDN string, conn net.Conn) error {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return nil
	}

	return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New(""))
}

func (h modifyTestHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (*ldap.ModifyResult, error) {
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
			return nil, ldap.NewError(ldap.LDAPResultOperationsError, fmt.Errorf("Unknown Operation: %v", change.Operation))
		}
	}
	if req.DN == "cn=testy,dc=example,dc=com" && len(AddAttributes) == 1 &&
		len(DeleteAttributes) == 3 && len(ReplaceAttributes) == 2 &&
		DeleteAttributes[2].Type == "details" && len(DeleteAttributes[2].Vals) == 0 {

		return nil, nil
	}

	return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New(""))
}

func (h modifyTestHandler) ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New(""))
}
