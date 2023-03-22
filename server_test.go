package ldaps

import (
	"bytes"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	listenString = "127.0.0.1:3389"
	ldapURL      = "ldap://" + listenString
	timeout      = 400 * time.Millisecond
	serverBaseDN = "o=testers,c=test"
)

func TestBindAnonOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", serverBaseDN)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindAnonFail(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", serverBaseDN)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	time.Sleep(timeout)
	quit <- true
}

func TestBindSimpleOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := serverBaseDN

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindSimpleFailBadPw(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := serverBaseDN

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindSimpleFailBadDn(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := serverBaseDN

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindSSL(t *testing.T) {
	ldapURLSSL := "ldaps://" + listenString
	longerTimeout := time.Millisecond * 300
	quit := make(chan bool)
	done := make(chan bool)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServeTLS(listenString, "tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem"); err != nil {
			t.Errorf("s.ListenAndServeTLS failed: %s", err.Error())
		}
	}()

	time.Sleep(longerTimeout * 2)

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", serverBaseDN)
		cmd.Env = append(cmd.Environ(), "LDAPTLS_REQCERT=never")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 2):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindPanic(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindPanic{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", serverBaseDN)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)

	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	quit := make(chan bool)
	done := make(chan bool)
	s := NewServer()

	go func() {
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		s.SetStats(true)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", serverBaseDN)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	binds, unbinds, conns := s.GetStats()
	if conns != 1 || binds != 1 || unbinds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
	quit <- true
}

type bindAnonOK struct{}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}

	return ldap.LDAPResultInvalidCredentials, nil
}

type bindSimple struct{}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return ldap.LDAPResultSuccess, nil
	}

	return ldap.LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct{}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return ldap.LDAPResultSuccess, nil
	}

	return ldap.LDAPResultInvalidCredentials, nil
}

type bindPanic struct{}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	panic("test panic at the disco")
}

type bindCaseInsensitive struct{}

func (b bindCaseInsensitive) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if strings.ToLower(bindDN) == "cn=case,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return ldap.LDAPResultSuccess, nil
	}

	return ldap.LDAPResultInvalidCredentials, nil
}

type searchSimple struct{}

func (s searchSimple) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=ned,o=testers,c=test", map[string][]string{
			"cn":            {"ned"},
			"o":             {"ate"},
			"uidNumber":     {"5000"},
			"accountstatus": {"active"},
			"uid":           {"ned"},
			"description":   {"ned via sa"},
			"objectclass":   {"posixaccount"},
		}),
		ldap.NewEntry("cn=trent,o=testers,c=test", map[string][]string{
			"cn":            {"trent"},
			"o":             {"ate"},
			"uidNumber":     {"5005"},
			"accountstatus": {"active"},
			"uid":           {"trent"},
			"description":   {"trent via sa"},
			"objectclass":   {"posixaccount"},
		}),
		ldap.NewEntry("cn=randy,o=testers,c=test", map[string][]string{
			"cn":            {"randy"},
			"o":             {"ate"},
			"uidNumber":     {"5555"},
			"accountstatus": {"active"},
			"uid":           {"randy"},
			"objectclass":   {"posixaccount"},
		}),
	}

	return ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchSimple2 struct{}

func (s searchSimple2) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=hamburger,o=testers,c=testz", map[string][]string{
			"cn":            {"hamburger"},
			"o":             {"testers"},
			"uidNumber":     {"5000"},
			"accountstatus": {"active"},
			"uid":           {"hamburger"},
			"objectclass":   {"posixaccount"},
		}),
	}

	return ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchPanic struct{}

func (s searchPanic) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	panic("this is a test panic")
}

type searchControls struct{}

func (s searchControls) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := ldap.NewEntry("cn=hamburger,o=testers,c=testz", map[string][]string{
			"cn":            {"hamburger"},
			"o":             {"testers"},
			"uidNumber":     {"5000"},
			"accountstatus": {"active"},
			"uid":           {"hamburger"},
			"objectclass":   {"posixaccount"},
		})

		return ServerSearchResult{[]*ldap.Entry{newEntry}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
	}

	return ServerSearchResult{[]*ldap.Entry{}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchCaseInsensitive struct{}

func (s searchCaseInsensitive) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=CASE,o=testers,c=test", map[string][]string{
			"cn":            {"CaSe"},
			"o":             {"ate"},
			"uidNumber":     {"5005"},
			"accountstatus": {"active"},
			"uid":           {"trent"},
			"description":   {"trent via sa"},
			"objectclass":   {"posixaccount"},
		}),
	}

	return ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func TestRouteFunc(t *testing.T) {
	if routeFunc("", []string{"a", "xyz", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
	if routeFunc("a=b", []string{"a=b", "x=y,a=b", "tt"}) != "a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"a=b", "x=y,a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"x=y,a=b", "a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("nosuch", []string{"x=y,a=b", "a=b", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
}
