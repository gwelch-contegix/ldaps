package ldaps

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Other LDAP constants.
const (
	LDAPBindAuthSimple = 0
	LDAPBindAuthSASL   = 3
	oidStartTLS        = "1.3.6.1.4.1.1466.20037"
)

type Binder interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (*ldap.SimpleBindResult, error)
}
type Searcher interface {
	Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (*ldap.SearchResult, error)
}
type Modifier interface {
	Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (*ldap.ModifyResult, error)
}
type Adder interface {
	Add(boundDN string, req ldap.AddRequest, conn net.Conn) error
}
type ModifyDNr interface {
	ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) error
}
type Deleter interface {
	Delete(boundDN, deleteDN string, conn net.Conn) error
}
type Comparer interface {
	Compare(boundDN string, req ldap.CompareRequest, conn net.Conn) error
}
type Abandoner interface {
	Abandon(boundDN string, conn net.Conn) error
}
type Closer interface {
	Close(boundDN string, conn net.Conn)
}

type Server struct {
	BindFns     map[string]Binder
	SearchFns   map[string]Searcher
	AddFns      map[string]Adder
	ModifyFns   map[string]Modifier
	DeleteFns   map[string]Deleter
	ModifyDNFns map[string]ModifyDNr
	CompareFns  map[string]Comparer
	AbandonFns  map[string]Abandoner
	CloseFns    map[string]Closer
	Quit        chan bool
	EnforceLDAP bool
	stats       *stats

	// If set, server will accept StartTLS.
	TLSConfig *tls.Config
}

type Stats struct {
	Conns          int
	Binds          int
	Unbinds        int
	Searches       int
	NotImplemented int
}

type stats struct {
	Stats
	statsMutex sync.Mutex
}

func NewServer() *Server {
	s := new(Server)
	s.Quit = make(chan bool)

	d := defaultHandler{}
	s.BindFns = make(map[string]Binder)
	s.SearchFns = make(map[string]Searcher)
	s.AddFns = make(map[string]Adder)
	s.ModifyFns = make(map[string]Modifier)
	s.DeleteFns = make(map[string]Deleter)
	s.ModifyDNFns = make(map[string]ModifyDNr)
	s.CompareFns = make(map[string]Comparer)
	s.AbandonFns = make(map[string]Abandoner)
	s.CloseFns = make(map[string]Closer)
	s.BindFunc("", d)
	s.SearchFunc("", d)
	s.AddFunc("", d)
	s.ModifyFunc("", d)
	s.DeleteFunc("", d)
	s.ModifyDNFunc("", d)
	s.CompareFunc("", d)
	s.AbandonFunc("", d)
	s.CloseFunc("", d)
	s.stats = nil

	return s
}

func (server *Server) BindFunc(baseDN string, f Binder) {
	server.BindFns[baseDN] = f
}

func (server *Server) SearchFunc(baseDN string, f Searcher) {
	server.SearchFns[baseDN] = f
}

func (server *Server) AddFunc(baseDN string, f Adder) {
	server.AddFns[baseDN] = f
}

func (server *Server) ModifyFunc(baseDN string, f Modifier) {
	server.ModifyFns[baseDN] = f
}

func (server *Server) DeleteFunc(baseDN string, f Deleter) {
	server.DeleteFns[baseDN] = f
}

func (server *Server) ModifyDNFunc(baseDN string, f ModifyDNr) {
	server.ModifyDNFns[baseDN] = f
}

func (server *Server) CompareFunc(baseDN string, f Comparer) {
	server.CompareFns[baseDN] = f
}

func (server *Server) AbandonFunc(baseDN string, f Abandoner) {
	server.AbandonFns[baseDN] = f
}

func (server *Server) CloseFunc(baseDN string, f Closer) {
	server.CloseFns[baseDN] = f
}

func (server *Server) QuitChannel(quit chan bool) {
	server.Quit = quit
}

func (server *Server) ListenAndServeTLS(listenString string, certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	ln, err := tls.Listen("tcp", listenString, &tlsConfig)
	if err != nil {
		return err
	}

	return server.Serve(ln)
}

func (server *Server) SetStats(enable bool) {
	if enable {
		server.stats = &stats{}
	} else {
		server.stats = nil
	}
}

func (server *Server) GetStats() Stats {
	defer func() {
		server.stats.statsMutex.Unlock()
	}()
	server.stats.statsMutex.Lock()

	return server.stats.Stats
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}

	return server.Serve(ln)
}

func (server *Server) Serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting network connection: %s", err.Error())
				}

				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.stats.countConns(1)
			go server.handleConnection(c)
		case <-server.Quit:
			ln.Close()
			close(server.Quit)

			break listener
		}
	}

	return nil
}

// Close closes the underlying net.Listener, and waits for confirmation
func (server *Server) Close() {
	server.Quit <- true
	<-server.Quit
}

func (server *Server) handleConnection(conn net.Conn) {
	boundDN := "" // "" == anonymous

handler:
	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())

			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			log.Print("len(packet.Children) < 2")

			break
		}
		// check the message ID and ClassType
		messageID64, ok := packet.Children[0].Value.(int64)
		if !ok {
			log.Printf("malformed messageID: %T: %#v", packet.Children[0].Value, packet.Children[0].Value)

			break
		}
		messageID := uint64(messageID64)
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			log.Print("req.ClassType != ber.ClassApplication")

			break
		}
		// handle controls if present
		controls := []ldap.Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				var control ldap.Control
				control, err = ldap.DecodeControl(child)
				if err != nil {
					log.Print("Failed to decode control")
				} else {
					controls = append(controls, control)
				}
			}
		}

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			name, ok := ldap.ApplicationMap[uint8(req.Tag)]
			if !ok {
				name = "Unknown"
			}
			log.Printf("Unhandled operation: %s [%d]", name, req.Tag)
			responsePacket := encodeLDAPResponse(messageID, ldap.ApplicationUnbindRequest, ldap.LDAPResultUnavailable, fmt.Sprintf("Unhandled operation: %s [%d]", name, req.Tag))
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
			}

			break handler

		case ldap.ApplicationUnbindRequest:
			server.stats.countUnbinds(1)

			break handler // simply disconnect
		case ldap.ApplicationExtendedRequest:
			var tlsConn *tls.Conn
			if n := len(req.Children); n == 1 || n == 2 {
				if name := ber.DecodeString(req.Children[0].Data.Bytes()); name == oidStartTLS {
					tlsConn = tls.Server(conn, server.TLSConfig)
				}
			}
			var ldapResultCode uint16
			ldapResultCode = ldap.LDAPResultSuccess
			if tlsConn == nil {
				// Wasn't an upgrade. We don't support other Extended requestes
				ldapResultCode = ldap.LDAPResultUnavailable
			}

			responsePacket := encodeLDAPResponse(messageID, ldap.ApplicationExtendedResponse, ldapResultCode, ldap.LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())

				break handler
			}
			if tlsConn != nil {
				conn = tlsConn
			}
		case ldap.ApplicationAbandonRequest:
			err = HandleAbandonRequest(req, boundDN, server.AbandonFns, conn)
			if err != nil {
				log.Printf("Error Abandoning Request: %s", err)

				break handler
			}

		case ldap.ApplicationBindRequest:
			server.stats.countBinds(1)
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			_, err := HandleBindRequest(req, server.BindFns, conn) // TODO: Handle SimpleBindResult
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Binding: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationBindResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationSearchRequest:
			server.stats.countSearches(1)
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			err = HandleSearchRequest(req, &controls, messageID, boundDN, server, conn)
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Searching: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationSearchResultDone, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}

		case ldap.ApplicationAddRequest:
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			err = HandleAddRequest(req, boundDN, server.AddFns, conn)
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				if e.Err != nil {
					message = e.Err.Error()
					if resultCode != ldap.LDAPResultSuccess {
						log.Printf("Error Adding: %s", err)
					}
				}
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationAddResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationModifyRequest:
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			_, err = HandleModifyRequest(req, boundDN, server.ModifyFns, conn) // TODO: Handle ModifyResult
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Modifying: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationModifyResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationDelRequest:
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			err = HandleDeleteRequest(req, boundDN, server.DeleteFns, conn)
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}
			if resultCode != ldap.LDAPResultSuccess {
				log.Printf("Error Deleting: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationDelResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationModifyDNRequest:
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			err = HandleModifyDNRequest(req, boundDN, server.ModifyDNFns, conn)
			if err != nil {
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}
			if !(resultCode == ldap.LDAPResultSuccess || resultCode == ldap.LDAPResultCompareFalse || resultCode == ldap.LDAPResultCompareTrue) {
				log.Printf("Error Modifying DN: %s", err)
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationModifyDNResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		case ldap.ApplicationCompareRequest:
			var resultCode uint16 = ldap.LDAPResultSuccess
			message := ""
			err = HandleCompareRequest(req, boundDN, server.CompareFns, conn)
			if err != nil {
				log.Printf("Error Comparing: %s", err)
				e := &ldap.Error{}
				if !errors.As(err, &e) {
					e = &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("Internal Error")}
				} else if e.Err == nil {
					e.Err = errors.New("")
				}
				resultCode = e.ResultCode
				message = e.Err.Error()
			}

			if err = sendPacket(conn, encodeLDAPResponse(messageID, ldap.ApplicationCompareResponse, resultCode, message)); err != nil {
				log.Printf("sendPacket error: %s", err.Error())

				break handler
			}
		}
	}

	for _, c := range server.CloseFns {
		c.Close(boundDN, conn)
	}

	conn.Close()
}

func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())

		return err
	}

	return nil
}

func routeFunc(dn string, funcNames []string) string {
	bestPick := ""
	bestPickWeight := 0
	dnMatch := "," + strings.ToLower(dn)
	var weight int
	for _, fn := range funcNames {
		if strings.HasSuffix(dnMatch, ","+fn) {
			//  empty string as 0, no-comma string 1 , etc
			if fn == "" {
				weight = 0
			} else {
				weight = strings.Count(fn, ",") + 1
			}
			if weight > bestPickWeight {
				bestPick = fn
				bestPickWeight = weight
			}
		}
	}

	return bestPick
}

func encodeLDAPResponse(messageID uint64, responseType ber.Tag, LDAPResultCode uint16, errorMessage string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, responseType, nil, ldap.ApplicationMap[uint8(responseType)])
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(LDAPResultCode), "resultCode: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errorMessage, "errorMessage: "))

	responsePacket.AppendChild(response)

	return responsePacket
}

type defaultHandler struct{}

func (h defaultHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (*ldap.SimpleBindResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (*ldap.SearchResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (*ldap.ModifyResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Delete(boundDN, deleteDN string, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) ModifyDN(boundDN string, req ldap.ModifyDNRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Compare(boundDN string, req ldap.CompareRequest, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Abandon(boundDN string, conn net.Conn) error {
	return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("Not Implemented"))
}

func (h defaultHandler) Close(boundDN string, conn net.Conn) {} // conn will be closed automatically

func (stats *stats) countConns(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Conns += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countBinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Binds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countUnbinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Unbinds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countSearches(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Searches += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *stats) countNotImplemented(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.NotImplemented += delta
		stats.statsMutex.Unlock()
	}
}
