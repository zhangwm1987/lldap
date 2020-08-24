/*
 * Openldap (2.4.51) binding in GO
 *
 *
 */

package openldap

/*

#include <stdlib.h>
#include <ldap.h>
#include <sys/time.h>
#include <time.h>


static inline char* to_charptr(const void* s) { return (char*)s; }
static inline LDAPControl** to_ldapctrlptr(const void* s) {
	return (LDAPControl**) s;
}

static inline struct timeval* to_timevalptr(const void* s) {
	return (struct timeval*) s;
}

static inline LDAPControl* build_control(char* oid, char is_critical) {
	LDAPControl *simpleControl = malloc(sizeof(LDAPControl));

	simpleControl->ldctl_oid = "1.2.840.113556.1.4.528";
        simpleControl->ldctl_iscritical = 1;
	simpleControl->ldctl_value.bv_len = 0;
	simpleControl->ldctl_value.bv_val = NULL;
	return simpleControl;
}

#cgo CFLAGS: -DLDAP_DEPRECATED=1
#cgo linux CFLAGS: -DLINUX=1
#cgo LDFLAGS: -lldap_r -llber
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

/* Intialize() open an LDAP connexion ; supported url formats :
 *
 *   ldap://host:389/
 *   ldaps://secure-host:636/
 *
 * return values :
 *  - on success : LDAP object, nil
 *  - on error : nil and error with error description.
 */
func Initialize(url string) (*Ldap, error) {
	_url := C.CString(url)
	defer C.free(unsafe.Pointer(_url))

	var ldap *C.LDAP

	rv := C.ldap_initialize(&ldap, _url)

	if rv != 0 {
		err := errors.New(fmt.Sprintf("LDAP::Initialize() error (%d) : %s",
			rv, ErrorToString(int(rv))))
		return nil, err
	}

	return &Ldap{ldap}, nil
}

/*
 * StartTLS() is used for regular LDAP (not
 * LDAPS) connections to establish encryption
 * after the session is running.
 *
 * return value :
 *  - nil on success,
 *  - error with error description on error.
 */
func (self *Ldap) StartTLS() error {
	var rv int

	// API: int ldap_start_tls_s(LDAP *ld, LDAPControl **serverctrls, LDAPControl **clientctrls);
	rv = int(C.ldap_start_tls_s(self.conn,
		C.to_ldapctrlptr(unsafe.Pointer(nil)),
		C.to_ldapctrlptr(unsafe.Pointer(nil))))

	if rv == LDAP_OPT_SUCCESS {
		return nil
	}

	return errors.New(fmt.Sprintf("LDAP::StartTLS() error (%d) : %s", rv,
		ErrorToString(rv)))
}

func (self *Ldap) Bind(who, cred string) error {
	var rv int

	authmethod := C.int(LDAP_AUTH_SIMPLE)

	if who == "" {
		_who := C.to_charptr(unsafe.Pointer(nil))
		_cred := C.to_charptr(unsafe.Pointer(nil))

		rv = int(C.ldap_bind_s(self.conn, _who, _cred, authmethod))
	} else {
		_who := C.CString(who)
		_cred := C.CString(cred)
		defer C.free(unsafe.Pointer(_who))
		rv = int(C.ldap_bind_s(self.conn, _who, _cred, authmethod))
	}

	if rv == LDAP_OPT_SUCCESS {
		return nil
	}

	return errors.New(fmt.Sprintf("LDAP::Bind() error (%d) : %s", rv, ErrorToString(rv)))
}

//func (self *Ldap) SearchExt(base string, scope int, filter string, attributes []string) (*LdapMessage, error) {
func (self *Ldap) SearchExt(searchReq *LdapSearchRequest) (int, error) {
	// 1 => attributes only 0 => attributes and values
	var attrsonly int = 0

	_base := C.CString(searchReq.Base)
	defer C.free(unsafe.Pointer(_base))

	_filter := C.CString(searchReq.Filter)
	defer C.free(unsafe.Pointer(_filter))

	// transform []string to C.char** null terminated array (attributes argument)
	_attributes := make([]*C.char, len(searchReq.Attributes)+1) // default set to nil (NULL in C)

	for k, arg := range searchReq.Attributes {
		_attributes[k] = C.CString(arg)
		defer C.free(unsafe.Pointer(_attributes[k]))
	}

	controls := make([]*C.LDAPControl, 2)

	//	var serverControl C.LDAPControl
	//	serverControl.ldctl_oid = C.CString(searchReq.ServerControl.Ldctl_oid)
	//	serverControl.ldctl_iscritical = C.char(searchReq.ServerControl.Ldctl_iscritical)
	//cControl.ldctl_value.bv_len = C.ulong(0)
	//cControl.ldctl_value.bv_val = C.CString(searchReq.serverControl.ldctl_value.bv_val)
	//cControl.ldctl_value.bv_val = C.CString("")
	//controls[0] = &serverControl

	//	var sControl, cControl **C.LDAPControl
	//	sControl = controls[0]
	//	//sControl = nil
	//	cControl = nil
	controls[0] = C.build_control(C.CString(searchReq.ServerControl.Ldctl_oid),
		C.char(searchReq.ServerControl.Ldctl_iscritical),
	)

	//	var sz = 0
	var msgid C.int
	rv := int(C.ldap_search_ext(self.conn, _base, C.int(searchReq.Scope), _filter,
		&_attributes[0], C.int(attrsonly),
		//		C.to_ldapctrlptr(unsafe.Pointer(&controls[0])),
		&controls[0],
		C.to_ldapctrlptr(unsafe.Pointer(nil)),
		//cControl,
		C.to_timevalptr(unsafe.Pointer(nil)),
		C.int(0),
		&msgid,
	))

	if rv != LDAP_OPT_SUCCESS {
		return 0, errors.New(fmt.Sprintf("LDAP::Search() error : %d (%s)", rv, ErrorToString(rv)))
	}

	return int(msgid), nil
}

func (self *Ldap) SearchExtSync(searchReq LdapSearchRequest, msgID *int) (*LdapMessage, error) {
	var attrsonly int = 0

	_base := C.CString(searchReq.Base)
	defer C.free(unsafe.Pointer(_base))

	_filter := C.CString(searchReq.Filter)
	defer C.free(unsafe.Pointer(_filter))

	// transform []string to C.char** null terminated array (attributes argument)
	_attributes := make([]*C.char, len(searchReq.Attributes)+1) // default set to nil (NULL in C)

	for k, arg := range searchReq.Attributes {
		_attributes[k] = C.CString(arg)
		defer C.free(unsafe.Pointer(_attributes[k]))
	}

	var c_msg *C.LDAPMessage
	rv := int(C.ldap_search_ext_s(self.conn, _base, C.int(searchReq.Scope), _filter,
		&_attributes[0], C.int(attrsonly),
		C.to_ldapctrlptr(unsafe.Pointer(nil)),
		C.to_ldapctrlptr(unsafe.Pointer(nil)),
		C.to_timevalptr(unsafe.Pointer(nil)),
		C.int(0),
		&c_msg))

	if rv != LDAP_OPT_SUCCESS {
		return nil, errors.New(fmt.Sprintf("LDAP::Search() error : %d (%s)", rv, ErrorToString(rv)))
	}

	Msg := &LdapMessage{
		ldap:  self,
		errno: rv,
		msg:   c_msg,
	}

	return Msg, nil
}

// ------------------------------------- Ldap* method (object oriented) -------------------------------------------------------------------

// Create a new LdapAttribute entry with name and values.
func LdapAttributeNew(name string, values []string) *LdapAttribute {
	a := new(LdapAttribute)
	a.values = values
	a.name = name
	return a
}

// Append() adds an LdapAttribute to self LdapEntry
func (self *LdapEntry) Append(a LdapAttribute) {
	self.values = append(self.values, a)
}

// String() is used for fmt.Println(self)
//
func (self *LdapAttribute) String() string {
	return self.ToText()
}

// ToText() returns a text string representation of LdapAttribute
// avoiding displaying binary data.
//
func (self *LdapAttribute) ToText() string {

	var list []string

	for _, a := range self.Values() {
		if !_isPrint(a) {
			list = append(list, fmt.Sprintf("binary-data[%d]", len(a)))
		} else {
			list = append(list, a)
		}
	}
	if len(list) > 1 {
		return fmt.Sprintf("%s: (%d)[%s]", self.name, len(list), strings.Join(list, ", "))
	}
	return fmt.Sprintf("%s: [%s]", self.name, strings.Join(list, ", "))
}

// Name() return attribute name
func (self *LdapAttribute) Name() string {
	return self.name
}

// Values() returns array values for self LdapAttribute
//
func (self *LdapAttribute) Values() []string {
	return self.values
}

// _isPrint() returns true if str is printable
//
// @private method
func _isPrint(str string) bool {
	for _, c := range str {

		if !strconv.IsPrint(rune(c)) {
			return false
		}
	}

	return true
}

// IsPrint() returns true is self LdapAttribute is printable.
func (self *LdapAttribute) IsPrint() bool {
	for _, a := range self.Values() {
		if !_isPrint(a) {
			return false
		}
	}
	return true
}

// Dn() returns DN (Distinguish Name) for self LdapEntry
func (self *LdapEntry) Dn() string {
	return self.dn
}

// Attributes() returns an array of LdapAttribute
func (self *LdapEntry) Attributes() []LdapAttribute {
	return self.values
}

// Print() allow printing self LdapEntry with fmt.Println()
func (self *LdapEntry) String() string {
	return self.ToText()
}

// GetValuesByName() get a list of values for self LdapEntry, using "name" attribute
func (self *LdapEntry) GetValuesByName(attrib string) []string {

	for _, a := range self.values {
		if a.Name() == attrib {
			return a.values
		}
	}

	return []string{}
}

// GetOneValueByName() ; a quick way to get a single attribute value
func (self *LdapEntry) GetOneValueByName(attrib string) (string, error) {

	for _, a := range self.values {
		if a.Name() == attrib {
			return a.values[0], nil
		}
	}

	return "", errors.New(fmt.Sprintf("LdapEntry::GetOneValueByName() error : attribute %s not found", attrib))
}

// ToText() return a string representating self LdapEntry
func (self *LdapEntry) ToText() string {

	txt := fmt.Sprintf("dn: %s\n", self.dn)

	for _, a := range self.values {
		txt = txt + fmt.Sprintf("%s\n", a.ToText())
	}

	return txt
}

// Append() add e to LdapSearchResult array
func (self *LdapSearchResult) Append(e LdapEntry) {
	self.entries = append(self.entries, e)
}

// ToText() : a quick way to print an LdapSearchResult
func (self *LdapSearchResult) ToText() string {

	txt := fmt.Sprintf("# query : %s\n", self.filter)
	txt = txt + fmt.Sprintf("# num results : %d\n", self.Count())
	txt = txt + fmt.Sprintf("# search : %s\n", self.Filter())
	txt = txt + fmt.Sprintf("# base : %s\n", self.Base())
	txt = txt + fmt.Sprintf("# attributes : [%s]\n", strings.Join(self.Attributes(), ", "))

	for _, e := range self.entries {
		txt = txt + fmt.Sprintf("%s\n", e.ToText())
	}

	return txt
}

// String() : used for fmt.Println(self)
func (self *LdapSearchResult) String() string {
	return self.ToText()
}

// Entries() : returns an array of LdapEntry for self
func (self *LdapSearchResult) Entries() []LdapEntry {
	return self.entries
}

// Count() : returns number of results for self search.
func (self *LdapSearchResult) Count() int {
	return len(self.entries)
}

// Filter() : returns filter for self search
func (self *LdapSearchResult) Filter() string {
	return self.filter
}

// Filter() : returns base DN for self search
func (self *LdapSearchResult) Base() string {
	return self.base
}

// Filter() : returns scope for self search
func (self *LdapSearchResult) Scope() int {
	return self.scope
}

// Filter() : returns an array of attributes used for this actual search
func (self *LdapSearchResult) Attributes() []string {
	return self.attributes
}
