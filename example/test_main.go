package main

/*
 * Author : Marc Quinton / 2012.
 *
 * ldapsearch command mimics openldap/seach command. Supported options :
 *  - host : ldap[s]://hostname:port/ format,
 *  - user,
 *  - password,
 *  - base
 *
 *  arguments : filter [attributes]
 *  - filter is an LDAP filter (ex: objectClass=*, cn=*admin*", ...
 *  - attributes is an LDAP attribute list ; can be empty. ex: cn, sn, givenName, mail, ...
 *
 */

import (
	//	"errors"
	"fmt"
	"openldap"
)

func main() {
	ldapConn, err := openldap.Initialize("ldap://localhost:389/")
	if err != nil {
		fmt.Println("Initialize error %v", err)
		return
	}

	ldapConn.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)
	err = ldapConn.Bind("cn=admin,dc=example,dc=com", "lab123")
	if err != nil {
		fmt.Println("ldap bind error ", err)
		return
	}

	control := &openldap.LdapControl{}
	control.Ldctl_oid = "1.2.840.113556.1.4.528"
	control.Ldctl_iscritical = 1

	searchREQ := &openldap.LdapSearchRequest{
		LdapConn:      ldapConn,
		Base:          "dc=example,dc=com",
		Scope:         openldap.LDAP_SCOPE_SUBTREE,
		Filter:        "(!(cn=miners))",
		Attributes:    []string{"dn", "cn"},
		ServerControl: control,
		ClientControl: nil,
	}

	_, err = ldapConn.SearchExt(searchREQ)
	if err != nil {
		fmt.Println("search ext error ", err)
		return

	}

}
