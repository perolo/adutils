package adutils

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"regexp"
	"sourcery.assaabloy.net/perolo/jira-client"
	"strings"
)

var l *ldap.Conn

type ADUser struct {
	Uname string
	Name  string
	Err   string
	Rfa   jira.Issue
	Mail  string
	DN    string
}
type ADHierarchy struct {
	Name    string `json:"name"`
	Parent  string `json:"parent"`
	Tooltip string `json:"tooltip"`
}

func InitAD(user string, pass string) {

	var err error
	l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", "ad.global", 389)) //3268
	if err != nil {
		log.Fatal(err)
	}
	//defer l.Close()

	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}

	// First bind with a read only user
	err = l.Bind(user, pass)
	if err != nil {
		log.Fatal(err)
	}

}
func Difference(a []ADUser, b map[string]ADUser) []ADUser {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[strings.ToLower(x.Uname)] = struct{}{}
	}
	var diff []ADUser
	for _, x := range a {
		if _, found := mb[strings.ToLower(x.Uname)]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func Difference2(a map[string]ADUser, b []ADUser) []ADUser {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[strings.ToLower(x.Uname)] = struct{}{}
	}
	var diff []ADUser
	for _, x := range a {
		if _, found := mb[strings.ToLower(x.Uname)]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func GetUnamesInGroup(group string, basedn string) (users []ADUser, err error) {

	// Search for the given group
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(group))
	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:     basedn,
		Scope:      2, // subtree
		Filter:     filter,
		Attributes: []string{"member", "cn", "dn"},
	})

	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		fmt.Printf("User does not exist or too many entries returned :  \n")
		var erru ADUser
		erru.Name = group
		erru.DN = filter

		//		log.Fatal("User does not exist or too many entries returned")
	} else {
		dn := sr.Entries[0].DN

		//		filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=%s))", dn)
		//filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=%s))", ldap.EscapeFilter(dn))
		//filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(memberOf=%s))", ldap.EscapeFilter(dn))
		//filter2 := fmt.Sprintf("(&(objectClass=user)(memberOf=%s))", dn)
		filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(dn))

		result, err := l.Search(&ldap.SearchRequest{
			BaseDN: basedn,
			Scope:  ldap.ScopeWholeSubtree, // subtree
			//DerefAliases: ldap.NeverDerefAliases,
			Filter:     filter2,
			Attributes: []string{"sAMAccountName", "mail", "displayName"},
		})
		if err != nil {
			return users, fmt.Errorf("LDAP search failed for user: %s", dn)

		}
		if len(result.Entries) == 0 {
			//fmt.Printf("filter2 = %s, count: %v \n", filter2,  len(result.Entries))
		} else {
			for _, e := range result.Entries {
				var newUsr ADUser
				newUsr.Uname = e.GetAttributeValue("sAMAccountName")
				newUsr.Mail = e.GetAttributeValue("mail")
				newUsr.Name = e.GetAttributeValue("displayName")
				newUsr.DN = e.DN
				users = append(users, newUsr)
			}
			//			fmt.Printf("filter2 = %s, count: %v \n", filter2,  len(result.Entries))
		}
	}
	return users, err
}

func ExpandHierarchy(group string, hierarchy []ADHierarchy, basedn string) (groups []string, hierarchies []ADHierarchy, err error) {

	// Search for the given group
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", group)
	//	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s))", group)

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN:     basedn,
		Scope:      2, // subtree
		Filter:     filter,
		Attributes: []string{"member", "cn", "dn"},
	})

	if err != nil {
		return nil, nil, err
		//		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		//fmt.Printf("User does not exist or too many entries returned :  \n")
		err2 := fmt.Errorf("user does not exist or too many entries returned : %v", len(sr.Entries))
		return nil, nil, err2
		//		log.Fatal(err)
		//		log.Fatal("User does not exist or too many entries returned")
	} else {
		for _, entry := range sr.Entries[0].Attributes {
			if entry.Name == "member" {
				for _, vall := range entry.Values {
					re := regexp.MustCompile("OU=([^,]+)")
					matches := re.FindAllString(vall, -1)
					for _, aMatch := range matches {
						if aMatch == "OU=DistributionGroups" || aMatch == "OU=_Security Groups" || aMatch == "OU=SecurityGroups" {
							re2 := regexp.MustCompile("CN=([^,]+)")
							matches2 := re2.FindStringSubmatch(vall)
							str2 := strings.Replace(matches2[1], "\\", "", -1)
							var newhierarchy ADHierarchy
							newhierarchy.Name = str2
							newhierarchy.Parent = group
							hierarchies = append(hierarchies, newhierarchy)
							fmt.Printf("\"%s\" -> \"%s\"\n", group, str2)
							groups = append(groups, str2)
							ngroups, nhierachy, _ := ExpandHierarchy(str2, hierarchy, basedn)
							groups = append(groups, ngroups...)
							hierarchies = append(hierarchies, nhierachy...)
						}
					}
				}
			}
		}
	}
	return groups, hierarchies, err
}

/*
 * Returns the DN of the object representing the authenticated user.
 */

func GetActiveUserDN(name string, basedn string) (ADUser, error) {
	var theUser ADUser
	//	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(samaccountname=%s))", ldap.EscapeFilter(name))
	filter := fmt.Sprintf("(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(samaccountname=%s))", ldap.EscapeFilter(name))

	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:       basedn,
		Scope:        ldap.ScopeWholeSubtree, // subtree
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"sAMAccountName", "mail", "displayName"},
	})
	if err != nil {
		return theUser, fmt.Errorf("LDAP search failed for user: %v", err)

	}
	if len(result.Entries) == 0 {
		fmt.Printf("Not found in AD: %s \n", name)
		return theUser, fmt.Errorf("Not found in AD: %s \n", name)

	} else if len(result.Entries) > 1 {
		fmt.Printf("More than one hit for %s : %v \n", name, len(result.Entries))
		return theUser, fmt.Errorf("More than one hit for: %s \n", name)
	} else if len(result.Entries) == 1 {
		e := result.Entries[0]
		if strings.Contains(e.DN, "OU=User") || strings.Contains(e.DN, "OU=Administrators") {
			theUser.DN = e.DN
			theUser.Mail = e.GetAttributeValue("mail")
			theUser.Name = e.GetAttributeValue("displayName")
		} else {
			fmt.Printf("Not found in AD as User: %s \n", name)
			return theUser, fmt.Errorf("Not found in AD: %s \n", name)
		}
	} else {
		fmt.Printf("Not found in AD Que?: %s \n", name)

	}

	return theUser, nil
}

func GetAllUserDN(name string, basedn string) (ADUser, error) {
	var theUser ADUser
	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(samaccountname=%s))", ldap.EscapeFilter(name))
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:       basedn,
		Scope:        ldap.ScopeWholeSubtree, // subtree
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"sAMAccountName", "mail", "displayName", "ObjectGUID"}, //"EmployeeNumber"
	})
	if err != nil {
		return theUser, fmt.Errorf("LDAP search failed for user: %v", err)

	}
	if len(result.Entries) == 0 {
		fmt.Printf("Not found in AD: %s \n", name)
		return theUser, fmt.Errorf("Not found in AD: %s \n", name)

	} else if len(result.Entries) > 1 {
		fmt.Printf("More than one hit for %s : %v \n", name, len(result.Entries))
		return theUser, fmt.Errorf("More than one hit for: %s \n", name)
	} else if len(result.Entries) == 1 {
		e := result.Entries[0]
		if strings.Contains(e.DN, "OU=User") {
			theUser.DN = e.DN
			theUser.Mail = e.GetAttributeValue("mail")
			theUser.Name = e.GetAttributeValue("displayName")
		} else {
			fmt.Printf("Not found in AD as User: %s \n", name)
			return theUser, fmt.Errorf("Not found in AD: %s \n", name)
		}
	} else {
		fmt.Printf("Not found in AD Que?: %s \n", name)

	}

	return theUser, nil
}

func GetActiveEmailDN(email string, basedn string) ([]ADUser, error) {
	var theUser []ADUser
	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=%s))", ldap.EscapeFilter(email))
	//	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(mail=%s))", ldap.EscapeFilter(email))
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:       basedn,
		Scope:        ldap.ScopeWholeSubtree, // subtree
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"sAMAccountName", "mail", "displayName"},
	})
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed for email: %v", err)

	}
	if len(result.Entries) == 0 {
		fmt.Printf("Email not found in AD: %s \n", email)
		return theUser, fmt.Errorf("Email not found in AD: %s \n", email)

	} else if len(result.Entries) >= 1 {
		if len(result.Entries) > 1 {
			fmt.Printf("More than one hit for %s : %v \n", email, len(result.Entries))
		}
		for _, entr := range result.Entries {
			var aUser ADUser
			aUser.DN = entr.DN
			aUser.Mail = entr.GetAttributeValue("mail")
			aUser.Name = entr.GetAttributeValue("displayName")
			aUser.Uname = entr.GetAttributeValue("sAMAccountName")
			theUser = append(theUser, aUser)
		}
		return theUser, nil
	}

	return theUser, nil
}

func GetAllEmailDN(email string, basedn string) ([]ADUser, error) {
	var theUser []ADUser
	//	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=%s))", ldap.EscapeFilter(email))
	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(mail=%s))", ldap.EscapeFilter(email))
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:       basedn,
		Scope:        ldap.ScopeWholeSubtree, // subtree
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   []string{"sAMAccountName", "mail", "displayName"},
	})
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed for email: %v", err)

	}
	if len(result.Entries) == 0 {
		fmt.Printf("Email not found in AD: %s \n", email)
		return theUser, fmt.Errorf("Email not found in AD: %s \n", email)

	} else if len(result.Entries) >= 1 {
		if len(result.Entries) > 1 {
			fmt.Printf("More than one hit for %s : %v \n", email, len(result.Entries))
		}
		for _, entr := range result.Entries {
			var aUser ADUser
			aUser.DN = entr.DN
			aUser.Mail = entr.GetAttributeValue("mail")
			aUser.Name = entr.GetAttributeValue("displayName")
			aUser.Uname = entr.GetAttributeValue("sAMAccountName")
			theUser = append(theUser, aUser)
		}
		return theUser, nil
	}

	return theUser, nil
}

func SearchUserDN(name string, basedn string) ([]ADUser, error) {
	//var uname [] string
	var theUsers []ADUser
	// Find the distinguished name for the user if userPrincipalName used for login
	//		filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(displayName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(anr=%s) and (OU=UsersInternal)", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(anr=%s)", ldap.EscapeFilter(name))
	filter := fmt.Sprintf("(&(anr=%s)(objectCategory=person)(objectClass=user))", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(&(%s)(objectCategory=person)(objectClass=user))", ldap.EscapeFilter(name))

	//base := fmt.Sprintf("dc=ad,dc=global,cn=%s", g)
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:     "dc=ad,dc=global",
		Scope:      2, // subtree
		Filter:     filter,
		Attributes: []string{"sAMAccountName", "mail", "displayName"},
	})
	if err != nil {
		return theUsers, fmt.Errorf("LDAP search failed for detecting user: %v", err)
	}
	if len(result.Entries) == 0 {
		fmt.Printf("Not found in AD: %s \n", name)
	} else if len(result.Entries) > 1 {
		fmt.Printf("More tham one hit for %s : %v \n", name, len(result.Entries))
	}
	for _, e := range result.Entries {
		if strings.Contains(e.DN, "OU=User") {
			var aUser ADUser
			aUser.DN = e.DN
			aUser.Mail = e.GetAttributeValue("mail")
			aUser.Name = e.GetAttributeValue("displayName")
			aUser.Uname = e.GetAttributeValue("sAMAccountName")
			theUsers = append(theUsers, aUser)
		} else {
			fmt.Printf("   Skipping: %s \n", e.GetAttributeValue("sAMAccountName"))
		}
	}

	return theUsers, nil
}

func CloseAD() {
	l.Close()
}
