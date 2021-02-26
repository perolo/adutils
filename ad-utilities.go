package ad_utils

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"regexp"
	"strings"
)

var l *ldap.Conn

type ADUser struct {
	Uname string
	Name  string
	Err string
	Rfa string
	Mail  string
	DN string
}
type ADHierarchy struct {
	Name  string  `json:"name"`
	Parent string  `json:"parent"`
	Tooltip string  `json:"tooltip"`
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

func GetUnamesInGroup(group string) (users []ADUser, err error) {

	// Search for the given group
	//group = "#AAAB - GTT - RDO Stockholm Embedded Employees"
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(group))
	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN: "dc=ad,dc=global",
		Scope:      2, // subtree
		Filter:     filter,
		Attributes: []string{"member", "cn", "dn"},
		//Attributes: []string{"member", "cn", "dn", "samaccountname"},
	})

	//	sr, err := l.Search(searchRequest)
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
		dn:= sr.Entries[0].DN
//		dn := "CN=//#AAAB - GTT - RDO Stockholm Embedded Employees,OU=_Divisional,OU=DistributionGroups,OU=AAAB,OU=SSC,DC=ad,DC=global"

//		filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=%s))", dn)
		filter2 := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=%s))", ldap.EscapeFilter(dn))
		//base := fmt.Sprintf("dc=ad,dc=global,cn=%s", g)
		result, err := l.Search(&ldap.SearchRequest{
			BaseDN:     "dc=ad,dc=global",
			Scope:      ldap.ScopeWholeSubtree, // subtree
			//DerefAliases: ldap.NeverDerefAliases,
			Filter:     filter2,
			Attributes: []string{"sAMAccountName"},
		})
		if err != nil {
			return users, fmt.Errorf("LDAP search failed for user: %s",dn )

		}
		if len(result.Entries) == 0 {

		} else {
			for _, e := range result.Entries {
					var newUsr ADUser
					newUsr.Uname = e.GetAttributeValue("sAMAccountName")
					newUsr.DN = e.DN
				users = append(users, newUsr)
			}

		}
	}
	return users, err
}

func ExpandHierarchy(group string, hierarchy [] ADHierarchy) (groups []string, hierarchies [] ADHierarchy, err error) {

	// Search for the given group
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", group)

	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN: "dc=ad,dc=global",
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
		err2 := fmt.Errorf("User does not exist or too many entries returned : %v", len(sr.Entries))
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
							ngroups, nhierachy, err3 := ExpandHierarchy(str2, hierarchy )
							if err != nil {
								return nil, nil, err3
							}
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

func GetUserDN(name string) (ADUser, error) {
//	var uname []ADUser
	var theUser ADUser
	// Find the distinguished name for the user if userPrincipalName used for login
	//		filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(displayName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(anr=%s) and (OU=UsersInternal)", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(anr=%s)", ldap.EscapeFilter(name))
//P	filter := fmt.Sprintf("(&(anr=%s)(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(&(%s)(objectCategory=person)(objectClass=user))", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(&(anr=%s)(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=%s,DC=ad,DC=global)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(name), gr)
	//ReplaceAccents(name)
	//filter := fmt.Sprintf("(&(anr=%s)(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(name))
//Pfilter:=fmt.Sprintf("(%s)",ldap.EscapeFilter(name))
//dn:= "CN=#AAAB - GTT - RDO Stockholm Software1,OU=_Divisional,OU=DistributionGroups,OU=AAAB,OU=SSC,DC=ad,DC=global"
//dn:= "CN=/#AAAB - GTT - RDO Stockholm Software1,OU=_Divisional,OU=DistributionGroups,OU=AAAB,OU=SSC,DC=ad,DC=global"
//dn:= "CN=//#AAAB - GTT - RDO Stockholm Software1,OU=_Divisional,OU=DistributionGroups,OU=AAAB,OU=SSC,DC=ad,DC=global"
//dn:= "CN=G-AAAB-GTT-Group IP Management-sec,OU=_Divisional,OU=Security,OU=SecurityGroups,OU=AAAB,OU=SSC,DC=ad,DC=global"
//	filter:=fmt.Sprintf("(%s)",name)
//filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=%s))", ldap.EscapeFilter(dn))
	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(samaccountname=%s))", ldap.EscapeFilter(name))
	//base := fmt.Sprintf("dc=ad,dc=global,cn=%s", g)
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN:     "dc=ad,dc=global",
		Scope:      ldap.ScopeWholeSubtree, // subtree
		DerefAliases: ldap.NeverDerefAliases,
		Filter:     filter,
		Attributes: []string{"sAMAccountName"},
	})
	if err != nil {
		return theUser, fmt.Errorf("LDAP search failed for user: %v", err)

	}
	if len(result.Entries) == 0 {
		fmt.Printf("Not found in AD: %s \n", name)
		return theUser, fmt.Errorf("Not found in AD: %s \n", name)

	} else if len(result.Entries) > 1 {
				fmt.Printf("More tham one hit for %s : %v \n", name, len(result.Entries))
				return theUser, fmt.Errorf("More tham one hit for: %s \n", name)
	} else if len(result.Entries) == 1 {
		e := result.Entries[0]
		if strings.Contains(e.DN, "OU=User") {
			theUser.DN = e.DN
		} else {
			fmt.Printf("Not found in AD as User: %s \n", name)
			return theUser, fmt.Errorf("Not found in AD: %s \n", name)
		}
	} else {
		fmt.Printf("Not found in AD Que?: %s \n", name)

	}

	return theUser, nil
}


func CloseAD() {
	l.Close()
}
