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


func GetUsersInGroup(group string) (users, groups []string) {
	// Search for the given group
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s))", group)
	searchRequest := ldap.NewSearchRequest(
		"dc=ad,dc=global",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
//		[]string{"member", "cn", "dn", "sAMAccountName", "name", "distinguishedName"},
		[]string{"member", "cn", "dn", "sAMAccountName" },
//		Attributes: []string{"member", "cn", "dn", "sAMAccountName"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		fmt.Printf("User does not exist or too many entries returned :  \n")
		//		log.Fatal("User does not exist or too many entries returned")
	} else {
		for _, entry := range sr.Entries[0].Attributes {
			if entry.Name == "member" {
				for _, vall := range entry.Values {
					re := regexp.MustCompile("OU=([^,]+)")
					matches := re.FindAllString(vall, -1)
					//					fmt.Println(matches[1])

					for _, aMatch := range matches {
						if aMatch == "OU=Users" {
							vall2 := strings.Replace(vall, "\\,", "", -1)
							re2 := regexp.MustCompile("CN=([^,]+)")
							matches2 := re2.FindStringSubmatch(vall2)
							a := strings.Split(matches2[1], " ")
							for i := len(a)/2 - 1; i >= 0; i-- {
								opp := len(a) - 1 - i
								a[i], a[opp] = a[opp], a[i]
							}
							sw := ""
							for k, b := range a {
								sw = sw + b
								if k < len(a)-1 {
									sw = sw + " "
								}
							}
							fmt.Printf("\"%s\" -> \"%s\"\n", group, sw)
							users = append(users, sw)
						} else if aMatch == "OU=DistributionGroups" || aMatch == "OU=Distribution Groups" || aMatch == "OU=_Distribution Groups" || aMatch == "OU=_Security Groups" || aMatch == "OU=_Divisional" {
							//	vall2 := strings.Replace(vall, "\\", "", -1)
							re2 := regexp.MustCompile("CN=([^,]+)")
							matches2 := re2.FindStringSubmatch(vall)
							str2 := strings.Replace(matches2[1], "\\", "", -1)
							fmt.Printf("\"%s\" -> \"%s\"\n", group, str2)
							groups = append(groups, str2)
							nusers, ngropus := GetUsersInGroup(str2)
							users = append(users, nusers...)
							groups = append(groups, ngropus...)
						}
					}
				}
			}
		}
	}
	return users, groups
}

func GetUnamesInGroup(group string) (users, groups []string) {

	// Search for the given group
	filter := fmt.Sprintf("(&(objectCategory=group)(cn=%s))", group)
/*	searchRequest := ldap.NewSearchRequest(
		"dc=ad,dc=global",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
//		[]string{"member", "cn", "dn", "sAMAccountName", "name", "distinguishedName"},
//		[]string{"member", "cn", "dn", "sAMAccountName"},
		[]string{"member", "cn", "dn", "samaccountname"},

		nil,
	)*/
	sr, err := l.Search(&ldap.SearchRequest{
		BaseDN: "dc=ad,dc=global",
		//		BaseDN: base,
		Scope:  2, // subtree
		Filter: filter,
		Attributes: []string{"member", "cn", "dn"},
		//Attributes: []string{"member", "cn", "dn", "samaccountname"},
	})


//	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		fmt.Printf("User does not exist or too many entries returned :  \n")
		//		log.Fatal("User does not exist or too many entries returned")
	} else {
		for _, entry := range sr.Entries[0].Attributes {
			if entry.Name == "member" {
				for _, vall := range entry.Values {
					re := regexp.MustCompile("OU=([^,]+)")
					matches := re.FindAllString(vall, -1)
					for _, aMatch := range matches {
						if aMatch == "OU=Users" {

							vall2 := strings.Replace(vall, "\\,", "", -1)
							re2 := regexp.MustCompile("CN=([^,]+)")
							//re2 := regexp.MustCompile("CN=([^,]+),([^,]+)")
							matches2 := re2.FindStringSubmatch(vall2)
/*							a := strings.Split(matches2[1], " ")
							for i := len(a)/2 - 1; i >= 0; i-- {
								opp := len(a) - 1 - i
								a[i], a[opp] = a[opp], a[i]
							}
							sw := ""
							for k, b := range a {
								sw = sw + b
								if k < len(a)-1 {
									sw = sw + " "
								}

							}*/
							fmt.Printf("\"%s\" -> \"%s\"\n", group, matches2[1])
							us, _ := GetUserDN(matches2[1])
//							us, _ := GetUserDN(sw)

							users = append(users, us...)
						} else if aMatch == "OU=DistributionGroups" || aMatch == "OU=Distribution Groups" || aMatch == "OU=_Distribution Groups" || aMatch == "OU=_Security Groups" || aMatch == "OU=_Divisional" {
							re2 := regexp.MustCompile("CN=([^,]+)")
							matches2 := re2.FindStringSubmatch(vall)
							str2 := strings.Replace(matches2[1], "\\", "", -1)
							fmt.Printf("\"%s\" -> \"%s\"\n", group, str2)
							groups = append(groups, str2)
							nusers, ngropus := GetUnamesInGroup(str2)
							users = append(users, nusers...)
							groups = append(groups, ngropus...)
						}
					}
				}
			}
		}
	}
	return users, groups
}

/*
 * Returns the DN of the object representing the authenticated user.
 */
func GetUserDN(name string) ([]string, error) {
	var uname [] string
	// Find the distinguished name for the user if userPrincipalName used for login
	//		filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(displayName=%s)", ldap.EscapeFilter(name))
	//	filter := fmt.Sprintf("(anr=%s) and (OU=UsersInternal)", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(anr=%s)", ldap.EscapeFilter(name))
	filter := fmt.Sprintf("(&(anr=%s)(objectCategory=person)(objectClass=user))", ldap.EscapeFilter(name))
	//filter := fmt.Sprintf("(&(%s)(objectCategory=person)(objectClass=user))", ldap.EscapeFilter(name))

	//base := fmt.Sprintf("dc=ad,dc=global,cn=%s", g)
	result, err := l.Search(&ldap.SearchRequest{
		BaseDN: "dc=ad,dc=global",
		Scope:  2, // subtree
		Filter: filter,
		Attributes: []string{"sAMAccountName"},
	})
	if err != nil {
		return uname, fmt.Errorf("LDAP search failed for detecting user: %v", err)
	}
	if len(result.Entries) == 0 {
		fmt.Printf("Not found in AD: %s \n", name)
	} else if len(result.Entries) > 1 {
		fmt.Printf("More tham one hit for %s : %v \n", name, len(result.Entries))
	}
	for _, e := range result.Entries {
		if strings.Contains(e.DN, "OU=User") {
			uname = append(uname, e.GetAttributeValue("sAMAccountName"))
		} else {
			fmt.Printf("   Skipping: %s \n", e.GetAttributeValue("sAMAccountName"))
		}
	}

	return uname, nil
}

func CloseAD() {
	l.Close()

}
