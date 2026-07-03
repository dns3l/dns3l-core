package state

/*

// DISABLED, since sqlparser does not support 'COUNT(*) OVER ()'
// We rely on the thorough comptest for DB conformity instead.

func Test(t *testing.T) {
	q, pms := constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "", "", []string{}, "", nil)

	fmt.Println(q, pms)
	assertSQLValid(q)

	q, pms = constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "SomeKey", "", []string{}, "", &util.PaginationInfo{Limit: 0, Offset: 0})

	fmt.Println(q, pms)
	assertSQLValid(q)

	q, pms = constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "", "SomeCA", []string{}, "", &util.PaginationInfo{Limit: 1, Offset: 0})

	fmt.Println(q, pms)
	assertSQLValid(q)

	q, pms = constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "", "", []string{"example.com", "example.net"}, "bar.example.com", &util.PaginationInfo{Limit: 0, Offset: 3})

	fmt.Println(q, pms)
	assertSQLValid(q)

	q, pms = constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "", "SomeCA", []string{"example.com", "example.net"}, "", &util.PaginationInfo{Limit: 1, Offset: 4})

	fmt.Println(q, pms)
	assertSQLValid(q)

	q, pms = constructListCACertsQuery(func(name string) string {
		return "dns3l_" + name
	}, "", "SomeCA", []string{"example.com", "example.net"}, "bar.example.com", nil)

	fmt.Println(q, pms)
	assertSQLValid(q)
}

func assertSQLValid(sql string) {
	_, err := sqlparser.Parse(sql)
	if err != nil {
		panic(err)
	}
}

*/
