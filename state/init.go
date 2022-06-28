package state

func getSQLCreateStatement(dbProv SQLDBProvider) string {
	return `
-- CREATE INDEX user_idx ON ` + dbProv.DBName("acmeusers") + `(user_id);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("acmeusers") + ` (
	user_id TEXT,
	ca_id TEXT,
	privatekey TEXT,
	registration TEXT,
	registration_date TIMESTAMP,
	PRIMARY KEY (user_id, ca_id)
	);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("keycerts") + ` (
	key_name TEXT, ca_id TEXT, acme_user TEXT,
	issued_by TEXT,
	priv_key TEXT,
	cert TEXT,
	issuer_cert TEXT,
	domains TEXT,
	claim_time TIMESTAMP,
	renew_time TIMESTAMP,
	valid_start_time TIMESTAMP,
	valid_end_time TIMESTAMP,
	renew_count INTEGER,
	PRIMARY KEY (key_name, ca_id)
	);
`
}

func CreateSQLDB(dbProv SQLDBProvider) error {

	db, err := dbProv.GetNewDBConn()

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(getSQLCreateStatement(dbProv))
	if err != nil {
		panic(err)
	}

	return nil
}
