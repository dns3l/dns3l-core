package state

import (
	"os"
)

func getSQLInitStatement(dbProv SQLDBProvider) string {
	return `
-- CREATE INDEX user_idx ON ` + dbProv.DBName("users") + `(user_id);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("users") + ` (user_id TEXT, ca_id TEXT, privatekey TEXT, registration TEXT, registration_date TIMESTAMP, PRIMARY KEY (user_id, ca_id));
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("keycerts") + ` (key_name TEXT, ca_id TEXT, acme_user TEXT, issued_by TEXT, priv_key TEXT, cert TEXT, issuer_cert TEXT, domains TEXT, expiry_time TIMESTAMP, valid_start_time TIMESTAMP, PRIMARY KEY (key_name, ca_id));
`
}

func InitDB(dbProv SQLDBProvider) error {
	err := os.Remove("test.db")
	if err != nil {
		//foo
	}

	db, err := dbProv.GetNewDBConn()

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(getSQLInitStatement(dbProv))
	if err != nil {
		panic(err)
	}

	return nil
}
