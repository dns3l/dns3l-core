package sql

import (
	"os"
)

func getSQLInitStatement(dbProv SQLDBProvider) string {
	return `
-- CREATE INDEX user_idx ON ` + dbProv.DBName("users") + `(user_id);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("users") + ` (user_id TEXT PRIMARY KEY, privatekey TEXT, registration TEXT, registration_date TIMESTAMP);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("keycerts") + ` (user_id TEXT, key_name TEXT, priv_key TEXT, cert TEXT, issuer_cert TEXT, expiry_time TIMESTAMP, PRIMARY KEY (user_id, key_name));
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
