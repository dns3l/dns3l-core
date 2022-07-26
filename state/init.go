package state

import (
	"database/sql"
	"fmt"
)

func getSQLCreateStatementSQLite(dbProv SQLDBProvider) string {
	return `
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("acmeusers") + ` (
	user_id TEXT,
	ca_id TEXT,
	privatekey TEXT,
	registration TEXT,
	registration_date TIMESTAMP,
	PRIMARY KEY (user_id, ca_id)
	);
CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("keycerts") + ` (
	key_name TEXT,
	key_rz TEXT,
	ca_id TEXT,
	acme_user TEXT,
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

func getSQLCreateStatementMySQL(db *sql.DB, dbProv SQLDBProvider) error {

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("acmeusers") + ` (
	user_id CHAR(255),
	ca_id CHAR(64),
	privatekey TEXT,
	registration TEXT,
	registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (user_id, ca_id)
	);`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("keycerts") + ` (
	key_name CHAR(255),
	key_rz VARCHAR(255),
	ca_id CHAR(63),
	acme_user CHAR(255),
	issued_by VARCHAR(255),
	priv_key TEXT,
	cert MEDIUMTEXT,
	issuer_cert MEDIUMTEXT,
	domains TEXT,
	claim_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	renew_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	valid_start_time TIMESTAMP DEFAULT 0,
	valid_end_time TIMESTAMP DEFAULT 0,
	renew_count INTEGER,
	PRIMARY KEY (key_name, ca_id)
	);`)
	return err
}

func CreateSQLDB(dbProv SQLDBProvider) error {

	db, err := dbProv.GetNewDBConn()
	if err != nil {
		return err
	}

	if dbProv.GetType() == "sqlite3" {
		_, err = db.Exec(getSQLCreateStatementSQLite(dbProv))
		if err != nil {
			return err
		}
	} else if dbProv.GetType() == "mysql" {
		err = getSQLCreateStatementMySQL(db, dbProv)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf(
			"creating DB for SQL type '%s' is unsupported", dbProv.GetType())
	}

	return nil
}
