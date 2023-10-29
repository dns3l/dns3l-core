package state

import (
	"database/sql"
	"fmt"
)

func getSQLCreateStatementSQLite(dbProv SQLDBProvider, createdb bool) string {
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
	issued_by_email TEXT,
	priv_key TEXT,
	cert TEXT,
	issuer_cert TEXT,
	domains TEXT,
	claim_time TIMESTAMP,
	renewed_time TIMESTAMP,
	next_renewal_time TIMESTAMP,
	valid_start_time TIMESTAMP,
	valid_end_time TIMESTAMP,
	renew_count INTEGER,
	ttl_seconds INTEGER,
	PRIMARY KEY (key_name, ca_id)
	);
`
}

func createWithMySQL(db *sql.DB, dbProv SQLDBProvider, createdb bool) error {

	if createdb {

		log.Info("Creating database...")
		err := dbProv.CreateDB()
		if err != nil {
			log.WithError(err).Warn("Creating database failed. Maybe you already created it from an account with " +
				"sufficient rights, then this message can be ignored.")
		} else {
			log.Info("Created database.")
		}
	}

	log.Info("Setting or updating tables...")

	// Ensure sql_mode is set correctly
	// Default for MariaDB >= 10.2.4
	_, err := db.Exec("SET sql_mode = 'STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';")
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("acmeusers") + ` (
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
	ca_id CHAR(63),
	acme_user CHAR(255),
	issued_by VARCHAR(255),
	issued_by_email VARCHAR(255),
	priv_key TEXT,
	cert MEDIUMTEXT,
	issuer_cert MEDIUMTEXT,
	claim_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	renewed_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	next_renewal_time TIMESTAMP DEFAULT 0,
	valid_start_time TIMESTAMP DEFAULT 0,
	valid_end_time TIMESTAMP DEFAULT 0,
	renew_count INTEGER,
	ttl_seconds INTEGER DEFAULT 0,
	PRIMARY KEY (key_name, ca_id)
	);`)
	if err != nil {
		return err
	}

	//Needed in a separate table to quickly filter for subdomains.
	//We use the built-in MySQL prefix index, but then we need to
	//reverse the characters in the domain names
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("domains") + ` (
	dom_name_rev CHAR(255),
	key_name CHAR(255),
	ca_id VARCHAR(255),
	is_first_domain BOOLEAN,
	PRIMARY KEY (dom_name_rev, key_name, ca_id)
	);`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS ` + dbProv.DBName("suffix_domains_idx") + `
	ON ` + dbProv.DBName("domains") + `(dom_name_rev(255));`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS ` + dbProv.DBName("domains_per_key") + `
	ON ` + dbProv.DBName("domains") + `(key_name, ca_id);`)
	if err != nil {
		return err
	}

	log.Info("Tables set or updated.")

	return nil

}

func CreateSQLTables(dbProv SQLDBProvider, createdb bool) error {

	db, err := dbProv.GetDBConn()
	if err != nil {
		return err
	}

	if dbProv.GetType() == "sqlite3" {
		//in sqlite, we don't need to create databases
		_, err = db.Exec(getSQLCreateStatementSQLite(dbProv, createdb))
		if err != nil {
			return err
		}
	} else if dbProv.GetType() == "mysql" {
		err = createWithMySQL(db, dbProv, createdb)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf(
			"creating tables for SQL type '%s' is unsupported", dbProv.GetType())
	}

	return nil
}

// Called during the tests
func Truncate(dbProv SQLDBProvider) error {

	db, err := dbProv.GetDBConn()
	if err != nil {
		return err
	}

	for _, table := range []string{"acmeusers", "keycerts", "domains"} {
		_, err = db.Exec(`TRUNCATE TABLE ` + dbProv.DBName(table) + `;`)
		if err != nil {
			return err
		}

	}

	return nil

}
