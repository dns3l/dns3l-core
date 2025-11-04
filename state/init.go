package state

import (
	"database/sql"
	"fmt"
)

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
	ca_id CHAR(63),
	acme_user CHAR(255),
	issued_by VARCHAR(255),
	issued_by_email VARCHAR(255),
	priv_key TEXT,
	cert MEDIUMTEXT,
	issuer_cert MEDIUMTEXT,
	claim_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	renewed_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	next_renewal_time TIMESTAMP DEFAULT NULL,
	valid_start_time TIMESTAMP DEFAULT NULL,
	valid_end_time TIMESTAMP DEFAULT NULL,
	last_access_time TIMESTAMP DEFAULT NULL,
	access_count INTEGER DEFAULT 0,
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

	_, err = db.Exec(`DROP PROCEDURE IF EXISTS ` + dbProv.DBName("read_increment") + `;`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE PROCEDURE ` + dbProv.DBName("read_increment") + ` (IN my_key_name CHAR(255), IN my_ca_id CHAR(63))
	BEGIN
	  UPDATE ` + dbProv.DBName("keycerts") + ` SET last_access_time = utc_timestamp(), access_count = access_count + 1
	  WHERE key_name = my_key_name AND ca_id = my_ca_id;
	END;`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ` + dbProv.DBName("renew_info") + ` (
	renew_info TEXT
	);`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`DROP PROCEDURE IF EXISTS ` + dbProv.DBName("set_renew_info") + ` ;`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE PROCEDURE ` + dbProv.DBName("set_renew_info") + ` (IN myrenew_info TEXT)
	BEGIN
	  DECLARE EXIT HANDLER FOR SQLEXCEPTION, NOT FOUND
	  BEGIN
	    ROLLBACK;
	  END;
	  START TRANSACTION;
	    TRUNCATE TABLE ` + dbProv.DBName("renew_info") + `;
        INSERT INTO ` + dbProv.DBName("renew_info") + ` VALUES (myrenew_info);
	  COMMIT;
	END;`)
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

	if dbProv.GetType() == "mysql" {
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
