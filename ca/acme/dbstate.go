package acme

import (
	sqlraw "database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dta4/dns3l-go/sql"
)

type ACMEStateManagerSQL struct {
	Prov sql.SQLDBProvider
}

type ACMEStateManagerSQLSession struct {
	prov *ACMEStateManagerSQL
	db   *sqlraw.DB
}

func (m *ACMEStateManagerSQL) NewSession() (ACMEStateManagerSession, error) {
	db, err := m.Prov.GetNewDBConn()
	if err != nil {
		return nil, err
	}
	return &ACMEStateManagerSQLSession{db: db, prov: m}, nil
}

func (s *ACMEStateManagerSQLSession) Close() error {
	return s.db.Close()
}

func (s *ACMEStateManagerSQLSession) GetACMECertPrivkeyByID(keyname string, userid string) (string, time.Time, error) {
	row := s.db.QueryRow("SELECT priv_key, expiry_time FROM "+s.prov.Prov.DBName("keycerts")+" WHERE key_name=$1 AND user_id=$2 LIMIT 1",
		keyname, userid)
	var privKeyStr string
	var expiryTimeStr string
	err := row.Scan(&privKeyStr, &expiryTimeStr)
	if err == sqlraw.ErrNoRows {
		return "", time.Time{}, nil
	} else if err != nil {
		return "", time.Time{}, err
	}

	expiryTime, err := sql.DBStrToTime(expiryTimeStr)
	if err != nil {
		return "", time.Time{}, err
	}

	return privKeyStr, expiryTime, nil

}

func (s *ACMEStateManagerSQLSession) PutACMECertData(update bool, uid, keyname, privKeyStr, certStr, issuerCertStr string, expiryTime time.Time) error {
	expiryTimeStr := sql.TimeToDBStr(expiryTime)

	if update {
		log.Debugf("Updating certificate data for key '%s', user '%s' in database",
			keyname, uid)
		_, err := s.db.Exec(`UPDATE `+s.prov.Prov.DBName("keycerts")+` SET cert=$1, issuer_cert=$2, `+
			`expiry_time=$3 WHERE user_id=$4 AND key_name=$5;`,
			certStr, issuerCertStr, expiryTimeStr, uid, keyname)
		if err != nil {
			return fmt.Errorf("problem while storing new cert for existing key in database: %v",
				err)
		}
		return nil
	}

	log.Debugf("Storing new cert/key pair '%s' for user '%s' in database",
		keyname, uid)
	_, err := s.db.Exec(`INSERT INTO `+s.prov.Prov.DBName("keycerts")+` (user_id, key_name, `+
		`priv_key, cert, issuer_cert, expiry_time) values ($1, $2, $3, $4, $5, $6);`,
		uid, keyname, privKeyStr, certStr, issuerCertStr, expiryTimeStr)
	if err != nil {
		return fmt.Errorf("problem while storing new key and cert in database: %v", err)
	}

	return nil

}

func (s *ACMEStateManagerSQLSession) GetACMEUserPrivkeyByID(userid string) (string, string, error) {

	row := s.db.QueryRow(`select privatekey, registration from `+s.prov.Prov.DBName("users")+
		` where user_id = $1 limit 1;`, userid)

	var keyStr string
	var registrationStr string
	err := row.Scan(&keyStr, &registrationStr)
	if err == sqlraw.ErrNoRows {
		return "", "", nil
	} else if err != nil {
		return "", "", err
	}

	return keyStr, registrationStr, nil

}

func (s *ACMEStateManagerSQLSession) PutACMEUser(userid, privatekey,
	registrationStr string, registrationDate time.Time) error {

	_, err := s.db.Exec(`INSERT INTO `+s.prov.Prov.DBName("users")+
		` (user_id, privatekey, registration, registration_date) values ($1, $2, $3, $4);`,
		userid, privatekey, registrationStr, sql.TimeToDBStr(registrationDate))

	if err != nil {
		return fmt.Errorf("problem while obtaining certificate: %v", err)
	}
	return nil
}

func (s *ACMEStateManagerSQLSession) GetResource(keyName, userid, resourceName string) (string, error) {

	returns, err := s.GetResources(keyName, userid, resourceName)
	if err != nil {
		return "", err
	}
	if returns == nil {
		return "", nil
	}
	return returns[0], nil

}

func (s *ACMEStateManagerSQLSession) GetResources(keyName, userid string, resourceNames ...string) ([]string, error) {

	returns := make([]string, len(resourceNames))
	returns_ptr := make([]interface{}, len(resourceNames))
	for i, _ := range returns_ptr {
		//hackity hack
		returns_ptr[i] = &returns[i]
	}

	// TODO: validate -> just to be sure it is not wrongly used in the future.
	// #nosec G202 (dbFieldName is never user input!)
	row := s.db.QueryRow(`SELECT `+strings.Join(resourceNames, ",")+` FROM `+s.prov.Prov.DBName("keycerts")+` WHERE key_name=$1 `+
		`AND user_id=$2 LIMIT 1`, keyName, userid)

	err := row.Scan(returns_ptr...)
	if err == sqlraw.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return returns, nil
}
