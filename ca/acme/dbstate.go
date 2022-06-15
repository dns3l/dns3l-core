package acme

import (
	sqlraw "database/sql"
	"fmt"
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
