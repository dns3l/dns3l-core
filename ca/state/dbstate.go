package state

import (
	sqlraw "database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/common"
	"github.com/dta4/dns3l-go/state"
)

type CAStateManagerSQL struct {
	Prov state.SQLDBProvider
}

type CAStateManagerSQLSession struct {
	prov *CAStateManagerSQL
	db   *sqlraw.DB
}

func (m *CAStateManagerSQL) NewSession() (types.CAStateManagerSession, error) {
	db, err := m.Prov.GetNewDBConn()
	if err != nil {
		return nil, err
	}
	return &CAStateManagerSQLSession{db: db, prov: m}, nil
}

func (s *CAStateManagerSQLSession) Close() error {
	return s.db.Close()
}

func (s *CAStateManagerSQLSession) GetCACertByID(keyname string, caid string) (*types.CACertInfo, error) {
	row := s.db.QueryRow("SELECT priv_key, acme_user, issued_by, domains, renew_time, valid_start_time, valid_end_time "+
		"FROM "+s.prov.Prov.DBName("keycerts")+" WHERE key_name=$1 AND ca_id=$2 LIMIT 1;", keyname,
		caid)
	info := &types.CACertInfo{}
	var renewTimeStr string
	var validStartTimeStr string
	var validEndTimeStr string
	var domainsStr string
	err := row.Scan(&info.PrivKey, &info.ACMEUser, &info.IssuedByUser,
		&domainsStr, &renewTimeStr, &validStartTimeStr, &validEndTimeStr)
	if err == sqlraw.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	info.RenewTime, err = state.DBStrToTime(renewTimeStr)
	if err != nil {
		return nil, err
	}

	info.ValidStartTime, err = state.DBStrToTime(validStartTimeStr)
	if err != nil {
		return nil, err
	}

	info.ValidEndTime, err = state.DBStrToTime(validEndTimeStr)
	if err != nil {
		return nil, err
	}

	info.Domains = strings.Split(domainsStr, ",")

	return info, nil

}

func (s *CAStateManagerSQLSession) DelCACertByID(keyID string, caID string) error {
	res, err := s.db.Exec("DELETE FROM "+s.prov.Prov.DBName("keycerts")+" WHERE key_name=$1 AND ca_id=$2;",
		keyID, caID)
	//TODO "LIMIT 1" not working in sqlite3

	if err == nil {
		count, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if count <= 0 {
			return &common.NotFoundError{RequestedResource: keyID}
		}
	}

	return err

}

func (s *CAStateManagerSQLSession) PutCACertData(update bool, keyname string, caid string, info *types.CACertInfo,
	certStr, issuerCertStr string, claimTime time.Time) error {
	validStartTimeStr := state.TimeToDBStr(info.ValidStartTime)
	validEndTimeStr := state.TimeToDBStr(info.ValidEndTime)
	renewTimeStr := state.TimeToDBStr(info.RenewTime)
	domainsStr := strings.Join(info.Domains, ",")

	if update {
		log.Debugf("Updating certificate data for key '%s' in database",
			keyname)
		_, err := s.db.Exec(`UPDATE `+s.prov.Prov.DBName("keycerts")+` SET cert=$1, issuer_cert=$2, `+
			`acme_user=$3, issued_by=$4, domains=$5, renew_time=$6, valid_start_time=$7,
			valid_end_time=$8, renew_count = renew_count + 1 WHERE key_name=$9 AND ca_id=$10;`,
			certStr, issuerCertStr, info.ACMEUser, info.IssuedByUser, domainsStr,
			renewTimeStr, validStartTimeStr, validEndTimeStr, keyname, caid)
		if err != nil {
			return fmt.Errorf("problem while storing new cert for existing key in database: %v",
				err)
		}
		return nil
	}

	claimTimeStr := state.TimeToDBStr(claimTime)
	log.Debugf("Storing new cert/key pair '%s' for user '%s' in database",
		keyname, info.ACMEUser)
	_, err := s.db.Exec(`INSERT INTO `+s.prov.Prov.DBName("keycerts")+` (key_name, ca_id,`+
		`acme_user, issued_by, priv_key, cert, issuer_cert, domains, claim_time,
		renew_time, valid_start_time, valid_end_time, renew_count) `+
		`values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0);`,
		keyname, caid, info.ACMEUser, info.IssuedByUser, info.PrivKey, certStr,
		issuerCertStr, domainsStr, claimTimeStr, renewTimeStr, validStartTimeStr, validEndTimeStr)
	if err != nil {
		return fmt.Errorf("problem while storing new key and cert in database: %v", err)
	}

	return nil

}

func (s *CAStateManagerSQLSession) GetResource(keyName, caid, resourceName string) (string, error) {

	returns, err := s.GetResources(keyName, caid, resourceName)
	if err != nil {
		return "", err
	}
	if returns == nil {
		return "", nil
	}
	return returns[0], nil

}

func (s *CAStateManagerSQLSession) GetResources(keyName, caid string, resourceNames ...string) ([]string, error) {

	returns := make([]string, len(resourceNames))
	returnsPtr := make([]interface{}, len(resourceNames))
	for i := range returnsPtr {
		//hackity hack
		returnsPtr[i] = &returns[i]
	}

	// TODO: validate -> just to be sure it is not wrongly used in the future.
	// #nosec G202 (dbFieldName is never user input!)
	row := s.db.QueryRow(`SELECT `+strings.Join(resourceNames, ",")+` FROM `+s.prov.Prov.DBName("keycerts")+` WHERE key_name=$1 `+
		`LIMIT 1`, keyName)

	err := row.Scan(returnsPtr...)
	if err == sqlraw.ErrNoRows {
		return nil, &common.NotFoundError{RequestedResource: keyName}
	}
	if err != nil {
		return nil, err
	}

	return returns, nil
}
