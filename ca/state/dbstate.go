package state

import (
	"database/sql"
	sqlraw "database/sql"
	"fmt"
	"strings"

	"github.com/Masterminds/squirrel"
	"github.com/dta4/dns3l-go/ca/types"
	"github.com/dta4/dns3l-go/common"
	"github.com/dta4/dns3l-go/state"
	"github.com/dta4/dns3l-go/util"
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

const caCertsQueryElements = `key_name,
priv_key,
acme_user,
issued_by,
domains,
claim_time,
renew_time,
valid_start_time,
valid_end_time,
cert`

var caCertsQueryColumns = []string{
	"key_name",
	"priv_key",
	"acme_user",
	"issued_by",
	"domains",
	"claim_time",
	"renew_time",
	"valid_start_time",
	"valid_end_time",
	"cert",
}

func (s *CAStateManagerSQLSession) GetCACertByID(keyname string, caid string) (*types.CACertInfo, error) {
	rows, err := s.db.Query(`SELECT `+caCertsQueryElements+`
	FROM `+s.prov.Prov.DBName("keycerts")+` 
	WHERE key_name=? AND ca_id=? LIMIT 1;`,
		keyname, caid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	info := &types.CACertInfo{}
	if !rows.Next() {
		return nil, nil
	}
	err = s.rowToCACertInfo(rows, info)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return info, nil

}

func (s *CAStateManagerSQLSession) ListCACerts(keyName string, caid string, rzFilter []string,
	pginfo *util.PaginationInfo) ([]types.CACertInfo, error) {
	q := squirrel.Select(caCertsQueryColumns...).From(s.prov.Prov.DBName("keycerts"))
	filters := make(squirrel.Eq, 0)
	if keyName != "" {
		filters["key_name"] = keyName
	}
	if caid != "" {
		filters["ca_id"] = caid
	}
	if len(rzFilter) > 0 {
		filters["key_rz"] = rzFilter
	}
	q = q.Where(filters)
	if pginfo != nil {
		q = q.Limit(pginfo.Limit).Offset(pginfo.Offset)
	}

	rows, err := q.RunWith(s.db).Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make([]types.CACertInfo, 0, 100)

	for rows.Next() {
		res = append(res, types.CACertInfo{})
		err = s.rowToCACertInfo(rows, &res[len(res)-1])
		if err != nil {
			return nil, err
		}
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *CAStateManagerSQLSession) rowToCACertInfo(rows *sql.Rows, info *types.CACertInfo) error {
	var domainsStr string
	err := rows.Scan(&info.Name, &info.PrivKey, &info.ACMEUser, &info.IssuedByUser,
		&domainsStr, &info.ClaimTime, &info.RenewTime, &info.ValidStartTime, &info.ValidEndTime, &info.CertPEM)
	if err != nil {
		return err
	}

	info.Domains = strings.Split(domainsStr, ",")

	return nil
}

func (s *CAStateManagerSQLSession) DelCACertByID(keyID string, caID string) error {
	res, err := s.db.Exec("DELETE FROM "+s.prov.Prov.DBName("keycerts")+" WHERE key_name=? AND ca_id=?;",
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

func (s *CAStateManagerSQLSession) PutCACertData(update bool, keyname string, keyrz string, caid string, info *types.CACertInfo,
	certStr, issuerCertStr string) error {
	domainsStr := strings.Join(info.Domains, ",")

	if update {
		log.Debugf("Updating certificate data for key '%s' in database",
			keyname)
		_, err := s.db.Exec(`UPDATE `+s.prov.Prov.DBName("keycerts")+` SET cert=?, issuer_cert=?, `+
			`acme_user=?, issued_by=?, domains=?, renew_time=?, valid_start_time=?,
			valid_end_time=?, renew_count = renew_count + 1 WHERE key_name=? AND ca_id=?;`,
			certStr, issuerCertStr, info.ACMEUser, info.IssuedByUser, domainsStr,
			info.RenewTime.UTC(), info.ValidStartTime.UTC(), info.ValidEndTime.UTC(), keyname, caid)
		if err != nil {
			return fmt.Errorf("problem while storing new cert for existing key in database: %v",
				err)
		}
		return nil
	}

	log.Debugf("Storing new cert/key pair '%s' for user '%s' in database",
		keyname, info.ACMEUser)
	_, err := s.db.Exec(`INSERT INTO `+s.prov.Prov.DBName("keycerts")+` (key_name, key_rz, ca_id,`+
		`acme_user, issued_by, priv_key, cert, issuer_cert, domains, claim_time,
		renew_time, valid_start_time, valid_end_time, renew_count) `+
		`values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0);`,
		keyname, keyrz, caid, info.ACMEUser, info.IssuedByUser, info.PrivKey, certStr,
		issuerCertStr, domainsStr, info.ClaimTime.UTC(), info.RenewTime.UTC(), info.ValidStartTime.UTC(), info.ValidEndTime.UTC())
	if err != nil {
		return fmt.Errorf("problem while storing new key and cert in database: %v", err)
	}

	return nil

}

func (s *CAStateManagerSQLSession) GetResource(keyName, caid, resourceName string) (string, []string, error) {

	returns, domains, err := s.GetResources(keyName, caid, resourceName)
	if err != nil {
		return "", nil, err
	}
	if returns == nil {
		return "", nil, nil
	}
	return returns[0], domains, nil
}

func (s *CAStateManagerSQLSession) GetResources(keyName, caid string, resourceNames ...string) ([]string, []string, error) {

	var domainsStr string

	returns := make([]string, len(resourceNames))
	returnsPtr := make([]interface{}, len(resourceNames)+1)
	for i := range returnsPtr {
		//hackity hack
		if i == 0 {
			returnsPtr[0] = &domainsStr
		} else {
			returnsPtr[i] = &returns[i-1]
		}
	}

	// TODO: validate -> just to be sure it is not wrongly used in the future.
	// #nosec G202 (dbFieldName is never user input!)
	row := s.db.QueryRow(`SELECT domains,`+strings.Join(resourceNames, ",")+` FROM `+s.prov.Prov.DBName("keycerts")+` WHERE key_name=? 
	AND ca_id=? LIMIT 1`, keyName, caid)

	err := row.Scan(returnsPtr...)
	if err == sqlraw.ErrNoRows {
		return nil, nil, &common.NotFoundError{RequestedResource: keyName}
	}
	if err != nil {
		return nil, nil, err
	}

	return returns, strings.Split(domainsStr, ","), nil
}

func (s *CAStateManagerSQLSession) DeleteCertAllCA(keyID string) error {
	res, err := s.db.Exec("DELETE FROM "+s.prov.Prov.DBName("keycerts")+" WHERE key_name=?;",
		keyID)

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
