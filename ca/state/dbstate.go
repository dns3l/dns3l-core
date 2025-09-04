package state

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/renew"
	authtypes "github.com/dns3l/dns3l-core/service/auth/types"
	"github.com/dns3l/dns3l-core/state"
	"github.com/dns3l/dns3l-core/util"
)

type CAStateManagerSQL struct {
	Prov state.SQLDBProvider
}

type CAStateManagerSQLSession struct {
	prov *CAStateManagerSQL
	db   *sql.DB
}

func (m *CAStateManagerSQL) NewSession() (types.CAStateManagerSession, error) {
	db, err := m.Prov.GetDBConn()
	if err != nil {
		return nil, err
	}
	return &CAStateManagerSQLSession{db: db, prov: m}, nil
}

func (s *CAStateManagerSQLSession) Close() error {
	//Nothing to do
	return nil
}

var caCertsQueryColumns = []string{
	"key_name",
	"priv_key",
	"acme_user",
	"issued_by",
	"issued_by_email",
	"claim_time",
	"renewed_time",
	"next_renewal_time",
	"valid_start_time",
	"valid_end_time",
	"last_access_time",
	"access_count",
	"cert",
	"ttl_seconds",
}

func (s *CAStateManagerSQLSession) GetCACertByID(keyname string, caid string) (*types.CACertInfo, error) {

	rows, err := s.db.Query(`SELECT `+strings.Join(caCertsQueryColumns, ",")+`
	FROM `+s.prov.Prov.DBName("keycerts")+` 
	WHERE key_name=? AND ca_id=? LIMIT 1;`,
		keyname, caid)
	if err != nil {
		return nil, err
	}
	defer util.LogDefer(log, rows.Close)

	info := &types.CACertInfo{}
	info.IssuedBy = &authtypes.UserInfo{}
	if !rows.Next() {
		return nil, nil
	}
	var ttlsec int
	err = rows.Scan(&info.Name, &info.PrivKey, &info.ACMEUser, &info.IssuedBy.Name, &info.IssuedBy.Email,
		&info.ClaimTime, &info.RenewedTime, &info.NextRenewalTime, &info.ValidStartTime, &info.ValidEndTime,
		&info.LastAccessTime, &info.AccessCount, &info.CertPEM, &ttlsec)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	info.TTLSelected = time.Duration(ttlsec) * time.Second

	info.Domains, err = s.GetDomains(keyname, caid)
	if err != nil {
		if _, ok := err.(*common.NotFoundError); ok {
			return nil, fmt.Errorf("no domains found for requested keyname %s: %w", keyname, err)
		}
		return nil, err
	}

	return info, nil

}

func domainToReverseQueryForm(domain string) (string, string) {

	ndomain := util.StringReverse(util.GetDomainFQDNDot(domain))
	//ensure backend standard form and then reverse

	if strings.HasSuffix(ndomain, ".") {
		return ndomain, ndomain + "%"
	}
	return ndomain, ndomain + ".%" //thus we cannot break out to equal-suffixed higher-level domains

}

func domainReverseDBFormToNormal(domainRev string) string {
	return util.StringReverse(domainRev)
}

func constructListCACertsQuery(dbn func(name string) string, keyName string, caid string,
	authzFilter []string, queryFilter string, pginfo *util.PaginationInfo) (string, []interface{}) {

	//Note that we will never filter for keyName and caid at the same time.
	//It will just ignore one of the filters

	filters := make([]string, 0, 10)
	filterParams := make([]interface{}, 0, 10)

	if keyName != "" {
		filters = append(filters, "key_name = ?")
		filterParams = append(filterParams, keyName)
	}
	if caid != "" {
		filters = append(filters, "ca_id = ?")
		filterParams = append(filterParams, caid)
	}

	if queryFilter != "" {
		filters = append(filters, "(dom_name_rev = ? OR dom_name_rev LIKE ?)")
		filter1, filter2 := domainToReverseQueryForm(queryFilter)
		filterParams = append(filterParams, filter1, filter2)
	}

	if len(authzFilter) > 0 {
		filterAuth := make([]string, 0, 10)
		for _, elem := range authzFilter {
			filterAuth = append(filterAuth, "dom_name_rev = ? OR dom_name_rev LIKE ?")
			filter1, filter2 := domainToReverseQueryForm(elem)
			filterParams = append(filterParams, filter1, filter2)
		}
		filters = append(filters, fmt.Sprintf("(%s)", strings.Join(filterAuth, " OR ")))
	}

	filtersStr := strings.Join(filters, " AND ")

	if filtersStr != "" {
		filtersStr = "AND " + filtersStr
	}

	var paginationsql string
	if pginfo != nil {
		paginationsql = pginfo.MakeSQL()
	} else {
		paginationsql = ""
	}

	return `SELECT
		` + keycertsDistinctQueryStr(dbn) + `
		GROUP_CONCAT(` + dbn("domains") + `.dom_name_rev)
		FROM ` + dbn("domains") + ` JOIN ` + dbn("keycerts") + ` USING (key_name, ca_id) WHERE
		(` + dbn("keycerts") + `.key_name, ` + dbn("keycerts") + `.ca_id) IN (
				select key_name, ca_id FROM ` + dbn("domains") + ` WHERE
					is_first_domain=true ` + filtersStr + `
				GROUP BY key_name, ca_id
				ORDER BY is_first_domain desc, ` + dbn("domains") + `.dom_name_rev
			)
		GROUP BY key_name, ca_id` + paginationsql + `;`, filterParams
}

func keycertsDistinctQueryStr(dbn func(name string) string) string {
	myQCString := ""
	qcprefix := dbn("keycerts") + "."
	for i := range caCertsQueryColumns {
		myQCString += qcprefix + caCertsQueryColumns[i] + ","
	}
	return myQCString
}

func (s *CAStateManagerSQLSession) ListCACerts(keyName string, caid string, authzFilter []string,
	queryFilter string, pginfo *util.PaginationInfo) ([]types.CACertInfo, error) {

	q, params := constructListCACertsQuery(s.prov.Prov.DBName, keyName, caid,
		authzFilter, queryFilter, pginfo)

	rows, err := s.db.Query(q, params...)
	if err != nil {
		log.Debugf("Failing query was %s", q)
		return nil, err
	}
	defer util.LogDefer(log, rows.Close)

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
	var domainsRevStr string
	info.IssuedBy = &authtypes.UserInfo{}
	var ttlsec int
	err := rows.Scan(&info.Name, &info.PrivKey, &info.ACMEUser, &info.IssuedBy.Name, &info.IssuedBy.Email,
		&info.ClaimTime, &info.RenewedTime, &info.NextRenewalTime, &info.ValidStartTime, &info.ValidEndTime,
		&info.LastAccessTime, &info.AccessCount, &info.CertPEM, &ttlsec,
		&domainsRevStr)
	info.TTLSelected = time.Duration(ttlsec) * time.Second
	if err != nil {
		return err
	}

	info.Domains = strings.Split(domainsRevStr, ",")

	for i := range info.Domains {
		info.Domains[i] = domainReverseDBFormToNormal(info.Domains[i])
	}

	return nil
}

func (s *CAStateManagerSQLSession) DelCACertByID(keyID string, caID string) error {

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer util.RollbackIfNotCommitted(log, tx)

	res, err := tx.Exec(`DELETE FROM `+s.prov.Prov.DBName("keycerts")+` WHERE key_name=? AND ca_id=? LIMIT 1;`, keyID, caID)
	if err != nil {
		return err
	}
	affected1, err := res.RowsAffected()
	if err != nil {
		return err
	}

	res, err = s.db.Exec(`DELETE FROM `+s.prov.Prov.DBName("domains")+` WHERE key_name=? AND ca_id=?;`, keyID, caID)
	if err != nil {
		return err
	}
	affected2, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected1 <= 0 && affected2 <= 0 {
		return &common.NotFoundError{RequestedResource: keyID}
	}
	if (affected1 > 0) != (affected2 > 0) {
		log.Error("Entry has been in keycerts but not in domains table or vice versa - " +
			"this should not happen. Deleted certificate's remains.")
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return err

}

func (s *CAStateManagerSQLSession) UpdateCACertData(keyname string, caid string, renewedTime, nextRenewalTime,
	validStartTime, validEndTime time.Time, certStr, issuerCertStr string) error {

	log.Debugf("Updating certificate data for key '%s' in database",
		keyname)
	_, err := s.db.Exec(`UPDATE `+s.prov.Prov.DBName("keycerts")+` SET cert=?, issuer_cert=?, `+
		`renewed_time=?, next_renewal_time=?, valid_start_time=?,
				valid_end_time=?, renew_count = renew_count + 1 WHERE key_name=? AND ca_id=?;`,
		certStr, issuerCertStr, renewedTime, nextRenewalTime, validStartTime, validEndTime, keyname, caid)
	if err != nil {
		return fmt.Errorf("problem while storing new cert for existing key in database: %w",
			err)
	}
	return nil
}

func (s *CAStateManagerSQLSession) PutCACertData(keyname string, caid string, info *types.CACertInfo,
	certStr, issuerCertStr string) error {

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer util.RollbackIfNotCommitted(log, tx)

	log.Debugf("Storing new cert/key pair '%s' for user '%s' in database",
		keyname, info.IssuedBy.GetPreferredName())
	_, err = tx.Exec(`INSERT INTO `+s.prov.Prov.DBName("keycerts")+` (key_name, ca_id,`+
		`acme_user, issued_by, issued_by_email, priv_key, cert, issuer_cert, claim_time,
	renewed_time, next_renewal_time, valid_start_time, valid_end_time, renew_count, ttl_seconds) `+
		`values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?);`,
		keyname, caid, info.ACMEUser, info.IssuedBy.Name, info.IssuedBy.Email,
		info.PrivKey, certStr,
		issuerCertStr, info.ClaimTime.UTC(), info.RenewedTime.UTC(),
		info.NextRenewalTime.UTC(), info.ValidStartTime.UTC(), info.ValidEndTime.UTC(),
		info.TTLSelected.Seconds())
	if err != nil {
		return fmt.Errorf("problem while storing new key and cert in database: %w", err)
	}

	for i, domain := range info.Domains {
		_, err := tx.Exec(`INSERT INTO `+s.prov.Prov.DBName("domains")+` (dom_name_rev, key_name, ca_id, is_first_domain) `+
			`VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE key_name=key_name;`,
			util.StringReverse(util.GetDomainFQDNDot(domain)), keyname, caid, i == 0)
		if err != nil {
			return err
		}
	}

	return tx.Commit()

}

// Needed for authz
func (s *CAStateManagerSQLSession) GetDomains(keyName, caid string) ([]string, error) {

	rows, err := s.db.Query(`SELECT dom_name_rev FROM `+s.prov.Prov.DBName("domains")+` 
	WHERE key_name=? AND ca_id=? ORDER BY is_first_domain DESC;`, keyName, caid)
	if err != nil {
		return nil, err
	}

	defer func() {
		util.LogDefer(log, rows.Close)
	}()

	domains := make([]string, 0, 10)
	for rows.Next() {
		domainsRevStr := ""
		err := rows.Scan(&domainsRevStr)
		if err != nil {
			return nil, err
		}
		domains = append(domains, domainReverseDBFormToNormal(domainsRevStr))
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	if len(domains) <= 0 {
		return nil, &common.NotFoundError{RequestedResource: keyName}
	}

	return domains, nil
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
	row := s.db.QueryRow(`SELECT `+strings.Join(resourceNames, ",")+` FROM `+s.prov.Prov.DBName("keycerts")+` 
	WHERE key_name=? AND ca_id=? LIMIT 1;`, keyName, caid)

	err := row.Scan(returnsPtr...)
	if err == sql.ErrNoRows {
		return nil, &common.NotFoundError{RequestedResource: keyName}
	}
	if err != nil {
		return nil, err
	}

	_, err = s.db.Exec(`CALL `+s.prov.Prov.DBName("read_increment")+`(?, ?);`, keyName, caid)
	if err != nil {
		return nil, err
	}

	return returns, nil
}

func (s *CAStateManagerSQLSession) DeleteCertAllCA(keyID string) error {

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer util.LogDefer(log, tx.Rollback)

	res, err := tx.Exec(`DELETE FROM `+s.prov.Prov.DBName("keycerts")+` WHERE key_name=?;`, keyID)
	if err != nil {
		return err
	}
	affected1, err := res.RowsAffected()
	if err != nil {
		return err
	}

	res, err = s.db.Exec(`DELETE FROM `+s.prov.Prov.DBName("domains")+` WHERE key_name=?;`, keyID)
	if err != nil {
		return err
	}
	affected2, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected1 <= 0 && affected2 <= 0 {
		return &common.NotFoundError{RequestedResource: keyID}
	}
	if (affected1 > 0) != (affected2 > 0) {
		log.Error("Entry has been in keycerts but not in domains table or vice versa - " +
			"this should not happen. Deleted certificate's remains.")
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return err

}

func (s *CAStateManagerSQLSession) GetNumberOfCerts(caID string,
	validonly bool, currentTime time.Time) (uint, error) {
	q := squirrel.Select("count(*)").From(s.prov.Prov.DBName("keycerts"))
	if caID != "" {
		q = q.Where(squirrel.Eq{"ca_id": caID})
	}
	if validonly {
		q = q.Where(squirrel.Lt{"valid_start_time": currentTime}).
			Where(squirrel.Gt{"valid_end_time": currentTime})
	}

	rs := q.RunWith(s.db).QueryRow()

	var numrows uint
	err := rs.Scan(&numrows)
	if err != nil {
		return 0, err
	}

	return numrows, nil
}

func (s *CAStateManagerSQLSession) ListExpired(atTime time.Time,
	limit uint) ([]types.CertificateRenewInfo, error) {
	return s.listTimeExpired(atTime, limit, "valid_end_time")
}

func (s *CAStateManagerSQLSession) ListToRenew(atTime time.Time,
	limit uint) ([]types.CertificateRenewInfo, error) {
	return s.listTimeExpired(atTime, limit, "next_renewal_time")
}

func (s *CAStateManagerSQLSession) listTimeExpired(atTime time.Time, limit uint,
	field string) ([]types.CertificateRenewInfo, error) {
	q := squirrel.Select("key_name", "ca_id", "valid_end_time", "next_renewal_time", "ttl_seconds").From(
		s.prov.Prov.DBName("keycerts")).Where(squirrel.Lt{field: atTime}).OrderBy("valid_end_time")

	rows, err := q.RunWith(s.db).Query()
	if err != nil {
		return nil, err
	}
	defer util.LogDefer(log, rows.Close)

	res := make([]types.CertificateRenewInfo, 0, 1024)

	i := 0
	for rows.Next() {
		res = append(res, types.CertificateRenewInfo{})
		var ttlsec int
		info := &res[i]
		err := rows.Scan(&info.CertKey, &info.CAID, &info.ExpiresAt, &info.NextRenewal, &ttlsec)
		info.TTLSelected = time.Duration(ttlsec) * time.Second
		if err != nil {
			return nil, err
		}

		i++
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *CAStateManagerSQLSession) UserHasCerts(user *authtypes.UserInfo, caid string) (bool, error) {

	row := s.db.QueryRow(`SELECT COUNT(*) FROM `+s.prov.Prov.DBName("keycerts")+
		` WHERE issued_by=? AND issued_by_email=? AND ca_id=? LIMIT 1;`, user.Name, user.Email, caid)

	var numrows uint
	err := row.Scan(&numrows)
	if err != nil {
		return true, err
	}
	if numrows > 0 {
		return true, nil
	}

	return false, nil

}

// PutLastRenewSummary implements types.CAStateManagerSession.
func (s *CAStateManagerSQLSession) PutLastRenewSummary(info *renew.ServerInfoRenewal) error {
	infoBytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error while marshaling renew info: %w", err)
	}
	_, err = s.db.Exec("CALL "+s.prov.Prov.DBName("set_renew_info")+"(?);", string(infoBytes))
	return err
}

// GetLastRenewSummary implements types.CAStateManagerSession.
func (s *CAStateManagerSQLSession) GetLastRenewSummary() (*renew.ServerInfoRenewal, error) {

	var resultBytes string
	row := s.db.QueryRow(`SELECT renew_info FROM ` + s.prov.Prov.DBName("renew_info") + `;`)
	err := row.Scan(&resultBytes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result := &renew.ServerInfoRenewal{}
	err = json.Unmarshal([]byte(resultBytes), result)
	if err != nil {
		return nil, err
	}

	return result, nil

}
