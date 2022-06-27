package state

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DBProvider provides new sql.DB connections on request. On GetNewDBConn()
// an object *sql.DB is returned.
// Optionally, if set, executes the function provided in SetDBPreExec() first.
type SQLDBProvider interface {
	GetNewDBConn() (*sql.DB, error)
	SetDBPreExec(func(*sql.DB) error)
	DBName(name string) string
}

// DBProviderDefault is the default database provider. Type and URL must be given,
// which are needed to call sql.Open()
type SQLDBProviderDefault struct {
	Type        string `yaml:"type"`
	URL         string `yaml:"url"`
	PreExecFunc func(*sql.DB) error
	DBPrefix    string `yaml:"dbprefix"`
}

// SetDBPreExec sets a function which is executed every time a new database connection is created.
// This function is called on the new *sql.DB object *before* GetNewDBConn returns it.
func (c *SQLDBProviderDefault) SetDBPreExec(preExecFunc func(*sql.DB) error) {
	c.PreExecFunc = preExecFunc
}

// GetNewDBConn returns a freshly opened sql.DB object. Optionally, if set, executes the function
// set with SetDBPreExec() which can do modifications on sql.DB before it returns the database object.
func (c *SQLDBProviderDefault) GetNewDBConn() (*sql.DB, error) {
	db, err := sql.Open(c.Type, c.URL)
	if err != nil {
		return nil, err
	}
	if c.PreExecFunc != nil {
		err := c.PreExecFunc(db)
		if err != nil {
			return nil, fmt.Errorf("error while executing pre-execution function in database connection: %v", err)
		}
	}
	return db, nil
}

// TestDBConn connects to the database and sends a sql.DB.Ping() once
func (c *SQLDBProviderDefault) TestDBConn() error {
	log.Debugf("Testing DB connection...")
	db, err := c.GetNewDBConn()
	if err != nil {
		return fmt.Errorf("problems while obtaining established database connection: %v", err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return fmt.Errorf("problems while pinging database: %v", err)
	}
	log.Debugf("%sSuccessfully tested DB connection")

	return nil
}

func (c *SQLDBProviderDefault) DBName(name string) string {
	return fmt.Sprintf("%s_%s", c.DBPrefix, name)
}

func TimeToDBStr(timeObj time.Time) string {
	return timeObj.Format(time.RFC3339)
}

func DBStrToTime(timeStr string) (time.Time, error) {
	return time.Parse(time.RFC3339, timeStr)
}
