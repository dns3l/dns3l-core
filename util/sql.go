package util

import (
	"database/sql"

	"github.com/sirupsen/logrus"
)

// To be used by "defer", rollback, only log error if the error is not
// that the transaction has already been committed
func RollbackIfNotCommitted(log *logrus.Entry, tx *sql.Tx) {

	err := tx.Rollback()

	if err == sql.ErrTxDone {
		return
	}

	LogIfError(log, err)

}
