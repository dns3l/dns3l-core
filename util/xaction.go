package util

import (
	"fmt"
	"strings"
)

type TransactionalJobList []TransactionalJob

func (jl TransactionalJobList) Commit() error {

	for i := 0; i < len(jl); i++ {
		err := CatchPanic(jl[i].Do)
		if err != nil {
			rberr := jl.rollbackFrom(i-1, err)
			if rberr != nil {
				return rberr
			}
			return err
		}
	}

	return nil

}

func (jl TransactionalJobList) rollbackFrom(jobID int, origErr error) *TransactionRollbackError {
	var rbErr *TransactionRollbackError = nil
	for i := jobID; i >= 0; i-- {
		err := CatchPanic(jl[i].Undo)
		if err != nil {
			if rbErr == nil {
				rbErr = &TransactionRollbackError{
					RollbackErrors: make([]*TransactionRollbackErrorElem, 0, 10),
					Err:            origErr,
				}
			}
			rbErr.RollbackErrors = append(rbErr.RollbackErrors, &TransactionRollbackErrorElem{
				Num: i,
				Err: err,
			})
		}
	}

	return rbErr
}

type TransactionalJob interface {
	Do() error
	Undo() error
}

type TransactionRollbackErrorElem struct {
	Num int
	Err error
}

func (e *TransactionRollbackErrorElem) Unwrap() error {
	return e.Err
}

func (e *TransactionRollbackErrorElem) Error() string {
	return fmt.Sprintf("n=%d, %s", e.Num, e.Err.Error())
}

type TransactionRollbackError struct {
	RollbackErrors []*TransactionRollbackErrorElem
	Err            error
}

func (e *TransactionRollbackError) Unwrap() []error {

	es := make([]error, len(e.RollbackErrors)+1)
	es[0] = e.Err

	for i := range e.RollbackErrors {
		es[i+1] = e.RollbackErrors[i]
	}

	return es

}

func (e *TransactionRollbackError) Error() string {

	errsStr := make([]string, len(e.RollbackErrors))
	for i := range e.RollbackErrors {
		errsStr[i] = e.RollbackErrors[i].Error()
	}
	return fmt.Sprintf("%s. During rollback the following errors additionally occurred: %s", e.Err.Error(), strings.Join(errsStr, "; "))
}

type TransactionalJobImpl struct {
	DoFunc   func() error
	UndoFunc func() error
}

func (i *TransactionalJobImpl) Do() error {
	if i.DoFunc == nil {
		return nil
	}
	return i.DoFunc()
}

func (i *TransactionalJobImpl) Undo() error {
	if i.UndoFunc == nil {
		return nil
	}
	return i.UndoFunc()
}
