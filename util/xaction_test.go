package util

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXActAllWorking(t *testing.T) {

	a1 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "",
	}
	a2 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "",
	}
	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "",
		UndoBehav: "",
	}

	l := TransactionalJobList{a1, a2, am}

	assert.NoError(t, l.Commit())

	assert.True(t, a1.Done)
	assert.True(t, a2.Done)
	assert.True(t, am.Done)
	assert.False(t, am.Undone)
	assert.False(t, a2.Undone)
	assert.False(t, a1.Undone)

}

func TestXActErrCleanRollback(t *testing.T) {

	a1 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "",
	}
	a2 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "",
	}
	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "panic",
		UndoBehav: "",
	}

	l := TransactionalJobList{a1, a2, am}

	assert.ErrorContains(t, l.Commit(), "Panic occurred")

	assert.True(t, a1.Done)
	assert.True(t, a2.Done)
	assert.False(t, am.Done)
	assert.False(t, am.Undone)
	assert.True(t, a2.Undone)
	assert.True(t, a1.Undone)

}

func TestXActErrorDuringRollback(t *testing.T) {

	a1 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "",
	}
	a2 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "fooerror",
	}
	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "div0",
		UndoBehav: "",
	}

	l := TransactionalJobList{a1, a2, am}

	err := l.Commit()

	assert.ErrorContains(t, err, "divide by")
	assert.ErrorContains(t, err, "fooerror")

	assert.Nil(t, errors.Unwrap(err))

	suberrs := UnwrapMultiErr(err)
	assert.Len(t, suberrs, 2)
	assert.ErrorContains(t, suberrs[0], "divide")
	assert.ErrorContains(t, suberrs[1], "fooerror")

	assert.True(t, a1.Done)
	assert.True(t, a2.Done)
	assert.False(t, am.Done)
	assert.False(t, am.Undone)
	assert.False(t, a2.Undone)
	assert.True(t, a1.Undone)

}

func TestXActMiniOK(t *testing.T) {

	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "",
		UndoBehav: "",
	}

	l := TransactionalJobList{am}

	assert.NoError(t, l.Commit())

	assert.True(t, am.Done)
	assert.False(t, am.Undone)

}

func TestXActMiniErr(t *testing.T) {

	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "panic",
		UndoBehav: "",
	}

	l := TransactionalJobList{am}

	err := l.Commit()

	assert.ErrorContains(t, err, "Panic")

	assert.Nil(t, errors.Unwrap(err))
	assert.Nil(t, UnwrapMultiErr(err))

	assert.False(t, am.Done)
	assert.False(t, am.Undone)

}

func TestXActBig(t *testing.T) {

	a1 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "",
	}
	a2 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "panic",
	}
	a3 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "div0",
	}
	a4 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "",
	}
	a5 := &TransactionalTestAction{
		Name:      "Preparation 1",
		DoBehav:   "",
		UndoBehav: "QuuxErr",
	}
	a6 := &TransactionalTestAction{
		Name:      "Preparation 2",
		DoBehav:   "",
		UndoBehav: "",
	}
	am := &TransactionalTestAction{
		Name:      "Main thing",
		DoBehav:   "foobaz",
		UndoBehav: "blargh",
	}
	am2 := &TransactionalTestAction{
		Name:      "Main thing 2",
		DoBehav:   "aaa",
		UndoBehav: "b",
	}

	l := TransactionalJobList{a1, a2, a3, a4, a5, a6, am, am2}

	err := l.Commit()

	fmt.Println(err)
	assert.ErrorContains(t, err, "foobaz")
	assert.ErrorContains(t, err, "QuuxErr")
	assert.ErrorContains(t, err, "divide by")
	assert.ErrorContains(t, err, "Panic")

	assert.Nil(t, errors.Unwrap(err))

	suberrs := UnwrapMultiErr(err)
	assert.Len(t, suberrs, 4)
	assert.ErrorContains(t, suberrs[0], "foobaz")
	assert.ErrorContains(t, suberrs[1], "n=4")
	assert.ErrorContains(t, suberrs[1], "QuuxErr")
	assert.ErrorContains(t, suberrs[2], "n=2")
	assert.ErrorContains(t, suberrs[2], "divide by")
	assert.ErrorContains(t, suberrs[3], "n=1")
	assert.ErrorContains(t, suberrs[3], "Panic")

	assert.True(t, a1.Done)
	assert.True(t, a2.Done)
	assert.True(t, a3.Done)
	assert.True(t, a4.Done)
	assert.True(t, a5.Done)
	assert.True(t, a6.Done)
	assert.False(t, am.Done)
	assert.False(t, am2.Done)

	assert.False(t, am2.Undone)
	assert.False(t, am.Undone)
	assert.True(t, a6.Undone)
	assert.False(t, a5.Undone)
	assert.True(t, a4.Undone)
	assert.False(t, a3.Undone)
	assert.False(t, a2.Undone)
	assert.True(t, a1.Undone)

}

type TransactionalTestAction struct {
	Name      string
	DoBehav   string
	UndoBehav string
	Done      bool
	Undone    bool
}

func (a *TransactionalTestAction) Do() error {
	fmt.Printf("Execute %s\n", a.Name)
	return a.behav(a.DoBehav, &a.Done)
}

func (a *TransactionalTestAction) Undo() error {
	fmt.Printf("Rollback %s\n", a.Name)
	return a.behav(a.UndoBehav, &a.Undone)
}

func getZero() int {
	return 0
}

func (a *TransactionalTestAction) behav(b string, doneval *bool) error {

	if b == "div0" {
		fmt.Println(1 / getZero())
	}
	if b == "panic" {
		panic("Panic occurred!!!!!")
	}
	if b == "" {
		*doneval = true
		return nil
	}
	return fmt.Errorf("%s: %s", a.Name, b)
}
