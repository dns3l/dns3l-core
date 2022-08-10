package util

import (
	"sync"
	"time"
)

//Returns a cached value for a specified amount of time (timeout)
//Concurrent requests for the cached value are blocked, later requests
//are supplied with the cached value retrieved from earlier requests
type SingleValCache[T interface{}] struct {
	l       sync.Mutex
	Timeout time.Duration
	time    time.Time
	value   T
	valid   bool
}

func (v *SingleValCache[T]) GetCached(fetch func() (T, error)) (T, error) {
	v.l.Lock()
	defer v.l.Unlock()

	now := time.Now()

	if v.valid && v.time.Add(v.Timeout).After(now) {
		return v.value, nil
	}

	newval, err := fetch()
	if err != nil {
		return newval, err
	}
	v.value = newval
	v.time = now
	v.valid = true
	return v.value, nil

}

func (v *SingleValCache[T]) Invalidate() {
	v.l.Lock()
	v.valid = false
	v.l.Unlock()
}
