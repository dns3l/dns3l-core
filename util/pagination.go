package util

import (
	"fmt"
	"net/http"
	"strconv"
)

type PaginationInfo struct {
	Limit      uint64 //if limit is 0 limit is infinite
	Offset     uint64
	TotalCount uint64
}

func (p *PaginationInfo) MakeSQL() string {
	if p.Limit > 0 {
		if p.Offset > 0 {
			return fmt.Sprintf(" LIMIT %d, %d", p.Offset, p.Limit)
		}
		return fmt.Sprintf(" LIMIT %d", p.Limit)
	}

	return ""
}

func (p *PaginationInfo) SetHTTPHeaders(r *http.Response) {
	if p.Limit > 0 {
		r.Header.Add("Page-Limit", strconv.FormatUint(p.Limit, 10))
	}
	if p.Offset > 0 {
		r.Header.Add("Page-Offset", strconv.FormatUint(p.Offset, 10))
	}
	r.Header.Add("Total-Count", strconv.FormatUint(p.TotalCount, 10))
}

func PaginationInfoFromRequest(r *http.Request) *PaginationInfo {
	var offset, limit uint64
	q := r.URL.Query()
	offsetStr := q.Get("offset")
	limitStr := q.Get("limit")
	if offsetStr != "" {
		offset, _ = strconv.ParseUint(offsetStr, 10, 64)
	}
	if limitStr != "" {
		limit, _ = strconv.ParseUint(limitStr, 10, 64)
	}
	if limit > 0 || offset > 0 {
		return &PaginationInfo{
			Limit:  limit,
			Offset: offset,
		}
	}
	return nil
}
