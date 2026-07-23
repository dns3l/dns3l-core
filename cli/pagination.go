package cli

import (
	"fmt"
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"
)

type PaginationInfo struct {
	offset     uint64
	limit      uint64
	totalcount uint64
}

func PaginationInfoFromHeaders(header http.Header) *PaginationInfo {
	p := &PaginationInfo{}
	p.offset = strToUint64_0(header.Get("Page-Offset"), "offset")
	p.limit = strToUint64_0(header.Get("Page-Limit"), "limit")
	p.totalcount = strToUint64_0(header.Get("Total-Count"), "totalcount")
	return p
}

func (p *PaginationInfo) String() string {
	if p.limit > 0 {
		return fmt.Sprintf("Showing element %d - %d of %d elements", p.offset+1, p.offset+p.limit, p.totalcount)
	}
	return ""
}

func strToUint64_0(s, desc string) uint64 {
	if s == "" {
		return 0
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		log.WithFields(log.Fields{"desc": desc, "value": s}).Debug("could not parse unsigned integer, assuming 0")
		return 0
	}
	return u
}

type Paginator struct {
	hidden uint64
}

func NewPaginator(hidden uint64) *Paginator {
	return &Paginator{
		hidden: hidden,
	}
}

func (h *Paginator) Page(olimit, ooffset uint64,
	pg func(limit, offset uint64) (*PaginationInfo, uint64, error),
) (*PaginationInfo, uint64, error) {
	if h.hidden == 0 || (olimit > 0 && olimit <= h.hidden) {
		return pg(olimit, ooffset)
	}

	curoffset := ooffset
	curlimit := h.hidden
	total := uint64(0)
	for {
		pinfo, num, err := pg(curlimit, curoffset)
		if err != nil {
			return nil, total, err
		}
		total += num
		if pinfo == nil || pinfo.limit != curlimit || pinfo.offset != curoffset {
			// prevent infinite loops if server did not recognize pagination
			// Behave as if pagination was not supported
			return &PaginationInfo{}, total, nil
		}
		if num < h.hidden {
			// we have all elements
			return &PaginationInfo{offset: ooffset, limit: olimit, totalcount: pinfo.totalcount}, total, nil
		}
		curoffset += num
		if olimit > 0 {
			curlimit = min(h.hidden, olimit-num)
		}
	}

}
