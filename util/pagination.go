package util

import "fmt"

type PaginationInfo struct {
	Limit  uint64 //if limit is 0 limit is infinite
	Offset uint64
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
