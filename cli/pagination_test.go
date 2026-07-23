package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type expectPage struct {
	t       *testing.T
	cursor  int
	expects []expectPageElem
}

type expectPageElem struct {
	limit  uint64
	offset uint64
	pginfo *PaginationInfo
	num    uint64
	err    error
}

func (e *expectPage) ExpectPage(limit uint64, offset uint64,
) (*PaginationInfo, uint64, error) {
	if e.cursor >= len(e.expects) {
		panic("nothing to expect anymore")
	}
	elem := e.expects[e.cursor]
	assert.Equal(e.t, elem.limit, limit, "limit")
	assert.Equal(e.t, elem.offset, offset, "offset")
	e.cursor++
	return elem.pginfo, elem.num, elem.err
}
func (e *expectPage) AssertEnd() {
	assert.True(e.t, e.cursor >= len(e.expects), "not all calls done")
}

func TestPagerNoLimit(t *testing.T) {

	// No limit set, not paging
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     0,
					totalcount: 8,
				},
				num: 8,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(0, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(8), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(0), pinfo.limit, "olimit")
	assert.Equal(t, uint64(0), pinfo.offset, "ooffset")
	assert.Equal(t, uint64(8), pinfo.totalcount, "ototalcount")
	xp.AssertEnd()

	// No limit set, paging
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     0,
					totalcount: 22,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 10,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     10,
					totalcount: 22,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 20,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     20,
					totalcount: 22,
				},
				num: 2,
			},
		},
	}
	p = NewPaginator(10)
	pinfo, num, err = p.Page(0, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(22), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(0), pinfo.limit)
	assert.Equal(t, uint64(0), pinfo.offset)
	assert.Equal(t, uint64(22), pinfo.totalcount)
	xp.AssertEnd()
}

func TestPagerGoodCase(t *testing.T) {
	// Limit sent smaller than hidden page
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  5,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      5,
					offset:     0,
					totalcount: 8,
				},
				num: 5,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(5, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(5), pinfo.limit)
	assert.Equal(t, uint64(0), pinfo.offset)
	assert.Equal(t, uint64(8), pinfo.totalcount)
	xp.AssertEnd()

	// Limit sent
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     0,
					totalcount: 23,
				},
				num: 10,
			},
			{
				limit:  8,
				offset: 10,
				pginfo: &PaginationInfo{
					limit:      8,
					offset:     10,
					totalcount: 23,
				},
				num: 8,
			},
		},
	}
	pinfo, num, err = p.Page(18, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(18), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(18), pinfo.limit)
	assert.Equal(t, uint64(0), pinfo.offset)
	assert.Equal(t, uint64(23), pinfo.totalcount)
	xp.AssertEnd()

}

func TestPagerLimitExactMultipleOfHiddenStopsAtLimit(t *testing.T) {
	// olimit is an exact multiple of hidden, and more data is available on the
	// server beyond olimit. The paginator must stop fetching once olimit
	// elements have been collected instead of continuing to page through all
	// remaining server data.
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     0,
					totalcount: 100,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 10,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     10,
					totalcount: 100,
				},
				num: 10,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(20, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(20), num, "paginator must stop exactly at olimit instead of continuing to page")
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(20), pinfo.limit)
	assert.Equal(t, uint64(0), pinfo.offset)
	assert.Equal(t, uint64(100), pinfo.totalcount)
	xp.AssertEnd()

	// Same scenario, but with a non-zero outer offset and more than two hidden
	// pages required to satisfy olimit.
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 4,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     4,
					totalcount: 100,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 14,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     14,
					totalcount: 100,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 24,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     24,
					totalcount: 100,
				},
				num: 10,
			},
		},
	}
	p = NewPaginator(10)
	pinfo, num, err = p.Page(30, 4, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(30), num, "paginator must stop exactly at olimit instead of continuing to page")
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(30), pinfo.limit)
	assert.Equal(t, uint64(4), pinfo.offset)
	assert.Equal(t, uint64(100), pinfo.totalcount)
	xp.AssertEnd()
}

func TestPagerOuterOffset(t *testing.T) {
	// Limit sent smaller than hidden page
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  5,
				offset: 4,
				pginfo: &PaginationInfo{
					limit:      5,
					offset:     4,
					totalcount: 20,
				},
				num: 5,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(5, 4, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(5), pinfo.limit)
	assert.Equal(t, uint64(4), pinfo.offset)
	assert.Equal(t, uint64(20), pinfo.totalcount)
	xp.AssertEnd()

	// Limit sent
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 4,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     4,
					totalcount: 23,
				},
				num: 10,
			},
			{
				limit:  8,
				offset: 14,
				pginfo: &PaginationInfo{
					limit:      8,
					offset:     14,
					totalcount: 23,
				},
				num: 8,
			},
		},
	}
	pinfo, num, err = p.Page(18, 4, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(18), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(18), pinfo.limit)
	assert.Equal(t, uint64(4), pinfo.offset)
	assert.Equal(t, uint64(23), pinfo.totalcount)
	xp.AssertEnd()

}

func TestPagerLastZero(t *testing.T) {
	// Limit sent smaller than hidden page
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 10,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     10,
					totalcount: 20,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 20,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     20,
					totalcount: 20,
				},
				num: 0,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(20, 10, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(20), pinfo.limit)
	assert.Equal(t, uint64(10), pinfo.offset)
	assert.Equal(t, uint64(20), pinfo.totalcount)
	xp.AssertEnd()

	// Limit sent
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 10,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     10,
					totalcount: 30,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 20,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     20,
					totalcount: 30,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 30,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     30,
					totalcount: 30,
				},
				num: 0,
			},
		},
	}
	pinfo, num, err = p.Page(30, 10, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(20), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(30), pinfo.limit)
	assert.Equal(t, uint64(10), pinfo.offset)
	assert.Equal(t, uint64(30), pinfo.totalcount)
	xp.AssertEnd()

}

func TestPagerOffsetOnly(t *testing.T) {
	// Limit sent smaller than hidden page
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 4,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     4,
					totalcount: 12,
				},
				num: 8,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(0, 4, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(8), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(0), pinfo.limit)
	assert.Equal(t, uint64(4), pinfo.offset)
	assert.Equal(t, uint64(12), pinfo.totalcount)
	xp.AssertEnd()

	// Limit sent
	xp = expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 4,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     4,
					totalcount: 32,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 14,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     14,
					totalcount: 32,
				},
				num: 10,
			},
			{
				limit:  10,
				offset: 24,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     24,
					totalcount: 32,
				},
				num: 8,
			},
		},
	}
	pinfo, num, err = p.Page(0, 4, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(28), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(0), pinfo.limit)
	assert.Equal(t, uint64(4), pinfo.offset)
	assert.Equal(t, uint64(32), pinfo.totalcount)
	xp.AssertEnd()

}

func TestPagerErr(t *testing.T) {

	// No limit set, not paging
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      10,
					offset:     0,
					totalcount: 8,
				},
				num: 8,
				err: errors.New("coffee too cold"),
			},
		},
	}
	p := NewPaginator(10)
	_, _, err := p.Page(0, 0, xp.ExpectPage)
	assert.Error(t, err)
	xp.AssertEnd()
}

func TestPagingUnsupported(t *testing.T) {

	// No limit set, not paging
	xp := expectPage{
		t: t,
		expects: []expectPageElem{
			{
				limit:  10,
				offset: 0,
				pginfo: &PaginationInfo{
					limit:      0,
					offset:     0,
					totalcount: 0,
				},
				num: 18,
			},
		},
	}
	p := NewPaginator(10)
	pinfo, num, err := p.Page(0, 0, xp.ExpectPage)
	assert.NoError(t, err)
	assert.Equal(t, uint64(18), num)
	assert.NotNil(t, pinfo)
	assert.Equal(t, uint64(0), pinfo.limit)
	assert.Equal(t, uint64(0), pinfo.offset)
	assert.Equal(t, uint64(0), pinfo.totalcount)
	xp.AssertEnd()
}
