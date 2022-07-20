package common

import (
	"fmt"
	"math/rand"
	"strings"
)

func MakeNewDomainName4Test(testableZones []string) (string, string, error) {
	zone := strings.TrimLeft(testableZones[rand.Int()%len(testableZones)], ".")
	name := fmt.Sprintf("test%d.%s", rand.Intn(100000), zone)
	return name, zone, nil
}
