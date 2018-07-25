package model

import (
	"fmt"
	"testing"
)

// NewImage returns an image.
func TestNewImage(t *testing.T) {
	vulnFound := 0
	vulnNotFound := 0
	for ii := 0; ii < 1000; ii++ {
		fmt.Println(fmt.Sprintf("vuln / safe ratio : %v / %v", vulnFound, vulnNotFound))
		if ii > 10 && (vulnFound > 0 && vulnNotFound > 0) {
			return
		}
		if randImage().vulns > 0 {
			vulnFound++
		} else {
			vulnNotFound++
		}
	}
	fmt.Println(fmt.Sprintf("vuln / safe ratio : %v / %v", vulnFound, vulnNotFound))
	t.Errorf("need to find images that HAVE vulnerabilities, and DONT have vulnerabilities.")
}
