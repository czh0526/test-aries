package bitstring

import (
	"fmt"
	"testing"
)

func TestBitString(t *testing.T) {
	totalCredentials := 1000
	revokedIndexes := []int{3, 15, 256}

	statusListEntry, err := GenerateStatusList(totalCredentials, revokedIndexes)
	if err != nil {
		fmt.Printf("Error: %v \n", err)
		return
	}

	fmt.Println("Status List Entry: ")
	for k, v := range statusListEntry {
		fmt.Printf(" %s: %v\n", k, v)
	}
}
