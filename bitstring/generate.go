package bitstring

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func GenerateStatusList(totalCredentials int, revokedIndexes []int) (map[string]interface{}, error) {
	if totalCredentials <= 0 {
		return nil, errors.New("totalCredentials must be greater than 0")
	}

	bitString := strings.Repeat("0", totalCredentials)
	bitStringBytes := []byte(bitString)

	for _, index := range revokedIndexes {
		if index < 0 || index >= totalCredentials {
			return nil, fmt.Errorf("index out of bounds, index = %v", index)
		}
		bitStringBytes[index] = '1'
	}
	bitStringBinary := bitStringBytesToBytes(bitStringBytes)

	encodedList := base64.StdEncoding.EncodeToString(bitStringBinary)

	statusListEntry := map[string]interface{}{
		"statusPurpose":   "revocation",
		"bitStringLength": totalCredentials,
		"encodedList":     encodedList,
	}

	return statusListEntry, nil
}

func bitStringBytesToBytes(bitStringBytes []byte) []byte {
	bitLength := len(bitStringBytes)
	byteLength := (bitLength + 7) / 8
	binaryBytes := make([]byte, byteLength)

	for i := 0; i < bitLength; i++ {
		if bitStringBytes[i] == '1' {
			byteIndex := i / 8
			bitIndex := uint(7 - (i % 8)) // Bits are indexed from most significant bit
			binaryBytes[byteIndex] |= 1 << bitIndex
		}
	}

	return binaryBytes
}
