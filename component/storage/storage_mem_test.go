package storage

import (
	"log"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/assert"
)

func TestStorage_Mem(t *testing.T) {

	store, err := mem.NewProvider().OpenStore("mem-store")
	assert.NoError(t, err)

	err = store.Put("key1", []byte("value1"))
	assert.NoError(t, err)

	value, err := store.Get("key1")
	assert.NoError(t, err)

	log.Printf("Retrieved (key1): `%s`\n", value)

}
