package storage

import (
	"log"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/stretchr/testify/assert"
)

func TestStorage_LevelDB(t *testing.T) {

	dbPath := setupLevelDB(t)
	store, err := leveldb.NewProvider(dbPath).OpenStore("leveldb-store")
	assert.NoError(t, err)

	err = store.Put("key1", []byte("value1"))
	assert.NoError(t, err)

	value, err := store.Get("key1")
	assert.NoError(t, err)

	log.Printf("Retrieved (key1): `%s`\n", value)

}

func setupLevelDB(t *testing.T) string {
	dbPath, err := os.MkdirTemp("", "leveldb")
	if err != nil {
		t.Fatalf("Failed to create temp dir for leveldb: %v", err)
	}

	t.Cleanup(func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to remove temp dir for leveldb: %v", err)
		}
	})
	return dbPath
}
