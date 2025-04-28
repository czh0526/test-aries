package storage

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/stretchr/testify/assert"
)

func TestLevelDbStorage(t *testing.T) {
	dbPath := setupLevelDB(t)

	// 构建 Aries 框架实例
	ariesInstance, err := aries.New(
		aries.WithStoreProvider(leveldb.NewProvider(dbPath)),
	)
	assert.NoError(t, err)

	defer func() {
		err = ariesInstance.Close()
		if err != nil {
			log.Fatalf("Failed to close Aries framework (v0.3.2): %v", err)
		}
	}()

	// 获取 Aries 上下文
	// 这里的上下文是一个提供者，包含了存储、密钥管理等服务
	// 你可以在这个上下文中使用存储服务来进行数据存储和检索
	ariesCtx, err := ariesInstance.Context()
	if err != nil {
		log.Fatalf("Failed to get context from Aries framework (v0.3.2): %v", err)
	}

	err = runLevelDbOperations(ariesCtx)
	if err != nil {
		log.Fatalf("Failed to run example operations (v0.3.2): %v", err)
	}

	log.Println("Example operations completed successfully (v0.3.2)")
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

func runLevelDbOperations(ariesCtx *context.Provider) error {
	store, err := ariesCtx.StorageProvider().OpenStore("example-store")
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}

	err = store.Put("key1", []byte("value1"))
	if err != nil {
		return fmt.Errorf("failed to put value in store: %w", err)
	}

	value, err := store.Get("key1")
	if err != nil {
		return fmt.Errorf("failed to get value from store: %w", err)
	}
	log.Printf("Retrieved (key1): `%s`\n", value)

	return nil
}
