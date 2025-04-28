package storage

import (
	"fmt"
	"log"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/stretchr/testify/assert"
)

func TestMemStorage(t *testing.T) {
	// 构建 Aries 框架实例
	ariesInstance, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
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

	err = runMemStorageOperations(ariesCtx)
	if err != nil {
		log.Fatalf("Failed to run example operations (v0.3.2): %v", err)
	}

	log.Println("Example operations completed successfully (v0.3.2)")
}

func runMemStorageOperations(ariesCtx *context.Provider) error {
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
