package spi

import (
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	kms_spi "github.com/hyperledger/aries-framework-go/spi/kms"
)

type mockStorageProvider struct {
	storage    kms_spi.Store
	secretLock secretlock.Service
}

func MockStorageProvider(storage kms_spi.Store, secretLock secretlock.Service) kms_spi.Provider {
	return &mockStorageProvider{
		storage:    storage,
		secretLock: secretLock,
	}
}

func (m *mockStorageProvider) StorageProvider() kms_spi.Store {
	return m.storage
}

func (m *mockStorageProvider) SecretLock() secretlock.Service {
	return m.secretLock
}
