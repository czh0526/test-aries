package spi

import (
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	kms_spi "github.com/hyperledger/aries-framework-go/spi/kms"
)

type inMemoryKMSStore struct {
	Keys map[string][]byte
}

func NewInMemoryKMSStore() kms_spi.Store {
	return &inMemoryKMSStore{
		Keys: make(map[string][]byte),
	}
}

func (s *inMemoryKMSStore) Put(secretId string, key []byte) error {
	s.Keys[secretId] = key
	return nil
}

func (s *inMemoryKMSStore) Get(secretId string) ([]byte, error) {
	key, ok := s.Keys[secretId]
	if !ok {
		return nil, kms.ErrKeyNotFound
	}
	return key, nil
}

func (s *inMemoryKMSStore) Delete(secretId string) error {
	delete(s.Keys, secretId)
	return nil
}
