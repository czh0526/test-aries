package localkms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/czh0526/test-aries/spi"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/assert"
)

const testMasterKeyURI = "local-lock://test/key/uri"

func TestImportECDSAKey(t *testing.T) {
	localKms, err := createLocalKms()
	assert.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	_, _, err = localKms.ImportPrivateKey(privKey, kms.ECDSAP256TypeDER)
	assert.NoError(t, err)
}

func TestImportEd25519Key(t *testing.T) {
	localKms, err := createLocalKms()
	assert.NoError(t, err)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	_, _, err = localKms.ImportPrivateKey(privKey, kms.ED25519Type)
	assert.NoError(t, err)
}

func createLocalKms() (*localkms.LocalKMS, error) {

	kmsStore := spi.NewInMemoryKMSStore()

	// Create a new LocalKMS instance
	kms, err := localkms.New("local-lock://test/key/uri",
		spi.MockStorageProvider(kmsStore, &noop.NoLock{}),
	)
	if err != nil {
		return nil, err
	}

	return kms, nil
}
