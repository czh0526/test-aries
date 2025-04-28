package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/stretchr/testify/assert"
)

const testMasterKeyURI = "local-lock://test/key/uri"

func TestIMportECDSAKeyWithInvalidKey(t *testing.T) {
	k := createKMS(t)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	_, _, err = k.ImportPrivateKey(privKey, kms.ECDSAP256TypeDER)
	assert.NoError(t, err)
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	// Create a new LocalKMS instance
	kms, err := localkms.New("local-lock://test/key/uri", nil)
	assert.NoError(t, err)

	return kms
}
