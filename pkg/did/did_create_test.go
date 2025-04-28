package did

import (
	"fmt"
	"testing"

	"crypto/ed25519"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/assert"
)

func TestVdrRead(t *testing.T) {

	storeProvider := mem.NewProvider()

	//
	secretLock := &noop.NoLock{}

	kmsStore, err := kms.NewAriesProviderWrapper(storeProvider)
	assert.NoError(t, err)

	kmsProvider := kmsProvider{
		store:             kmsStore,
		secretLockService: secretLock,
	}
	localKMS, err := localkms.New("local-lock://test-lock/", &kmsProvider)
	assert.NoError(t, err)

	// 创建密钥对
	secretId, publicKey, err := localKMS.CreateAndExportPubKeyBytes(kms.ED25519)
	assert.NoError(t, err)
	fmt.Printf("Secret ID: %s\n", secretId)

	// 创建 KeyId
	didKey, keyId := fingerprint.CreateDIDKey(publicKey)
	fmt.Printf("did key => %v \n", didKey)
	fmt.Printf("key id  => %v \n", keyId)

	vdrKey := vdrkey.New()
	didDoc, err := vdrKey.Read(didKey)
	assert.NoError(t, err)

	documentBytes, err := didDoc.DIDDocument.JSONBytes()
	assert.NoError(t, err)
	fmt.Printf("DID: %s\n", documentBytes)

	docBytes, err := didDoc.JSONBytes()
	assert.NoError(t, err)
	fmt.Printf("DID: %s\n", docBytes)
}

type kmsProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

func TestVdrCreate(t *testing.T) {
	ed25519Type := "Ed25519VerificationKey2018"
	ed25519PublicKeyBase58 := "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"

	verificationMethod := did.VerificationMethod{
		Type:  ed25519Type,
		Value: ed25519.PublicKey(base58.Decode(ed25519PublicKeyBase58)),
	}

	vdrKey := vdrkey.New()
	docResolution, err := vdrKey.Create(&did.Doc{
		VerificationMethod: []did.VerificationMethod{verificationMethod},
	})
	assert.NoError(t, err)

	docResolitionBytes, err := docResolution.JSONBytes()
	assert.NoError(t, err)

	fmt.Printf("DID: %s\n", docResolitionBytes)
}
