package kms

import (
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	kms_spi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/assert"
)

const testMasterKeyURI = "local-lock://test/key/uri"

func TestEncryptDecrypt_Roate(t *testing.T) {

	// 构建 Secret Lock 对象
	sl := createMasterKeyAndSecretLock(t)

	// 构建 KMS Store 对象
	kmsStore := newInMemoryKMSStore()

	// 构建 KMS 服务对象
	kmsService, err := localkms.New(testMasterKeyURI, &mockStorageProvider{
		storage:    kmsStore,
		secretLock: sl,
	})
	assert.NoError(t, err)

	keyTemplates := []kms_spi.KeyType{
		kms_spi.AES128GCMType,
		kms_spi.AES256GCMNoPrefixType,
		kms_spi.AES256GCMType,
		kms_spi.ChaCha20Poly1305,
		kms_spi.XChaCha20Poly1305,
	}

	for _, v := range keyTemplates {
		// 创建一个新的密钥
		keyID, keyHandle, e := kmsService.Create(v)
		assert.NoError(t, e)

		// 构建一个 tinkcrypto 对象
		c := tinkcrypto.Crypto{}
		msg := []byte("Test Rotation Message")
		associatedData := []byte("some additional data")

		cipherText, nonce, e := c.Encrypt(msg, associatedData, keyHandle)
		assert.NoError(t, e)

		newKeyID, rotatedKeyHandle, e := kmsService.Rotate(v, keyID)
		assert.NoError(t, e)
		assert.NotEqual(t, newKeyID, keyID)

		decryptedMsg, e := c.Decrypt(cipherText, associatedData, nonce, rotatedKeyHandle)
		assert.NoError(t, e)
		assert.Equal(t, msg, decryptedMsg)
	}
}

func TestEncryptDecrypt_NoRotate(t *testing.T) {

	// 构建 Secret Lock 对象
	sl := createMasterKeyAndSecretLock(t)

	// 构建 KMS Store 对象
	kmsStore := newInMemoryKMSStore()

	// 构建 KMS 服务对象
	kmsService, err := localkms.New(testMasterKeyURI, &mockStorageProvider{
		storage:    kmsStore,
		secretLock: sl,
	})
	assert.NoError(t, err)

	keyTemplates := []kms_spi.KeyType{
		kms_spi.AES128GCMType,
		kms_spi.AES256GCMNoPrefixType,
		kms_spi.AES256GCMType,
		kms_spi.ChaCha20Poly1305,
		kms_spi.XChaCha20Poly1305,
	}

	for _, v := range keyTemplates {
		// 创建一个新的密钥
		_, keyHandle, e := kmsService.Create(v)
		assert.NoError(t, e)

		// 构建一个 tinkcrypto 对象
		c := tinkcrypto.Crypto{}
		msg := []byte("Test Rotation Message")
		aad := []byte("some additional data")

		cipherText, nonce, e := c.Encrypt(msg, aad, keyHandle)
		assert.NoError(t, e)

		decryptedMsg, e := c.Decrypt(cipherText, aad, nonce, keyHandle)
		assert.NoError(t, e)
		assert.Equal(t, msg, decryptedMsg)
	}
}

func createMasterKeyAndSecretLock(t *testing.T) secretlock.Service {
	masterKeyFilePath := "masterKey_file.txt"
	tmpfile, err := os.CreateTemp("", masterKeyFilePath)
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, tmpfile.Close())
		assert.NoError(t, os.Remove(tmpfile.Name()))
	}()

	masterKeyContent := random.GetRandomBytes(uint32(32))
	passphrase := "secretPassphrase"
	keySize := sha256.Size
	salt := make([]byte, keySize)
	_, err = rand.Read(salt)
	assert.NoError(t, err)

	masterLocker, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
	assert.NoError(t, err)

	masterLockEnc, err := masterLocker.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	assert.NoError(t, err)

	n, err := tmpfile.Write([]byte(masterLockEnc.Ciphertext))
	assert.NoError(t, err)
	assert.Equal(t, len(masterLockEnc.Ciphertext), n)

	r, err := local.MasterKeyFromPath(tmpfile.Name())
	assert.NoError(t, err)

	s, err := local.NewService(r, masterLocker)
	assert.NoError(t, err)

	return s
}
