package tink

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testing/fakekms"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/assert"
)

const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"

func TestKeySet_OneKey(t *testing.T) {
	client, err := fakekms.NewClient(keyURI)
	assert.NoError(t, err)

	kekAEAD, err := client.GetAEAD(keyURI)
	assert.NoError(t, err)

	// 为 Primitive 生成一个 Handle
	newHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	assert.NoError(t, err)

	// 对 keyset 进行加密
	keysetAssociatedData := []byte("keyset encryption example")
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = newHandle.WriteWithAssociatedData(writer, kekAEAD, keysetAssociatedData)
	assert.NoError(t, err)
	encryptedKeyset := buf.Bytes()

	// encryptedKeyset 可以被用来存储或传输

	// 对 keyset 进行解密
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle, err := keyset.ReadWithAssociatedData(reader, kekAEAD, keysetAssociatedData)
	assert.NoError(t, err)

	// ========= 以下是使用 AEAD primitive 加、解密的例子 ==========

	// 获取 Primitive
	primitive, err := aead.New(handle)
	assert.NoError(t, err)

	// 使用 Primitive 进行加密和解密
	plaintext := []byte("some message")
	assiciatedData := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, assiciatedData)
	assert.NoError(t, err)

	decrypted, err := primitive.Decrypt(ciphertext, assiciatedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	fmt.Printf("\tplain text => %s\n", plaintext)
	fmt.Printf("\tciphertext => %v\n", ciphertext)
	fmt.Printf("\tdecrypt text => %s\n", decrypted)

	// 加解密第二次
	primitive, err = aead.New(handle)
	assert.NoError(t, err)
	ciphertext, err = primitive.Encrypt(plaintext, assiciatedData)
	assert.NoError(t, err)

	decrypted, err = primitive.Decrypt(ciphertext, assiciatedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	fmt.Printf("\tplain text => %s\n", plaintext)
	fmt.Printf("\tciphertext => %v\n", ciphertext)
	fmt.Printf("\tdecrypt text => %s\n", decrypted)
}

func TestKeySet_MultiKeys_KeyInfo(t *testing.T) {

	associatedData := []byte("keyset encryption example")

	// 保存序列化的 kms
	encryptedKmsBytes, err := saveKmsToBytes(associatedData)
	assert.NoError(t, err)
	fmt.Printf("%s \n", encryptedKmsBytes)

	// 加载 kms Handle
	kmsHandle, err := loadKmsFromBytes(encryptedKmsBytes, associatedData)
	assert.NoError(t, err)
	manager := keyset.NewManagerFromHandle(kmsHandle)

	keysetInfo := kmsHandle.KeysetInfo()
	for _, keyInfo := range keysetInfo.KeyInfo {

		fmt.Printf("keyInfo => %v\n", keyInfo)
		fmt.Println()
		// 使用主密钥进行加解密
		extractedHandle, err := extractHandleByKeyId(manager, keyInfo.KeyId, nil)
		assert.NoError(t, err)
		fmt.Printf("extractedHandle => %v\n", extractedHandle)
		primitive, err := aead.New(extractedHandle)
		assert.NoError(t, err)

		plaintext := []byte("some message")
		associatedData := []byte("example encryption")
		ciphertext, err := primitive.Encrypt(plaintext, associatedData)
		assert.NoError(t, err)

		decrypted, err := primitive.Decrypt(ciphertext, associatedData)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
		fmt.Printf("\tplain text => %s\n", plaintext)
		fmt.Printf("\tciphertext => %v\n", ciphertext)
		fmt.Printf("\tdecrypt text => %s\n", decrypted)

	}
}

func extractHandleByKeyId(manager *keyset.Manager, keyId uint32, kekAEAD tink.AEAD) (*keyset.Handle, error) {

	err := manager.SetPrimary(keyId)
	if err != nil {
		return nil, err
	}

	handle, err := manager.Handle()
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func TestKeySet_MultiKeys_Primitive(t *testing.T) {

	associatedData := []byte("keyset encryption example")

	// 保存序列化的 kms
	encryptedKmsBytes, err := saveKmsToBytes(associatedData)
	assert.NoError(t, err)

	// 加载 kms Handle
	kmsHandle, err := loadKmsFromBytes(encryptedKmsBytes, associatedData)
	assert.NoError(t, err)

	primitives, err := kmsHandle.Primitives()
	assert.NoError(t, err)
	for prefix, entries := range primitives.Entries {
		fmt.Println()
		fmt.Printf("entries => %x\n", []byte(prefix))
		for _, entry := range entries {
			fmt.Printf("\tkeyId => %d\n", entry.KeyID)
			fmt.Printf("\tprefix => %x\n", []byte(entry.Prefix))
			fmt.Printf("\tprefix type => %s\n", entry.PrefixType)
			fmt.Printf("\ttypeUrl => %s\n", entry.TypeURL)
			primitive, ok := entry.Primitive.(tink.AEAD)
			assert.True(t, ok)

			plaintext := []byte("some message")
			associatedData := []byte("example encryption")
			ciphertext, err := primitive.Encrypt(plaintext, associatedData)
			assert.NoError(t, err)

			decrypted, err := primitive.Decrypt(ciphertext, associatedData)
			assert.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
			fmt.Printf("\tplain text => %s\n", plaintext)
			fmt.Printf("\tciphertext => %v\n", ciphertext)
			fmt.Printf("\tdecrypt text => %s\n", decrypted)
		}
	}
}

func saveKmsToBytes(associatedData []byte) ([]byte, error) {
	// 创建一个 keyset 管理器
	manager := keyset.NewManager()

	// 添加第一个密钥(AES256-GCM)
	// 注意：这里的 keyIdAes256Gcm 是一个新的密钥 ID
	keyIdAes256Gcm, err := manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	fmt.Printf("keyIdAes256Gcm => %d\n", keyIdAes256Gcm)
	keyIdAes256Gcm, err = manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	fmt.Printf("keyIdAes256Gcm => %d\n", keyIdAes256Gcm)

	// 添加第二个密钥(AES128-GCM)
	// 注意：这里的 keyIdAes128Gcm 是一个新的密钥 ID
	keyIdAes128Gcm, err := manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	fmt.Printf("keyIdAes128Gcm => %d\n", keyIdAes128Gcm)

	// 设置第一个密钥为主密钥
	err = manager.SetPrimary(keyIdAes256Gcm)
	if err != nil {
		return nil, err
	}

	// 连接 Kms
	kmsClient, err := fakekms.NewClient(keyURI)
	if err != nil {
		return nil, err
	}

	kmsAEAD, err := kmsClient.GetAEAD(keyURI)
	if err != nil {
		return nil, err
	}

	// 将 keyset 写入加密存储
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	kmsHandle, err := manager.Handle()
	if err != nil {
		return nil, err
	}

	if associatedData != nil {
		err = kmsHandle.WriteWithAssociatedData(writer, kmsAEAD, associatedData)
	} else {
		err = kmsHandle.WriteWithNoSecrets(writer)
	}
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func loadKmsFromBytes(kmsBytes []byte, associatedData []byte) (*keyset.Handle, error) {

	kmsClient, err := fakekms.NewClient(keyURI)
	if err != nil {
		return nil, err
	}

	kmsAEAD, err := kmsClient.GetAEAD(keyURI)
	if err != nil {
		return nil, err
	}

	reader := keyset.NewBinaryReader(bytes.NewReader(kmsBytes))
	var kmsHandle *keyset.Handle
	if associatedData != nil {
		kmsHandle, err = keyset.ReadWithAssociatedData(reader, kmsAEAD, associatedData)
	} else {
		kmsHandle, err = keyset.Read(reader, kmsAEAD)
	}
	if err != nil {
		return nil, err
	}

	return kmsHandle, nil
}
