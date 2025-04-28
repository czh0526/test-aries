package tink

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"
)

func TestAEAD_EncryptDecrypt(t *testing.T) {
	// 根据算法，构建 Handle
	handle, err := keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate())
	assert.NoError(t, err)

	// 使用 Handle 创建 AEAD primitive
	primitive, err := aead.New(handle)
	assert.NoError(t, err)

	plaintext := []byte("Hello, Tink!")
	additionalData := []byte("Additional Authenticated Data")

	// 加密
	ciphertext, err := primitive.Encrypt(plaintext, additionalData)
	assert.NoError(t, err)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// 解密
	decrypted, err := primitive.Decrypt(ciphertext, additionalData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
