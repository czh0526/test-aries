package tink

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/stretchr/testify/assert"
)

func TestEcdsa_SignVerify(t *testing.T) {

	privHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	assert.NoError(t, err)

	pubHandle, err := privHandle.Public()
	assert.NoError(t, err)

	primitive, err := signature.NewSigner(privHandle)
	assert.NoError(t, err)

	data := []byte("message")
	sig, err := primitive.Sign(data)
	assert.NoError(t, err)

	verifier, err := signature.NewVerifier(pubHandle)
	assert.NoError(t, err)

	err = verifier.Verify(sig, data)
	assert.NoError(t, err)
}
