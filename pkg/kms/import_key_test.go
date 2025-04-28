package kms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/czh0526/test-aries/spi"
	"github.com/google/tink/go/subtle/random"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
	kms_spi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/assert"
)

const maxKeyIDLen = 50

func TestLocalKMS_ImportPrivateKey(t *testing.T) {
	sl := createMasterKeyAndSecretLock(t)

	kmsStore := spi.NewInMemoryKMSStore()
	kmsService, e := localkms.New(testMasterKeyURI,
		spi.MockStorageProvider(kmsStore, sl),
	)
	assert.NoError(t, e)

	flagTests := []struct {
		tcName  string
		keyType kms_spi.KeyType
		curve   elliptic.Curve
		setID   bool
		ksID    string
	}{
		{
			tcName:  "import private key using ECDSA256DER type",
			keyType: kms_spi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSA384DER type",
			keyType: kms_spi.ECDSAP384TypeDER,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSA521DER type",
			keyType: kms_spi.ECDSAP521TypeDER,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using NISTP256ECDHKW type",
			keyType: kms_spi.NISTP256ECDHKWType,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using NISTP384ECDHKW type",
			keyType: kms_spi.NISTP384ECDHKWType,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using NISTP521ECDHKW type",
			keyType: kms_spi.NISTP521ECDHKWType,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using ECDSAP256TypeIEEEP1363 type",
			keyType: kms_spi.ECDSAP256TypeIEEEP1363,
			curve:   elliptic.P256(),
		},
		{
			tcName:  "import private key using ECDSAP384TypeIEEEP1363 type",
			keyType: kms_spi.ECDSAP384TypeIEEEP1363,
			curve:   elliptic.P384(),
		},
		{
			tcName:  "import private key using ECDSAP521TypeIEEEP1363 type",
			keyType: kms_spi.ECDSAP521TypeIEEEP1363,
			curve:   elliptic.P521(),
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set empty KeyID",
			keyType: kms_spi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID:    "",
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non empty KeyID",
			keyType: kms_spi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(maxKeyIDLen)))),
		},
		{
			tcName:  "import private key using ECDSAP256DER type and a set non KeyID larger than maxKeyIDLen",
			keyType: kms_spi.ECDSAP256TypeDER,
			curve:   elliptic.P256(),
			setID:   true,
			ksID: base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(
				uint32(base64.RawURLEncoding.DecodedLen(30)))),
		},
		{
			tcName:  "import private key using ECDSAP256IEEEP1363 type",
			keyType: kms_spi.ECDSASecp256k1IEEEP1363,
			curve:   btcec.S256(),
		},
		{
			tcName:  "import private key using ED25519Type type",
			keyType: kms_spi.ED25519Type,
		},
		{
			tcName:  "import private key using BLS12381G2Type type",
			keyType: kms_spi.BLS12381G2Type,
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			if tt.keyType == kms_spi.ED25519Type {
				pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
				assert.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				assert.NoError(t, err)

				pubKeyBytes, kt, err := kmsService.ExportPubKeyBytes(ksID)
				assert.NoError(t, err)
				assert.EqualValues(t, pubKey, pubKeyBytes)
				assert.Equal(t, tt.keyType, kt)
				return
			}

			if tt.keyType == kms_spi.BLS12381G2Type {
				seed := make([]byte, 32)

				_, err := rand.Read(seed)
				assert.NoError(t, err)

				pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
				assert.NoError(t, err)

				ksID, _, err := kmsService.ImportPrivateKey(privKey, tt.keyType)
				assert.NoError(t, err)

				pubKeyBytes, kt, err := kmsService.ExportPubKeyBytes(ksID)
				assert.NoError(t, err)
				assert.Equal(t, tt.keyType, kt)

				expectedPubKeyBytes, err := pubKey.Marshal()
				assert.NoError(t, err)
				assert.EqualValues(t, expectedPubKeyBytes, pubKeyBytes)
				return
			}

			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			assert.NoError(t, err)

			var ksID string
			if tt.setID {
				// 导入私钥
				// 指定 ksID
				ksID, _, err = kmsService.ImportPrivateKey(privKey, tt.keyType, kms_spi.WithKeyID(tt.ksID))
				assert.NoError(t, err)
				if tt.ksID != "" {
					assert.Equal(t, tt.ksID, ksID)
				}
			} else {
				// 导入私钥
				// 这里的 ksID 是随机生成的
				ksID, _, err = kmsService.ImportPrivateKey(privKey, tt.keyType)
				assert.NoError(t, err)
			}

			// 实际导出的公钥
			actualPubKey, kt, err := kmsService.ExportPubKeyBytes(ksID)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyType, kt)

			// 构建期待的公钥
			var expectedPubKey []byte
			switch tt.keyType {
			case kms_spi.ECDSAP256TypeDER, kms_spi.ECDSAP384TypeDER, kms_spi.ECDSAP521TypeDER, kms_spi.ECDSASecp256k1TypeDER:
				expectedPubKey, err = x509.MarshalPKIXPublicKey(privKey.Public())
				assert.NoError(t, err)

			case kms_spi.ECDSAP256TypeIEEEP1363, kms_spi.ECDSAP384TypeIEEEP1363, kms_spi.ECDSAP521TypeIEEEP1363, kms_spi.ECDSASecp256k1TypeIEEEP1363:
				expectedPubKey = elliptic.Marshal(tt.curve, privKey.X, privKey.Y)

			case kms_spi.NISTP256ECDHKWType, kms_spi.NISTP384ECDHKWType, kms_spi.NISTP521ECDHKWType:
				var curveName string
				switch tt.curve.Params().Name {
				case "P-256":
					curveName = "NIST_P256"
				case "P-384":
					curveName = "NIST_P384"
				case "P-521":
					curveName = "NIST_P521"
				case "secp256k1":
					curveName = "secp256k1"
				}

				cryptoKey := &crypto.PublicKey{
					KID:   ksID,
					X:     privKey.PublicKey.X.Bytes(),
					Y:     privKey.PublicKey.Y.Bytes(),
					Curve: curveName,
					Type:  "EC",
				}

				expectedPubKey, err = json.Marshal(cryptoKey)
				assert.NoError(t, err)
			}

			// 验证'导出的公钥'与'预期的公钥'相等
			assert.EqualValues(t, expectedPubKey, actualPubKey)
		})
	}

	kmsStoreJson, err := json.MarshalIndent(kmsStore, "", "  ")
	assert.NoError(t, err)

	fmt.Printf("%s \n", kmsStoreJson)
}
