package justencrypt

import (
	"encoding/hex"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

type KeyDerivationFixture struct {
	Password     *string `json:"password"`
	Password_Utf *string `json:"password_utf8"`
	Salt         string  `json:"salt"`
	Iterations   int     `json:"iterations"`
	Expected     string  `json:"output"`
}

type KeyDerivationFixtures struct {
	Fixtures []*KeyDerivationFixture `json:"keyderivation"`
}

func GetKeyDerivationFixtures() *KeyDerivationFixtures {
	d := readFile("crypt_vectors.json")

	fixtures := KeyDerivationFixtures{
		Fixtures: make([]*KeyDerivationFixture, 0),
	}
	err := json.Unmarshal(d, &fixtures)
	if err != nil {
		panic(err)
	}
	return &fixtures
}

type DecryptionFixture struct {
	Password        string `json:"password"`
	PrimarySeed     string `json:"primaryEncryptedSeed"`
	EncryptedSecret string `json:"encryptedSecret"`
	Checksum        string `json:"checksum"`
}

type DecryptionFixtures struct {
	Fixtures []*DecryptionFixture `json:"decryptonly"`
}

func GetDecryptionFixtures() *DecryptionFixtures {
	d := readFile("crypt_vectors.json")

	fixtures := DecryptionFixtures{
		Fixtures: make([]*DecryptionFixture, 0),
	}
	err := json.Unmarshal(d, &fixtures)
	if err != nil {
		panic(err)
	}
	return &fixtures
}

type EncryptionFixture struct {
	Password   string `json:"password"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Key        string `json:"key"`
	Iv         string `json:"iv"`
	PlainText  string `json:"pt"`
	CipherText string `json:"ct"`
	Tag        string `json:"tag"`
	Full       string `json:"full"`
}

type EncryptionFixtures struct {
	Fixtures []*EncryptionFixture `json:"encryption"`
}

func GetEncryptionFixtures() *EncryptionFixtures {
	d := readFile("crypt_vectors.json")

	fixtures := EncryptionFixtures{
		Fixtures: make([]*EncryptionFixture, 0),
	}
	err := json.Unmarshal(d, &fixtures)
	if err != nil {
		panic(err)
	}
	return &fixtures
}

type PasswordResetFixture struct {
	Password   string `json:"password"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Key        string `json:"key"`
	Iv         string `json:"iv"`
	PlainText  string `json:"pt"`
	CipherText string `json:"ct"`
	Tag        string `json:"tag"`
	Full       string `json:"full"`
}

type PasswordResetFixtures struct {
	Fixtures []*PasswordResetFixture `json:"password_reset_case"`
}

func GetPasswordResetFixtures() *PasswordResetFixtures {
	d := readFile("crypt_vectors.json")

	fixtures := PasswordResetFixtures{
		Fixtures: make([]*PasswordResetFixture, 0),
	}
	err := json.Unmarshal(d, &fixtures)
	if err != nil {
		panic(err)
	}
	return &fixtures
}

type MnemonicFixture struct {
	Data     string `json:"data"`
	Mnemonic string `json:"mnemonic"`
}

type MnemonicFixtures struct {
	Fixtures []*MnemonicFixture `json:"mnemonic"`
}

func GetMnemonicFixtures() *MnemonicFixtures {
	d := readFile("crypt_vectors.json")

	fixtures := MnemonicFixtures{
		Fixtures: make([]*MnemonicFixture, 0),
	}
	err := json.Unmarshal(d, &fixtures)
	if err != nil {
		panic(err)
	}
	return &fixtures
}

func TestKeyDerivation(t *testing.T) {
	fixtures := GetKeyDerivationFixtures()

	for i, fixture := range fixtures.Fixtures {
		//for i := 0; i < 1; i++ {
		//	fixture := fixtures.Fixtures[i]
		t.Run(desc(i), func(t *testing.T) {
			expectedKey, err := hex.DecodeString(fixture.Expected)

			salt, err := hex.DecodeString(fixture.Salt)
			if err != nil {
				panic(err)
			}

			header := &Header{
				Iterations: uint32(fixture.Iterations),
				Salt:       salt,
				SaltLen:    uint8(len(salt)),
			}

			var password []byte
			if fixture.Password != nil {
				password, err = hex.DecodeString(*fixture.Password)
				if err != nil {
					panic(err)
				}
			} else if fixture.Password_Utf != nil {
				password = []byte(*fixture.Password_Utf)
			} else {
				panic(errors.New("Incomplete test"))
			}
			key, err := header.DeriveKey(password)
			assert.NoError(t, err)
			assert.Equal(t, expectedKey, key)
		})
	}
}

func TestEncryption(t *testing.T) {
	fixtures := GetEncryptionFixtures()

	for i, fixture := range fixtures.Fixtures {
		t.Run(desc(i), func(t *testing.T) {

			salt, err := hex.DecodeString(fixture.Salt)
			if err != nil {
				panic(err)
			}

			header := &Header{
				Iterations: uint32(fixture.Iterations),
				Salt:       salt,
				SaltLen:    uint8(len(salt)),
			}

			iv, err := hex.DecodeString(fixture.Iv)
			if err != nil {
				panic(err)
			}
			pw, err := hex.DecodeString(fixture.Password)
			if err != nil {
				panic(err)
			}
			pt, err := hex.DecodeString(fixture.PlainText)
			if err != nil {
				panic(err)
			}
			ct, err := hex.DecodeString(fixture.CipherText)
			if err != nil {
				panic(err)
			}
			tag, err := hex.DecodeString(fixture.Tag)
			if err != nil {
				panic(err)
			}
			expectedFullCt, err := hex.DecodeString(fixture.Full)
			if err != nil {
				panic(err)
			}

			innerShouldBe := make([]byte, 0, len(ct) + len(tag))
			innerShouldBe = append(innerShouldBe, ct...)
			innerShouldBe = append(innerShouldBe, tag...)

			headerBytes, ivBytes, ctBytes, err := header.EncryptInnerWithIv(pt, pw, iv)
			assert.NoError(t, err)
			assert.Equal(t, header.ToBytes(), headerBytes)
			assert.Equal(t, innerShouldBe, ctBytes)
			assert.Equal(t, iv, ivBytes)

			ourFull := make([]byte, 0, len(headerBytes) + len(ivBytes) + len(ctBytes))
			ourFull = append(ourFull, headerBytes...)
			ourFull = append(ourFull, iv...)
			ourFull = append(ourFull, ctBytes...)

			assert.Equal(t, expectedFullCt, ourFull)

			decryptedInner, err := header.DecryptInner(ctBytes, iv, pw)
			assert.NoError(t, err)
			assert.Equal(t, pt, decryptedInner)

			decryptedFull, err := Decrypt(ourFull, pw)
			assert.NoError(t, err)
			assert.Equal(t, pt, decryptedFull)
		})
	}
}
