package justencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"github.com/btcsuite/golangcrypto/pbkdf2"
	"github.com/pkg/errors"
	"hash"
	"io"
)

const (
	KeySizeBytes = 32
	IvLen        = 16
	// Maximum salt len
	MaxSaltLen        uint8  = 0x80
	DefaultSaltLen    uint8  = 13
	DefaultIterations uint32 = 35000
)

var (
	ErrPasswordIsEmpty = errors.New("Password must not be empty")
	ErrSaltIsEmpty     = errors.New("Salt must not be empty")
	ErrSaltTooLong     = errors.New("Salt too long")
	ErrSaltLenMismatch = errors.New("`saltLen` should match the length of `salt`")

	HashingAlgo func() hash.Hash = sha512.New
	emptyArray                   = []byte{}
)

type Header struct {
	SaltLen    uint8
	Salt       []byte
	Iterations uint32
}

func (h *Header) Generate() error {

	iterations := DefaultIterations
	saltLen := DefaultSaltLen

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	return h.Init(salt, saltLen, iterations)
}

func (h *Header) Parse(reader io.Reader) error {
	var saltLen uint8 = 0
	err := binary.Read(reader, binary.BigEndian, &saltLen)
	if err != nil {
		return errors.Wrapf(err, "failed to parse saltLen")
	}

	if saltLen > MaxSaltLen {
		return ErrSaltTooLong
	}

	salt := make([]byte, saltLen)
	err = binary.Read(reader, binary.BigEndian, &salt)
	if err != nil {
		return errors.Wrapf(err, "failed to parse salt")
	}

	var iter uint32 = 0
	err = binary.Read(reader, binary.LittleEndian, &iter)

	h.SaltLen = saltLen
	h.Salt = salt
	h.Iterations = iter

	return nil
}

func (h *Header) Init(salt []byte, saltLen uint8, iterations uint32) error {
	if saltLen == 0 {
		return ErrSaltIsEmpty
	}

	l := len(salt)
	if saltLen != uint8(l) {
		return ErrSaltLenMismatch
	}

	if saltLen > MaxSaltLen {
		return ErrSaltTooLong
	}

	h.SaltLen = saltLen
	h.Salt = salt
	h.Iterations = iterations

	return nil
}

func (h *Header) DeriveKey(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrPasswordIsEmpty
	}

	return pbkdf2.Key(passphrase, h.Salt, int(h.Iterations), KeySizeBytes, HashingAlgo), nil
}

func (h *Header) EncryptInner(plaintext []byte, passphrase []byte) ([]byte, []byte, []byte, error) {
	iv := make([]byte, IvLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return emptyArray, emptyArray, emptyArray, err
	}

	return h.EncryptInnerWithIv(plaintext, passphrase, iv)
}

func (h *Header) EncryptInnerWithIv(plaintext []byte, passphrase []byte, iv []byte) ([]byte, []byte, []byte, error) {
	if len(iv) != IvLen {
		return emptyArray, emptyArray, emptyArray, errors.New("IV is the wrong length")
	}
	key, err := h.DeriveKey(passphrase)
	if err != nil {
		return emptyArray, emptyArray, emptyArray, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return emptyArray, emptyArray, emptyArray, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, IvLen)
	if err != nil {
		return emptyArray, emptyArray, emptyArray, err
	}

	header := h.ToBytes()
	ciphertext := aesgcm.Seal(nil, iv, plaintext, header)
	return header, iv, ciphertext, nil
}

func (h *Header) DecryptInner(ciphertext []byte, iv []byte, passphrase []byte) ([]byte, error) {
	key, err := h.DeriveKey(passphrase)
	if err != nil {
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, IvLen)
	if err != nil {
		return []byte{}, err
	}

	header := h.ToBytes()
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, header)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}

func (h *Header) ToBytes() []byte {
	size := 1 + 4 + h.SaltLen

	var iterBytes [4]byte
	binary.LittleEndian.PutUint32(iterBytes[:], h.Iterations)

	serialized := make([]byte, 0, size)
	serialized = append(serialized, h.SaltLen)
	serialized = append(serialized, h.Salt...)
	serialized = append(serialized, iterBytes[:]...)

	return serialized
}
