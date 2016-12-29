package xmlenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"hash"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ripemd160"
)

var ErrCannotFindEncryptedDataNode = errors.New("cannot find EncryptedData node")

var ErrPublicKeyMismatch = errors.New("certificate public key does not match provided private key")

type ErrUnsupportedAlgorithm struct {
	Algorithm string
}

func (e ErrUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported algorithm: %s", e.Algorithm)
}

func Decrypt(privateKey []byte, doc []byte) ([]byte, error) {
	decoder := xml.NewDecoder(bytes.NewReader(doc))
	for {
		startOffset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			return nil, ErrCannotFindEncryptedDataNode
		}
		if err != nil {
			return nil, err
		}

		if startElement, ok := token.(xml.StartElement); ok {
			if startElement.Name.Space == "http://www.w3.org/2001/04/xmlenc#" && startElement.Name.Local == "EncryptedData" {
				encryptedData := EncryptedData{}
				if err := decoder.DecodeElement(&encryptedData, &startElement); err != nil {
					return nil, err
				}
				plaintext, err := decrypt(privateKey, encryptedData)
				if err != nil {
					return nil, err
				}
				endOffset := decoder.InputOffset()

				rv := append(doc[:startOffset], append(plaintext, doc[endOffset:]...)...)
				return rv, nil
			}
		}
	}
}

func decrypt(privateKey []byte, encryptedData EncryptedData) ([]byte, error) {

	var key []byte
	if encryptedData.KeyInfo.EncryptedKey != nil {
		var err error
		key, err = decryptKey(privateKey, *encryptedData.KeyInfo.EncryptedKey)
		if err != nil {
			return nil, err
		}
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.CipherData.CipherValue.Data)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode ciphertext")
	}

	var block cipher.Block
	var iv []byte
	switch *encryptedData.EncryptionMethod.Algorithm {
	case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
		block, err = des.NewCipher(key)
		if err != nil {
			return nil, errors.Wrap(err, "AES init")
		}
		iv = ciphertext[:des.BlockSize]
		ciphertext = ciphertext[des.BlockSize:]
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
		fallthrough
	case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		fallthrough
	case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
		block, err = aes.NewCipher(key)
		if err != nil {
			return nil, errors.Wrap(err, "AES init")
		}
		iv = ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
	default:
		return nil, ErrUnsupportedAlgorithm{Algorithm: *encryptedData.EncryptionMethod.Algorithm}
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.Wrap(fmt.Errorf("ciphertext is not a multiple of the block size"),
			"invalid ciphertext")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// strip padding
	{
		paddingLen := int(ciphertext[len(ciphertext)-1])
		ciphertext = ciphertext[:len(ciphertext)-paddingLen]
	}

	return ciphertext, nil
}

func rsaPublicKeyEquals(a rsa.PublicKey, b rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func decryptKey(privateKey []byte, encryptedKey EncryptedKey) ([]byte, error) {
	cipherValue, err := base64.StdEncoding.DecodeString(string(encryptedKey.CipherData.CipherValue.Data))
	if err != nil {
		return nil, errors.Wrap(err, "decode key base64")
	}

	// TODO(ross): add support for http://www.w3.org/2001/04/xmlenc#rsa-1_5 once we can
	//   scrounge up some test vectors
	if *encryptedKey.EncryptionMethod.Algorithm != "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" {
		return nil, ErrUnsupportedAlgorithm{Algorithm: *encryptedKey.EncryptionMethod.Algorithm}
	}

	pemBlock, _ := pem.Decode(privateKey)
	if pemBlock == nil || pemBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.Wrap(fmt.Errorf("invalid private key"), "parse RSA private key")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "x509.ParsePKCS1PrivateKey")
	}

	{
		pemBlock, _ := pem.Decode([]byte(fmt.Sprintf(
			"-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			string(encryptedKey.KeyInfo.X509Data.X509Certificate.Data))))
		if pemBlock == nil {
			return nil, errors.New("cannot parse certificate")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "x509.ParseCertificate")
		}
		if !rsaPublicKeyEquals(*cert.PublicKey.(*rsa.PublicKey), rsaKey.PublicKey) {
			return nil, ErrPublicKeyMismatch
		}
	}

	label := []byte{}
	if encryptedKey.EncryptionMethod.OAEPparams != nil {
		label = encryptedKey.EncryptionMethod.OAEPparams.Data
	}

	var hashMethod hash.Hash
	switch encryptedKey.EncryptionMethod.DigestMethod.Algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		hashMethod = sha1.New()
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		hashMethod = sha256.New()
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		hashMethod = sha512.New()
	case "http://www.w3.org/2001/04/xmlenc#ripemd160":
		hashMethod = ripemd160.New()
	default:
		return nil, ErrUnsupportedAlgorithm{Algorithm: encryptedKey.EncryptionMethod.DigestMethod.Algorithm}
	}

	plaintext, err := rsa.DecryptOAEP(hashMethod, rand.Reader, rsaKey, cipherValue, label)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
