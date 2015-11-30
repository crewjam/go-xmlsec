package xmlenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
)

type method struct {
	Algorithm string `xml:",attr"`
}

type encryptedData struct {
	XMLName          string  `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
	ID               string  `xml:"Id,attr"`
	Type             string  `xml:",attr"`
	EncryptionMethod method  `xml:"EncryptionMethod"`
	KeyInfo          keyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       *cipherData
}

type keyInfo struct {
	XMLName      string        `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptedKey *encryptedKey `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	X509Data     x509Data      `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type encryptedKey struct {
	XMLName          string `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	EncryptionMethod *encryptionMethod
	KeyInfo          *keyInfo
	CipherData       *cipherData `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

type encryptionMethod struct {
	Algorithm    string `xml:",attr"`
	DigestMethod method `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
}

type x509Data struct {
	XMLName         string `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string
}

type cipherData struct {
	XMLName     string `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
	CipherValue string `xml:"CipherValue"`
}

// Decrypt searches the serialized XML document `doc` looking for
// EncryptedData elements and decrypting them. It returns the
// original document with the each EncryptedData element replaced
// by the derived plaintext.
//
// Key is a PEM-encoded RSA private key, or a binary TDES key or a
// binary AES key, depending on the encryption type in use.
func Decrypt(key []byte, doc []byte) ([]byte, error) {
	out := bytes.NewBuffer(nil)
	encoder := xml.NewEncoder(out)
	decoder := xml.NewDecoder(bytes.NewReader(doc))
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		if startElement, ok := t.(xml.StartElement); ok {
			if startElement.Name.Space == "http://www.w3.org/2001/04/xmlenc#" && startElement.Name.Local == "EncryptedData" {
				d := encryptedData{}
				if err := decoder.DecodeElement(&d, &startElement); err != nil {
					return nil, err
				}

				plaintext, err := decryptEncryptedData(key, &d)
				if err != nil {
					return nil, err
				}

				encoder.Flush()
				out.Write(plaintext)
				continue
			}
		}

		encoder.EncodeToken(t)
	}
	encoder.Flush()

	return out.Bytes(), nil
}

// decryptEncryptedData decrypts the EncryptedData element and returns the
// plaintext.
func decryptEncryptedData(key []byte, d *encryptedData) ([]byte, error) {
	if d.KeyInfo.EncryptedKey != nil {
		var err error
		key, err = decryptEncryptedKey(key, d.KeyInfo.EncryptedKey)
		if err != nil {
			return nil, err
		}
	}

	iv := []byte{}
	ciphertext, err := base64.StdEncoding.DecodeString(d.CipherData.CipherValue)
	if err != nil {
		return nil, err
	}

	var blockCipher cipher.Block
	switch d.EncryptionMethod.Algorithm {
	case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
		blockCipher, err = des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
		iv = ciphertext[:des.BlockSize]
		ciphertext = ciphertext[des.BlockSize:]

	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		"http://www.w3.org/2001/04/xmlenc#aes192-cbc",
		"http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		blockCipher, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		iv = ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]

	default:
		return nil, fmt.Errorf("unsupported encryption method: %s", d.EncryptionMethod.Algorithm)
	}

	mode := cipher.NewCBCDecrypter(blockCipher, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

// decryptEncryptedKey returns the plaintext version of the EncryptedKey which is
// encrypted using RSA-PKCS1v15 or RSA-OAEP-MGF1P and assuming the `key` is
// a PEM-encoded RSA private key.
func decryptEncryptedKey(key []byte, encryptedKey *encryptedKey) ([]byte, error) {
	// All the supported encryption schemes are based on RSA, so `key` must be an
	// RSA key. (c.f. http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html
	// in the "Key Transport" section)
	pemBlock, _ := pem.Decode(key)
	if pemBlock == nil {
		return nil, fmt.Errorf("Cannot parse key as PEM encoded RSA private key")
	}
	rsaPriv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// The only supported/required algorithm is SHA1
	// (c.f. http://www.w3.org/TR/2001/PR-xmldsig-core-20010820/ section "Algorithms")
	//
	// TODO(ross): if RSA-PKCS1v15 is used, do we need to specify the digest algorithm?
	var hashFunc hash.Hash
	switch encryptedKey.EncryptionMethod.DigestMethod.Algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		hashFunc = sha1.New()
	default:
		return nil, fmt.Errorf("unsupported digest method: %s",
			encryptedKey.EncryptionMethod.DigestMethod.Algorithm)
	}

	sessionKeyCiphertext, err := base64.StdEncoding.DecodeString(encryptedKey.CipherData.CipherValue)
	if err != nil {
		return nil, err
	}

	var sessionKeyPlaintext []byte
	switch encryptedKey.EncryptionMethod.Algorithm {
	case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
		sessionKeyPlaintext, err = rsa.DecryptPKCS1v15(rand.Reader, rsaPriv,
			sessionKeyCiphertext)
		if err != nil {
			return nil, err
		}
	case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
		sessionKeyPlaintext, err = rsa.DecryptOAEP(hashFunc, rand.Reader,
			rsaPriv, sessionKeyCiphertext, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported encryption method: %s",
			encryptedKey.EncryptionMethod.Algorithm)
	}

	return sessionKeyPlaintext, nil
}
