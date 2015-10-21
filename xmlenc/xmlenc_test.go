package xmlenc

import (
	"log"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EncryptTest struct{}

var _ = Suite(&EncryptTest{})

func (s *EncryptTest) TestEncrypt(c *C) {
	key := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9
IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+
PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQAB
AoGAD4/Z4LWVWV6D1qMIp1Gzr0ZmdWTE1SPdZ7Ej8glGnCzPdguCPuzbhGXmIg0V
J5D+02wsqws1zd48JSMXXM8zkYZVwQYIPUsNn5FetQpwxDIMPmhHg+QNBgwOnk8J
K2sIjjLPL7qY7Itv7LT7Gvm5qSOkZ33RCgXcgz+okEIQMYkCQQDzbTOyDL0c5WQV
6A2k06T/azdhUdGXF9C0+WkWSfNaovmTgRXh1G+jMlr82Snz4p4/STt7P/XtyWzF
3pkVgZr3AkEA7nPjXwHlttNEMo6AtxHd47nizK2NUN803ElIUT8P9KSCoERmSXq6
6PDekGNic4ldpsSvOeYCk8MAYoDBy9kvVwJBAMLgX4xg6lzhv7hR5+pWjTb1rIY6
rCHbrPfU264+UZXz9v2BT/VUznLF81WMvStD9xAPHpFS6R0OLghSZhdzhI0CQQDL
8Duvfxzrn4b9QlmduV8wLERoT6rEVxKLsPVz316TGrxJvBZLk/cV0SRZE1cZf4uk
XSWMfEcJ/0Zt+LdG1CqjAkEAqwLSglJ9Dy3HpgMz4vAAyZWzAxvyA1zW0no9GOLc
PQnYaNUN/Fy2SYtETXTb0CQ9X1rt8ffkFP7ya+5TC83aMg==
-----END RSA PRIVATE KEY-----`)
	log.Printf("%s", string(key))
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMC
Tk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYD
VQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG
9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4
MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xi
ZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2Zl
aWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5v
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LO
NoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHIS
KOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d
1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8
BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7n
bK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2Qar
Q4/67OZfHd7R+POBXhophSMv1ZOo
-----END CERTIFICATE-----`)
	log.Printf("%s", string(cert))

	docStr := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: Original XML doc file before encryption (encrypt3 example).
-->
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
	  <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
	  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
	    <!--<ds:KeyName>aes</ds:KeyName>-->
	    <xenc:EncryptedKey Id="aes" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
	      <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
	        Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
	        <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	      </xenc:EncryptionMethod>
	      <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
	        <xenc:CipherValue></xenc:CipherValue>
	      </xenc:CipherData>
	    </xenc:EncryptedKey>
	  </ds:KeyInfo>
      <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
        <xenc:CipherValue></xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
</Envelope>`)

	ctx := Context{}
	err := ctx.AddCert(cert)
	c.Assert(err, IsNil)

	err = ctx.AddKey(key)
	c.Assert(err, IsNil)

	actualEncryptedString, err := ctx.Encrypt(docStr, []byte("Hello, World!"))
	c.Assert(err, IsNil)
	log.Printf("%s", actualEncryptedString)

	//	expectedEncryptedString := "XXX"
	//c.Assert(string(actualEncryptedString), Equals, expectedEncryptedString)

	plaintext, err := ctx.Decrypt(actualEncryptedString)
	c.Assert(err, IsNil)
	log.Printf("plaintext=%s", plaintext)
	//c.Assert(string(plaintext), Equals, "Hello, World!")
}
