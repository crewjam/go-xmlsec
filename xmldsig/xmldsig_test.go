package xmldsig

import (
	"encoding/xml"
	"strings"
	"testing"
)

type Envelope struct {
	Data      string
	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

func TestSign(t *testing.T) {
	key := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBANPQbQ92nlbeg1Q5JNHSO1Yey46nZ7GJltLWw1ccSvp7pnvmfUm+
M521CpFpfr4EAE3UVBMoU9j/hqq3dFAc2H0CAwEAAQJBALFVCjmsAZyQ5jqZLO5N
qEfNuHZSSUol+xPBogFIOq3BWa269eNNcAK5or5g0XWWon7EPdyGT4qyDVH9KzXK
RLECIQDzm/Nj0epUGN51/rKJgRXWkXW/nfSCMO9fvQR6Ujoq3wIhAN6WeHK9vgWg
wBWqMdq5sR211+LlDH7rOUQ6rBpbsoQjAiEA7jzpfglgPPZFOOfo+oh/LuP6X3a+
FER/FQXpRyb7M8kCIETUrwZ8WkiPPxbz/Fqw1W5kjw/g2I5e2uSYaCP2eyuVAiEA
mOI6RhRyMqgxQyy0plJVjG1s4fdu92AWYy9AwYeyd/8=
-----END RSA PRIVATE KEY-----
`)

	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy
aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG
A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz
ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1
cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn
BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD
Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j
b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn
sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB
o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM
QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M
IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj
KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G
CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI
hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ
fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga
-----END CERTIFICATE-----
`)

	docStr := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: Simple signature template file for sign1 example.
-->
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>9H/rQr2Axe9hYTV2n/tCp+3UIQQ=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue></SignatureValue>
    <KeyInfo>
		<X509Data>
			<X509Certificate>MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy
aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG
A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz
ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1
cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn
BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD
Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j
b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn
sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB
o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM
QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M
IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj
KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G
CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI
hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ
fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga</X509Certificate>
		</X509Data>
	</KeyInfo>
  </Signature>
</Envelope>
`)
	expectedSignedString := `<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: Simple signature template file for sign1 example.
-->
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>9H/rQr2Axe9hYTV2n/tCp+3UIQQ=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>fDKK0so/zFcmmq2X+BaVFmS0t8KB7tyW53YN6n221OArzGCs4OyWsAjj/BUR+wNF
elOnt4fo2gPK1a3IVEhMGg==</SignatureValue>
    <KeyInfo>
		<X509Data>
			<X509Certificate>MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy
aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG
A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz
ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1
cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn
BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD
Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j
b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn
sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB
o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM
QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M
IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj
KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G
CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI
hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ
fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga</X509Certificate>
		</X509Data>
	</KeyInfo>
  </Signature>
</Envelope>
`
	actualSignedString, err := Sign(key, docStr)
	if err != nil {
		t.Errorf("sign: %s", err)
		return
	}

	if string(actualSignedString) != expectedSignedString {
		t.Errorf("sign: expected:\n%q\ngot:\n%q", expectedSignedString, string(actualSignedString))
		return
	}

	// Try again but this time construct the message from a struct having a Signature member
	doc := Envelope{Data: "Hello, World!"}
	doc.Signature = DefaultSignature(cert)
	docStr, err = xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Errorf("marshal: %s", err)
	}
	actualSignedString, err = Sign(key, docStr)
	if err != nil {
		t.Errorf("sign: %s", err)
		return
	}

	expectedSignedString = `<?xml version="1.0"?>
<Envelope>
  <Data>Hello, World!</Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference>
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>sEenIPkW9ssFSB9t4UU6VUrytqc=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>chSWfpQBIQraySsUHzs5N51+ruelu2HMHh5Mnd3EjcLqFBVD0f23kmXUp7zVhCVD
vCfqu9yXDYKVOBI57F0Efg==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAnBgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQDEw1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7LjqdnsYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQABo4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTMQygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGuMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZIhvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJfBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</Envelope>
`
	if string(actualSignedString) != expectedSignedString {
		t.Errorf("signed: expected %q, got `%q`", expectedSignedString, string(actualSignedString))
		return
	}

	if err := Verify(cert, actualSignedString); err != nil {
		t.Errorf("verify: %s", err)
		return
	}

	brokenDoc := strings.Replace(expectedSignedString, "Hello", "Goodbye", 1)
	err = Verify(cert, []byte(brokenDoc))
	if err != ErrVerificationFailed {
		t.Errorf("verify: expected verification failed, got %s", err)
		return
	}
}
