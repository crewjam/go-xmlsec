package xmlsec

import (
	"encoding/xml"
	"strings"

	. "gopkg.in/check.v1"
)

type Envelope struct {
	Data      string
	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

type XMLDSigTest struct {
	Key     []byte
	DERKey  []byte
	Cert    []byte
	DERCert []byte
	DocStr  []byte
}

var _ = Suite(&XMLDSigTest{})

func (testSuite *XMLDSigTest) SetUpTest(c *C) {
	testSuite.Key = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBANPQbQ92nlbeg1Q5JNHSO1Yey46nZ7GJltLWw1ccSvp7pnvmfUm+
M521CpFpfr4EAE3UVBMoU9j/hqq3dFAc2H0CAwEAAQJBALFVCjmsAZyQ5jqZLO5N
qEfNuHZSSUol+xPBogFIOq3BWa269eNNcAK5or5g0XWWon7EPdyGT4qyDVH9KzXK
RLECIQDzm/Nj0epUGN51/rKJgRXWkXW/nfSCMO9fvQR6Ujoq3wIhAN6WeHK9vgWg
wBWqMdq5sR211+LlDH7rOUQ6rBpbsoQjAiEA7jzpfglgPPZFOOfo+oh/LuP6X3a+
FER/FQXpRyb7M8kCIETUrwZ8WkiPPxbz/Fqw1W5kjw/g2I5e2uSYaCP2eyuVAiEA
mOI6RhRyMqgxQyy0plJVjG1s4fdu92AWYy9AwYeyd/8=
-----END RSA PRIVATE KEY-----
`)
	testSuite.DERKey = []byte("\x30\x82\x01\x3c\x02\x01\x00\x02\x41\x00\xd3\xd0\x6d\x0f\x76\x9e\x56\xde\x83\x54\x39\x24\xd1\xd2\x3b\x56\x1e\xcb\x8e\xa7\x67\xb1\x89\x96\xd2\xd6\xc3\x57\x1c\x4a\xfa\x7b\xa6\x7b\xe6\x7d\x49\xbe\x33\x9d\xb5\x0a\x91\x69\x7e\xbe\x04\x00\x4d\xd4\x54\x13\x28\x53\xd8\xff\x86\xaa\xb7\x74\x50\x1c\xd8\x7d\x02\x03\x01\x00\x01\x02\x41\x00\xb1\x55\x0a\x39\xac\x01\x9c\x90\xe6\x3a\x99\x2c\xee\x4d\xa8\x47\xcd\xb8\x76\x52\x49\x4a\x25\xfb\x13\xc1\xa2\x01\x48\x3a\xad\xc1\x59\xad\xba\xf5\xe3\x4d\x70\x02\xb9\xa2\xbe\x60\xd1\x75\x96\xa2\x7e\xc4\x3d\xdc\x86\x4f\x8a\xb2\x0d\x51\xfd\x2b\x35\xca\x44\xb1\x02\x21\x00\xf3\x9b\xf3\x63\xd1\xea\x54\x18\xde\x75\xfe\xb2\x89\x81\x15\xd6\x91\x75\xbf\x9d\xf4\x82\x30\xef\x5f\xbd\x04\x7a\x52\x3a\x2a\xdf\x02\x21\x00\xde\x96\x78\x72\xbd\xbe\x05\xa0\xc0\x15\xaa\x31\xda\xb9\xb1\x1d\xb5\xd7\xe2\xe5\x0c\x7e\xeb\x39\x44\x3a\xac\x1a\x5b\xb2\x84\x23\x02\x21\x00\xee\x3c\xe9\x7e\x09\x60\x3c\xf6\x45\x38\xe7\xe8\xfa\x88\x7f\x2e\xe3\xfa\x5f\x76\xbe\x14\x44\x7f\x15\x05\xe9\x47\x26\xfb\x33\xc9\x02\x20\x44\xd4\xaf\x06\x7c\x5a\x48\x8f\x3f\x16\xf3\xfc\x5a\xb0\xd5\x6e\x64\x8f\x0f\xe0\xd8\x8e\x5e\xda\xe4\x98\x68\x23\xf6\x7b\x2b\x95\x02\x21\x00\x98\xe2\x3a\x46\x14\x72\x32\xa8\x31\x43\x2c\xb4\xa6\x52\x55\x8c\x6d\x6c\xe1\xf7\x6e\xf7\x60\x16\x63\x2f\x40\xc1\x87\xb2\x77\xff")
	testSuite.Cert = []byte(`-----BEGIN CERTIFICATE-----
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
	testSuite.DERCert = []byte("\x30\x82\x03\xa7\x30\x82\x03\x51\xa0\x03\x02\x01\x02\x02\x09\x00\xaf\xa2\x8b\xb9\x33\xad\xda\xaf\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x30\x81\x9c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x13\x30\x11\x06\x03\x55\x04\x08\x13\x0a\x43\x61\x6c\x69\x66\x6f\x72\x6e\x69\x61\x31\x3d\x30\x3b\x06\x03\x55\x04\x0a\x13\x34\x58\x4d\x4c\x20\x53\x65\x63\x75\x72\x69\x74\x79\x20\x4c\x69\x62\x72\x61\x72\x79\x20\x28\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x2f\x78\x6d\x6c\x73\x65\x63\x29\x31\x16\x30\x14\x06\x03\x55\x04\x03\x13\x0d\x41\x6c\x65\x6b\x73\x65\x79\x20\x53\x61\x6e\x69\x6e\x31\x21\x30\x1f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x12\x78\x6d\x6c\x73\x65\x63\x40\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x30\x20\x17\x0d\x31\x34\x30\x35\x32\x33\x31\x37\x35\x35\x33\x34\x5a\x18\x0f\x32\x31\x31\x34\x30\x34\x32\x39\x31\x37\x35\x35\x33\x34\x5a\x30\x81\xc7\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x13\x30\x11\x06\x03\x55\x04\x08\x13\x0a\x43\x61\x6c\x69\x66\x6f\x72\x6e\x69\x61\x31\x3d\x30\x3b\x06\x03\x55\x04\x0a\x13\x34\x58\x4d\x4c\x20\x53\x65\x63\x75\x72\x69\x74\x79\x20\x4c\x69\x62\x72\x61\x72\x79\x20\x28\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x2f\x78\x6d\x6c\x73\x65\x63\x29\x31\x29\x30\x27\x06\x03\x55\x04\x0b\x13\x20\x54\x65\x73\x74\x20\x54\x68\x69\x72\x64\x20\x4c\x65\x76\x65\x6c\x20\x52\x53\x41\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x31\x16\x30\x14\x06\x03\x55\x04\x03\x13\x0d\x41\x6c\x65\x6b\x73\x65\x79\x20\x53\x61\x6e\x69\x6e\x31\x21\x30\x1f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x12\x78\x6d\x6c\x73\x65\x63\x40\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x30\x5c\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x4b\x00\x30\x48\x02\x41\x00\xd3\xd0\x6d\x0f\x76\x9e\x56\xde\x83\x54\x39\x24\xd1\xd2\x3b\x56\x1e\xcb\x8e\xa7\x67\xb1\x89\x96\xd2\xd6\xc3\x57\x1c\x4a\xfa\x7b\xa6\x7b\xe6\x7d\x49\xbe\x33\x9d\xb5\x0a\x91\x69\x7e\xbe\x04\x00\x4d\xd4\x54\x13\x28\x53\xd8\xff\x86\xaa\xb7\x74\x50\x1c\xd8\x7d\x02\x03\x01\x00\x01\xa3\x82\x01\x45\x30\x82\x01\x41\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff\x30\x2c\x06\x09\x60\x86\x48\x01\x86\xf8\x42\x01\x0d\x04\x1f\x16\x1d\x4f\x70\x65\x6e\x53\x53\x4c\x20\x47\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\xd7\xf4\xc6\x46\x77\xce\x37\x04\x23\xad\x29\x54\xfb\xb0\x0e\xa4\xcc\x43\x28\x19\x30\x81\xe3\x06\x03\x55\x1d\x23\x04\x81\xdb\x30\x81\xd8\x80\x14\xfe\xe4\xec\x53\x24\xf0\x95\x95\xc7\x10\xb5\xe1\x44\xb5\x5d\x39\x65\x5a\xe3\x7e\xa1\x81\xb4\xa4\x81\xb1\x30\x81\xae\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x13\x30\x11\x06\x03\x55\x04\x08\x13\x0a\x43\x61\x6c\x69\x66\x6f\x72\x6e\x69\x61\x31\x3d\x30\x3b\x06\x03\x55\x04\x0a\x13\x34\x58\x4d\x4c\x20\x53\x65\x63\x75\x72\x69\x74\x79\x20\x4c\x69\x62\x72\x61\x72\x79\x20\x28\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x2f\x78\x6d\x6c\x73\x65\x63\x29\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x13\x07\x52\x6f\x6f\x74\x20\x43\x41\x31\x16\x30\x14\x06\x03\x55\x04\x03\x13\x0d\x41\x6c\x65\x6b\x73\x65\x79\x20\x53\x61\x6e\x69\x6e\x31\x21\x30\x1f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x12\x78\x6d\x6c\x73\x65\x63\x40\x61\x6c\x65\x6b\x73\x65\x79\x2e\x63\x6f\x6d\x82\x09\x00\xaf\xa2\x8b\xb9\x33\xad\xda\xad\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x03\x41\x00\x0e\x5c\x18\xf4\xc8\x80\xa9\xd5\x19\x87\x5e\xa9\xd4\x96\xca\x69\xaf\x22\xc2\x5b\x7a\x4a\x04\x3d\x5d\x91\xbe\x07\x59\xaa\xce\xed\x18\xc0\xd7\x22\x49\x7c\x18\xd7\xb2\xca\xc4\x46\x7d\x39\x92\x90\x5c\xad\x17\xf3\xa2\xee\x2b\xdc\x30\xa0\x40\x53\xe1\x8f\x18\x1a")
	testSuite.DocStr = []byte(`<?xml version="1.0" encoding="UTF-8"?>
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

}

func (testSuite *XMLDSigTest) TestSignAndVerify(c *C) {
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
	actualSignedString, err := Sign(testSuite.Key, testSuite.DocStr, SignatureOptions{})
	c.Assert(err, IsNil)
	c.Assert(string(actualSignedString), Equals, expectedSignedString)

	err = Verify(testSuite.Cert, actualSignedString, SignatureOptions{})
	c.Assert(err, IsNil)
}

func (testSuite *XMLDSigTest) TestSignAndVerifyDER(c *C) {
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
	actualSignedString, err := Sign(testSuite.DERKey, testSuite.DocStr, SignatureOptions{
	  KeyFormat: DER,
	})
	c.Assert(err, IsNil)
	c.Assert(string(actualSignedString), Equals, expectedSignedString)

	err = Verify(testSuite.DERCert, actualSignedString, SignatureOptions{
	  KeyFormat: DER,
	})
	c.Assert(err, IsNil)
}

func (testSuite *XMLDSigTest) TestConstructFromSignature(c *C) {
	// Try again but this time construct the message from a struct having a Signature member
	doc := Envelope{Data: "Hello, World!"}
	doc.Signature = DefaultSignature(testSuite.Cert)
	docStr, err := xml.MarshalIndent(doc, "", "  ")
	c.Assert(err, IsNil)
	actualSignedString, err := Sign(testSuite.Key, docStr, SignatureOptions{})
	c.Assert(err, IsNil)

	expectedSignedString := `<?xml version="1.0"?>
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
	c.Assert(string(actualSignedString), Equals, expectedSignedString)

	err = Verify(testSuite.Cert, actualSignedString, SignatureOptions{})
	c.Assert(err, IsNil)
}

func (testSuite *XMLDSigTest) TestVerifyFailsWhenMessageModified(c *C) {
	// break the document and notice that the signature is invalid
	signedStr, err := Sign(testSuite.Key, testSuite.DocStr, SignatureOptions{})
	c.Assert(err, IsNil)

	err = Verify(testSuite.Cert, signedStr, SignatureOptions{})
	c.Assert(err, IsNil)

	signedStr = []byte(strings.Replace(string(signedStr), "Hello", "Goodbye", 1))
	err = Verify(testSuite.Cert, []byte(signedStr), SignatureOptions{})
	c.Assert(err, Equals, ErrVerificationFailed)
}

func (testSuite *XMLDSigTest) TestInvalidXML(c *C) {
	_, err := Sign(testSuite.Key, []byte("<invalid xml"), SignatureOptions{})
	c.Assert(err, ErrorMatches, ".*Couldn't find end of Start Tag.*")

	_, err = Sign(testSuite.Key, []byte("<invalid></invalid>"), SignatureOptions{})
	c.Assert(err, ErrorMatches, "cannot find start node")

	_, err = Sign([]byte("XXX"), testSuite.DocStr, SignatureOptions{})
	c.Assert(err, ErrorMatches, "failed to load pem key")

	err = Verify(testSuite.Cert, []byte("<invalid xml"), SignatureOptions{})
	c.Assert(err, ErrorMatches, ".*Couldn't find end of Start Tag.*")

	err = Verify(testSuite.Cert, []byte("<invalid></invalid>"), SignatureOptions{})
	c.Assert(err, ErrorMatches, "cannot find start node")

	err = Verify([]byte("XXX"), testSuite.DocStr, SignatureOptions{})
	c.Assert(err, ErrorMatches, ".*xmlSecOpenSSLAppKeyLoadMemory.*")

	err = Verify(testSuite.Key, testSuite.DocStr, SignatureOptions{})
	c.Assert(err, ErrorMatches, ".*xmlSecOpenSSLAppKeyLoadMemory.*")

	err = Verify(testSuite.Cert, testSuite.DocStr, SignatureOptions{})
	c.Assert(err, ErrorMatches, "signature verification failed")
}

func (testSuite *XMLDSigTest) TestVerifySAMLSignature(c *C) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEV
MBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYD
VQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4
MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQI
EwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRl
c3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7C
yVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe
3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aT
NPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614
kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWH
gWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0G
A1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ86
9nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBl
bm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNo
aWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRL
I4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo
93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4
/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAj
Geka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr
8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA==
-----END CERTIFICATE-----`)
	doc := []byte("<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"_f6f518e2c236c9c558f7a8bc6387b103\" IssueInstant=\"2015-11-29T21:29:09.991Z\" Version=\"2.0\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#_f6f518e2c236c9c558f7a8bc6387b103\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"xs\"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>VwEKsGObmOM6y22Nstadwz1fq6dnQ2aDmERPMuEteds=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gcROTzJ7HgTu/LQprki8v9J5y4et2np48hYspgmygZRvRawzxfQDgB0MBvDIBG78J5XSd401g7E999JUEh4JtSMAig1THbeWhyITGHU1Vpl2xAR5Ma0vCMLjVIleeuFHhStFBNqKirNfulfhEa7Q5THVGKrVsNuIaP/yc10Gf8AyHfCIOf/ZQGiU3Srp/pKZLXPkSKTEZIq5tAOl+pA0maFBvb4+EkMPB6E66HiXknHL9KdNh8bPcq+EkqjhtHWOy341F8W9iy6MJYGuO9ksxdiY6FK5SqmPHlgoJqXx7Et2vYME6opIgFYB6m1KW6kWgVcF0VyIzJbkXq3yTi0b5g==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMM\nUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcG\nA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcx\nCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gx\nETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcp\nu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsT\npSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txI\nfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB\n5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HE\nMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh8\n3KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTET\nMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0\nc2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5M\nFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpk\nOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4\n/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8Jjwx\npUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeW\nj8Bbnl+ev0peYzxFyF5sQA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"https://idp.testshib.org/idp/shibboleth\" SPNameQualifier=\"https://15661444.ngrok.io/saml2/metadata\">_5c425656721b41a6cfa4a9c96225e082</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData Address=\"75.144.86.91\" InResponseTo=\"id-3d21faf29a101222d740735fa512f161\" NotOnOrAfter=\"2015-11-29T21:34:09.991Z\" Recipient=\"https://15661444.ngrok.io/saml2/acs\"></saml2:SubjectConfirmationData></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2015-11-29T21:29:09.991Z\" NotOnOrAfter=\"2015-11-29T21:34:09.991Z\"><saml2:AudienceRestriction><saml2:Audience>https://15661444.ngrok.io/saml2/metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant=\"2015-11-29T21:29:09.715Z\" SessionIndex=\"_57adf921604642bd4e1dce7f308734f0\"><saml2:SubjectLocality Address=\"75.144.86.91\"></saml2:SubjectLocality><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">myself</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"eduPersonAffiliation\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Member</saml2:AttributeValue><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Staff</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"eduPersonPrincipalName\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.6\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">myself@testshib.org</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"sn\" Name=\"urn:oid:2.5.4.4\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">And I</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"eduPersonScopedAffiliation\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.9\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Member@testshib.org</saml2:AttributeValue><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Staff@testshib.org</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"givenName\" Name=\"urn:oid:2.5.4.42\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Me Myself</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"eduPersonEntitlement\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.7\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">urn:mace:dir:entitlement:common-lib-terms</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"cn\" Name=\"urn:oid:2.5.4.3\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Me Myself And I</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"eduPersonTargetedID\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.10\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue><saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" NameQualifier=\"https://idp.testshib.org/idp/shibboleth\" SPNameQualifier=\"https://15661444.ngrok.io/saml2/metadata\">8F+M9ovyaYNwCId0pVkVsnZYRDo=</saml2:NameID></saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"telephoneNumber\" Name=\"urn:oid:2.5.4.20\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">555-5555</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>")

	err := Verify(cert, doc, SignatureOptions{
		XMLID: []XMLIDOption{{
			ElementName:      "Assertion",
			ElementNamespace: "urn:oasis:names:tc:SAML:2.0:assertion",
			AttributeName:    "ID",
		}},
	})
	c.Assert(err, IsNil)
}
