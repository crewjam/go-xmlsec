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
	key := []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOK9uFHs/nXrH9Lc
GorG6lB7Qs42iWK6mIE56wI7dIdsOuXf6r0ht+d+YTTis24xw+wjEHXrVN0Okh6w
sKftzxo8chIo60+UB5NlKdvxAC7tpGNmrf49us/m5bdNx8IY+0pPK0c6B786Uluj
Tvx1WFdDXh3UQPBclbWtFe5S3gLxAgMBAAECgYAPj9ngtZVZXoPWowinUbOvRmZ1
ZMTVI91nsSPyCUacLM92C4I+7NuEZeYiDRUnkP7TbCyrCzXN3jwlIxdczzORhlXB
Bgg9Sw2fkV61CnDEMgw+aEeD5A0GDA6eTwkrawiOMs8vupjsi2/stPsa+bmpI6Rn
fdEKBdyDP6iQQhAxiQJBAPNtM7IMvRzlZBXoDaTTpP9rN2FR0ZcX0LT5aRZJ81qi
+ZOBFeHUb6MyWvzZKfPinj9JO3s/9e3JbMXemRWBmvcCQQDuc+NfAeW200QyjoC3
Ed3jueLMrY1Q3zTcSUhRPw/0pIKgRGZJerro8N6QY2JziV2mxK855gKTwwBigMHL
2S9XAkEAwuBfjGDqXOG/uFHn6laNNvWshjqsIdus99Tbrj5RlfP2/YFP9VTOcsXz
VYy9K0P3EA8ekVLpHQ4uCFJmF3OEjQJBAMvwO69/HOufhv1CWZ25XzAsRGhPqsRX
Eouw9XPfXpMavEm8FkuT9xXRJFkTVxl/i6RdJYx8Rwn/Rm34t0bUKqMCQQCrAtKC
Un0PLcemAzPi8ADJlbMDG/IDXNbSej0Y4tw9Cdho1Q38XLZJi0RNdNvQJD1fWu3x
9+QU/vJr7lMLzdoy
-----END PRIVATE KEY-----`)

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
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
	<KeyName/>
    </KeyInfo>
  </Signature>
</Envelope>`)

	expectedSignedString := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!--\nXML Security Library example: Simple signature template file for sign1 example.\n-->\n<Envelope xmlns=\"urn:envelope\">\n  <Data>\n\tHello, World!\n  </Data>\n  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n    <SignedInfo>\n      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n      <Reference URI=\"\">\n        <Transforms>\n          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n        </Transforms>\n        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n        <DigestValue>9H/rQr2Axe9hYTV2n/tCp+3UIQQ=</DigestValue>\n      </Reference>\n    </SignedInfo>\n    <SignatureValue>2rM7C8ZzCjxEY4kueUaSevvEZjORQ7hBTWGxUJXStyQScLtX1drFx9dRmUdk/uRr\n0O37B3gsbKzlpQNfdVYPIfWgswjEVLBH7Ncl1dJ6dTofkQrogIF5CQE+PIAG3MPh\nnWsIcBahRQ+rNaRB/TDscuEV3+V3Je4K7E0OEKEuP1I=</SignatureValue>\n    <KeyInfo>\n\t<KeyName/>\n    </KeyInfo>\n  </Signature>\n</Envelope>\n"

	actualSignedString, err := Sign(key, docStr)
	if err != nil {
		t.Errorf("sign: %s", err)
		return
	}

	if string(actualSignedString) != expectedSignedString {
		t.Errorf("signed: expected %q, got `%q`", expectedSignedString, string(actualSignedString))
		return
	}

	// Try again but this time construct the message from a struct having a Signature member
	doc := Envelope{Data: "Hello, World!"}
	doc.Signature = DefaultSignature()
	docStr, err = xml.Marshal(doc)
	if err != nil {
		t.Errorf("marshal: %s", err)
	}
	actualSignedString, err = Sign(key, docStr)
	if err != nil {
		t.Errorf("sign: %s", err)
		return
	}
	expectedSignedString = "<?xml version=\"1.0\"?>\n<Envelope><Data>Hello, World!</Data><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>09XOMG8zghPZhJYD8kM2uJsr1cc=</DigestValue></Reference></SignedInfo><SignatureValue>fqL9oHtcNiFFaTy7AJoQ1hs5Wz0fTqjq0xANLz/mSLBLiFv2OEicuwyo4InyBnyf\njSjmCBaz8QPX9rTW49a2wv1RMkls0WnqP65DUY2ofM4wKHWcjnGt1p1rlYdDv5Sl\njk5Wqwy2EmoqGSXQovRZmn4jidThmoqgum4LNKC2lFI=</SignatureValue><KeyInfo><KeyName/></KeyInfo></Signature></Envelope>\n"
	if string(actualSignedString) != expectedSignedString {
		t.Errorf("signed: expected %q, got `%q`", expectedSignedString, string(actualSignedString))
		return
	}

	if err := Verify(key, []byte(expectedSignedString)); err != nil {
		t.Errorf("verify: %s", err)
		return
	}

	brokenDoc := strings.Replace(expectedSignedString, "Hello", "Goodbye", 1)
	err = Verify(key, []byte(brokenDoc))
	if err != ErrVerificationFailed {
		t.Errorf("verify: expected verification failed, got %s", err)
		return
	}
}
