package xmldsig

import "encoding/xml"

// Method is part of Signature.
type Method struct {
	Algorithm string `xml:",attr"`
}

// Signature is a model for the Signature object specified by XMLDSIG. This is
// convenience object when constructing XML that you'd like to sign. For example:
//
//    type Foo struct {
//       Stuff string
//       Signature Signature
//    }
//
//    f := Foo{Suff: "hello"}
//    f.Signature = DefaultSignature()
//    buf, _ := xml.Marshal(f)
//    buf, _ = Sign(key, buf)
//
type Signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	CanonicalizationMethod Method   `xml:"SignedInfo>CanonicalizationMethod"`
	SignatureMethod        Method   `xml:"SignedInfo>SignatureMethod"`
	ReferenceTransforms    []Method `xml:"SignedInfo>Reference>Transforms>Transform"`
	DigestMethod           Method   `xml:"SignedInfo>Reference>DigestMethod"`
	DigestValue            string   `xml:"SignedInfo>Reference>DigestValue"`
	SignatureValue         string   `xml:"SignatureValue"`
	KeyName                string   `xml:"KeyInfo>KeyName"`
}

// DefaultSignature populates a default Signature that uses c14n and SHA1.
func DefaultSignature() Signature {
	return Signature{
		CanonicalizationMethod: Method{
			Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		},
		SignatureMethod: Method{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		},
		ReferenceTransforms: []Method{
			Method{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
		},
		DigestMethod: Method{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
		},
	}
}
