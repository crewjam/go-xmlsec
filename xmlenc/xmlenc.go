// Package xmlenc implements xml encrytion natively
// (https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html)
package xmlenc

import "encoding/xml"

type EncryptedData struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
	ID               *string           `xml:"Id,attr"`
	Type             *string           `xml:",attr"`
	EncryptionMethod *EncryptionMethod `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	KeyInfo          *KeyInfo          `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       *CipherData       `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

type EncryptionMethod struct {
	XMLName      xml.Name      `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	Algorithm    *string       `xml:",attr"`
	OAEPparams   *OAEPparams   `xml:"http://www.w3.org/2001/04/xmlenc# OAEPparams"`
	DigestMethod *DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
}

type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:",attr"`
}

type OAEPparams struct {
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# OAEPparams"`
	Data    []byte   `xml:",chardata"`
}

type KeyInfo struct {
	XMLName      xml.Name      `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptedKey *EncryptedKey `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	X509Data     *X509Data     `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type EncryptedKey struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	EncryptionMethod *EncryptionMethod `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	KeyInfo          *KeyInfo          `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       *CipherData       `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate *X509Certificate
}

type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    []byte   `xml:",chardata"`
}

type CipherData struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
	CipherValue *CipherValue
}

type CipherValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# CipherValue"`
	Data    string   `xml:",chardata"`
}
