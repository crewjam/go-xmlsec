package xmlenc

import (
	"encoding/xml"
)

type EncryptedData struct {
	XMLName          xml.Name `xml:"http://www.w3.org/2001/04/xmlenc#"`
	EncryptionMethod EncryptionMethod
	KeyInfo          KeyInfo
	CipherDataValue  string `xml:"CipherData>CipherValue"`
}

type EncryptionMethod struct {
	Algorithm string `xml:",attr"`
}

type KeyInfo struct {
	XMLName  xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	KeyName  string    `xml:"KeyName"`
	X509Data *X509Data `xml:"X509Data,omitempty"`
}

type X509Data struct {
	X509Certificate string `xml:"X509Certificate,omitempty"`
}
