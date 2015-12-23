package xmlsec

// #cgo pkg-config: xmlsec1
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmlenc.h>
// #include <xmlsec/templates.h>
// #include <xmlsec/crypto.h>
//
// // Note: the xmlSecKeyData*Id itentifiers are macros, so we need to wrap them
// // here to make them callable from go.
// static inline xmlSecKeyDataId MY_xmlSecKeyDataAesId(void) { return xmlSecKeyDataAesId; }
// static inline xmlSecKeyDataId MY_xmlSecKeyDataDesId(void) { return xmlSecKeyDataDesId; }
// static inline xmlSecTransformId MY_xmlSecTransformAes128CbcId(void) { return xmlSecTransformAes128CbcId; }
// static inline xmlSecTransformId MY_xmlSecTransformAes192CbcId(void) { return xmlSecTransformAes192CbcId; }
// static inline xmlSecTransformId MY_xmlSecTransformAes256CbcId(void) { return xmlSecTransformAes256CbcId; }
// static inline xmlSecTransformId MY_xmlSecTransformDes3CbcId(void) { return xmlSecTransformDes3CbcId; }
// static inline xmlSecTransformId MY_xmlSecTransformRsaOaepId(void) { return xmlSecTransformRsaOaepId; }
// static inline xmlSecTransformId MY_xmlSecTransformRsaPkcs1Id(void) { return xmlSecTransformRsaPkcs1Id; }
//
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	DefaultAlgorithm = iota
	Aes128Cbc
	Aes192Cbc
	Aes256Cbc
	Des3Cbc
	DsaSha1
	Sha1
	Sha256
	Sha384
	Sha512
	RsaOaep
	RsaPkcs1
)

type Options struct {
	SessionCipher   int
	Cipher          int
	DigestAlgorithm int
}

// XmlEncrypt encrypts the XML document to publicKey.
func XmlEncrypt(publicKey, doc []byte, opts Options) ([]byte, error) {
	startProcessingXML()
	defer stopProcessingXML()

	keysMngr := C.xmlSecKeysMngrCreate()
	if keysMngr == nil {
		return nil, fmt.Errorf("xmlSecKeysMngrCreate failed")
	}
	defer C.xmlSecKeysMngrDestroy(keysMngr)

	if rv := C.xmlSecCryptoAppDefaultKeysMngrInit(keysMngr); rv < 0 {
		return nil, fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrInit failed")
	}

	key := C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&publicKey[0])),
		C.xmlSecSize(len(publicKey)),
		C.xmlSecKeyDataFormatCertPem,
		nil, nil, nil)
	if key == nil {
		return nil, fmt.Errorf("xmlSecCryptoAppKeyLoadMemory failed")
	}

	if rv := C.xmlSecCryptoAppKeyCertLoadMemory(key,
		(*C.xmlSecByte)(unsafe.Pointer(&publicKey[0])),
		C.xmlSecSize(len(publicKey)),
		C.xmlSecKeyDataFormatCertPem); rv < 0 {
		C.xmlSecKeyDestroy(key)
		return nil, fmt.Errorf("xmlSecCryptoAppKeyCertLoad failed")
	}

	if rv := C.xmlSecCryptoAppDefaultKeysMngrAdoptKey(keysMngr, key); rv < 0 {
		return nil, fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrAdoptKey failed")
	}

	parsedDoc, err := newDoc(doc)
	if err != nil {
		return nil, err
	}
	defer closeDoc(parsedDoc)

	var sessionCipherTransform C.xmlSecTransformId
	switch opts.SessionCipher {
	case DefaultAlgorithm:
		sessionCipherTransform = C.MY_xmlSecTransformAes256CbcId()
	case Aes256Cbc:
		sessionCipherTransform = C.MY_xmlSecTransformAes256CbcId()
	case Aes192Cbc:
		sessionCipherTransform = C.MY_xmlSecTransformAes192CbcId()
	case Aes128Cbc:
		sessionCipherTransform = C.MY_xmlSecTransformAes128CbcId()
	case Des3Cbc:
		sessionCipherTransform = C.MY_xmlSecTransformDes3CbcId()
	default:
		return nil, fmt.Errorf("XXX")
	}

	// create encryption template to encrypt XML file and replace
	// its content with encryption result
	encDataNode := C.xmlSecTmplEncDataCreate(parsedDoc, sessionCipherTransform,
		nil, (*C.xmlChar)(unsafe.Pointer(&C.xmlSecTypeEncElement)), nil, nil)
	if encDataNode == nil {
		return nil, fmt.Errorf("xmlSecTmplEncDataCreate failed")
	}
	defer func() {
		if encDataNode != nil {
			C.xmlFreeNode(encDataNode)
			encDataNode = nil
		}
	}()

	// we want to put encrypted data in the <enc:CipherValue/> node
	if C.xmlSecTmplEncDataEnsureCipherValue(encDataNode) == nil {
		return nil, fmt.Errorf("xmlSecTmplEncDataEnsureCipherValue failed")
	}

	// add <dsig:KeyInfo/>
	keyInfoNode := C.xmlSecTmplEncDataEnsureKeyInfo(encDataNode, nil)
	if keyInfoNode == nil {
		return nil, fmt.Errorf("xmlSecTmplEncDataEnsureKeyInfo failed")
	}

	// add <enc:EncryptedKey/> to store the encrypted session key
	var cipherTransform C.xmlSecTransformId
	switch opts.Cipher {
	case DefaultAlgorithm:
		cipherTransform = C.MY_xmlSecTransformRsaOaepId()
	case RsaOaep:
		cipherTransform = C.MY_xmlSecTransformRsaOaepId()
	case RsaPkcs1:
		cipherTransform = C.MY_xmlSecTransformRsaPkcs1Id()
	}
	encKeyNode := C.xmlSecTmplKeyInfoAddEncryptedKey(keyInfoNode, cipherTransform, nil, nil, nil)
	if encKeyNode == nil {
		return nil, fmt.Errorf("xmlSecTmplKeyInfoAddEncryptedKey failed")
	}

	// we want to put encrypted key in the <enc:CipherValue/> node
	if C.xmlSecTmplEncDataEnsureCipherValue(encKeyNode) == nil {
		return nil, fmt.Errorf("xmlSecTmplEncDataEnsureCipherValue failed")
	}

	// add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to <enc:EncryptedKey/>
	keyInfoNode2 := C.xmlSecTmplEncDataEnsureKeyInfo(encKeyNode, nil)
	if keyInfoNode2 == nil {
		return nil, fmt.Errorf("xmlSecTmplEncDataEnsureKeyInfo failed")
	}
	// Add a DigestMethod element to the encryption method node
	{
		encKeyMethod := C.xmlSecTmplEncDataGetEncMethodNode(encKeyNode)
		var ns = constXmlChar("http://www.w3.org/2000/09/xmldsig#")
		var strDigestMethod = constXmlChar("DigestMethod")
		var strAlgorithm = constXmlChar("Algorithm")
		var algorithm *C.xmlChar
		switch opts.DigestAlgorithm {
		case Sha512:
			algorithm = constXmlChar("http://www.w3.org/2001/04/xmlenc#sha512")
		case Sha384:
			algorithm = constXmlChar("http://www.w3.org/2001/04/xmldsig-more#sha384")
		case Sha256:
			algorithm = constXmlChar("http://www.w3.org/2001/04/xmlenc#sha256")
		case Sha1:
			algorithm = constXmlChar("http://www.w3.org/2000/09/xmldsig#sha1")
		case DefaultAlgorithm:
			algorithm = constXmlChar("http://www.w3.org/2000/09/xmldsig#sha1")
		default:
			return nil, fmt.Errorf("unknown digest algorithm %d", opts.DigestAlgorithm)
		}
		node := C.xmlSecAddChild(encKeyMethod, strDigestMethod, ns)
		C.xmlSetProp(node, strAlgorithm, algorithm)
	}

	// add our certificate to KeyInfoNode
	x509dataNode := C.xmlSecTmplKeyInfoAddX509Data(keyInfoNode2)
	if x509dataNode == nil {
		return nil, fmt.Errorf("xmlSecTmplKeyInfoAddX509Data failed")
	}
	if dataNode := C.xmlSecTmplX509DataAddCertificate(x509dataNode); dataNode == nil {
		return nil, fmt.Errorf("xmlSecTmplX509DataAddCertificate failed")
	}

	// create encryption context
	var encCtx = C.xmlSecEncCtxCreate(keysMngr)
	if encCtx == nil {
		return nil, fmt.Errorf("xmlSecEncCtxCreate failed")
	}
	defer C.xmlSecEncCtxDestroy(encCtx)

	// generate a key of the appropriate type
	switch opts.SessionCipher {
	case DefaultAlgorithm:
		encCtx.encKey = C.xmlSecKeyGenerate(C.MY_xmlSecKeyDataAesId(), 256,
			C.xmlSecKeyDataTypeSession)
	case Aes128Cbc:
		encCtx.encKey = C.xmlSecKeyGenerate(C.MY_xmlSecKeyDataAesId(), 128,
			C.xmlSecKeyDataTypeSession)
	case Aes192Cbc:
		encCtx.encKey = C.xmlSecKeyGenerate(C.MY_xmlSecKeyDataAesId(), 192,
			C.xmlSecKeyDataTypeSession)
	case Aes256Cbc:
		encCtx.encKey = C.xmlSecKeyGenerate(C.MY_xmlSecKeyDataAesId(), 256,
			C.xmlSecKeyDataTypeSession)
	case Des3Cbc:
		encCtx.encKey = C.xmlSecKeyGenerate(C.MY_xmlSecKeyDataDesId(), 192,
			C.xmlSecKeyDataTypeSession)
	default:
		return nil, fmt.Errorf("unknown cipher type %d", opts.SessionCipher)
	}
	if encCtx.encKey == nil {
		return nil, fmt.Errorf("xmlSecKeyGenerate failed")
	}

	// encrypt the data
	if rv := C.xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, C.xmlDocGetRootElement(parsedDoc)); rv < 0 {
		return nil, fmt.Errorf("xmlSecEncCtxXmlEncrypt failed")
	}
	encDataNode = nil // the template is inserted in the doc, so we don't own it

	return dumpDoc(parsedDoc), nil
}
