package xmlsec

import (
	"errors"
	"fmt"
	"unsafe"
)

// #cgo pkg-config: xmlsec1
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmlenc.h>
// #include <xmlsec/xmldsig.h>
// #include <xmlsec/errors.h>
// #include <xmlsec/crypto.h>
import "C"

// DsigOptions represents additional, less commonly used, options for Sign and
// Verify
type DsigOptions struct {
	// Specify the name of ID attributes for specific elements. This
	// may be required if the signed document contains Reference elements
	// that define which parts of the document are to be signed.
	//
	// https://www.aleksey.com/xmlsec/faq.html#section_3_2
	// http://www.w3.org/TR/xml-id/
	// http://xmlsoft.org/html/libxml-valid.html#xmlAddID
	XMLID []XMLIDOption
}

type XMLIDOption struct {
	ElementName      string
	ElementNamespace string
	AttributeName    string
}

// Sign returns a version of docStr signed with key according to
// the XML-DSIG standard. docStr is a template document meaning
// that it contains a `Signature` element in the
// http://www.w3.org/2000/09/xmldsig# namespace.
func Sign(key []byte, doc []byte, opts DsigOptions) ([]byte, error) {

	startProcessingXML()
	defer stopProcessingXML()

	ctx := C.xmlSecDSigCtxCreate(nil)
	if ctx == nil {
		return nil, errors.New("failed to create signature context")
	}
	defer C.xmlSecDSigCtxDestroy(ctx)

	ctx.signKey = C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&key[0])),
		C.xmlSecSize(len(key)),
		C.xmlSecKeyDataFormatPem,
		nil, nil, nil)
	if ctx.signKey == nil {
		return nil, errors.New("failed to load pem key")
	}

	parsedDoc, err := newDoc2(doc, opts)
	if err != nil {
		return nil, err
	}
	defer closeDoc(parsedDoc)

	node := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeSignature)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecDSigNs)))
	if node == nil {
		return nil, errors.New("cannot find start node")
	}

	if rv := C.xmlSecDSigCtxSign(ctx, node); rv < 0 {
		return nil, errors.New("failed to sign")
	}

	return dumpDoc(parsedDoc), nil

}

// ErrVerificationFailed is returned from Verify when the signature is incorrect
var ErrVerificationFailed = errors.New("signature verification failed")

const (
	xmlSecDSigStatusUnknown   = 0
	xmlSecDSigStatusSucceeded = 1
	xmlSecDSigStatusInvalid   = 2
)

// Verify checks that the signature in docStr is valid according
// to the XML-DSIG specification. publicKey is the public part of
// the key used to sign docStr. If the signature is not correct,
// this function returns ErrVerificationFailed.
func Verify(publicKey []byte, doc []byte, opts DsigOptions) error {
	startProcessingXML()
	defer stopProcessingXML()

	keysMngr := C.xmlSecKeysMngrCreate()
	if keysMngr == nil {
		return fmt.Errorf("xmlSecKeysMngrCreate failed")
	}
	defer C.xmlSecKeysMngrDestroy(keysMngr)

	if rv := C.xmlSecCryptoAppDefaultKeysMngrInit(keysMngr); rv < 0 {
		return fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrInit failed")
	}

	key := C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&publicKey[0])),
		C.xmlSecSize(len(publicKey)),
		C.xmlSecKeyDataFormatCertPem,
		nil, nil, nil)
	if key == nil {
		return fmt.Errorf("xmlSecCryptoAppKeyLoadMemory failed")
	}

	if rv := C.xmlSecCryptoAppKeyCertLoadMemory(key,
		(*C.xmlSecByte)(unsafe.Pointer(&publicKey[0])),
		C.xmlSecSize(len(publicKey)),
		C.xmlSecKeyDataFormatCertPem); rv < 0 {
		C.xmlSecKeyDestroy(key)
		return fmt.Errorf("xmlSecCryptoAppKeyCertLoad failed")
	}

	if rv := C.xmlSecCryptoAppDefaultKeysMngrAdoptKey(keysMngr, key); rv < 0 {
		return fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrAdoptKey failed")
	}

	dsigCtx := C.xmlSecDSigCtxCreate(keysMngr)
	if dsigCtx == nil {
		return fmt.Errorf("xmlSecDSigCtxCreate failed")
	}
	defer C.xmlSecDSigCtxDestroy(dsigCtx)

	parsedDoc, err := newDoc2(doc, opts)
	if err != nil {
		return err
	}
	defer closeDoc(parsedDoc)

	node := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeSignature)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecDSigNs)))
	if node == nil {
		return errors.New("cannot find start node")
	}

	if rv := C.xmlSecDSigCtxVerify(dsigCtx, node); rv < 0 {
		return ErrVerificationFailed
	}

	if dsigCtx.status != xmlSecDSigStatusSucceeded {
		return ErrVerificationFailed
	}
	return nil
}
