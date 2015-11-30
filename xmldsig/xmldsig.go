package xmldsig

import (
	"errors"
	"fmt"
	"unsafe"
)

// Note: on mac you need: brew install libxmlsec1 libxml2

// #cgo pkg-config: xmlsec1
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmldsig.h>
// #include <xmlsec/crypto.h>
import "C"

// #cgo pkg-config: libxml-2.0
// #include <libxml/parser.h>
// #include <libxml/parserInternals.h>
// #include <libxml/xmlmemory.h>
// // Macro wrapper function
// static inline void MY_xmlFree(void *p) {
//   xmlFree(p);
// }
import "C"

func init() {
	C.xmlInitParser()

	if rv := C.xmlSecInit(); rv < 0 {
		panic("xmlsec failed to initialize")
	}
	if rv := C.xmlSecCryptoAppInit(nil); rv < 0 {
		panic("xmlsec crypto initialization failed.")
	}
	if rv := C.xmlSecCryptoInit(); rv < 0 {
		panic("xmlsec crypto initialization failed.")
	}
}

func newDoc(buf []byte) (*C.xmlDoc, error) {
	ctx := C.xmlCreateMemoryParserCtxt((*C.char)(unsafe.Pointer(&buf[0])),
		C.int(len(buf)))
	if ctx == nil {
		return nil, errors.New("error creating parser")
	}
	defer C.xmlFreeParserCtxt(ctx)

	//C.xmlCtxtUseOptions(ctx, C.int(p.Options))
	C.xmlParseDocument(ctx)

	if ctx.wellFormed == C.int(0) {
		return nil, errors.New("malformed XML")
	}

	doc := ctx.myDoc
	if doc == nil {
		return nil, errors.New("parse failed")
	}
	return doc, nil
}

func dumpDoc(doc *C.xmlDoc) []byte {
	var buffer *C.xmlChar
	var bufferSize C.int
	C.xmlDocDumpMemory(doc, &buffer, &bufferSize)
	rv := C.GoStringN((*C.char)(unsafe.Pointer(buffer)), bufferSize)
	C.MY_xmlFree(unsafe.Pointer(buffer))

	// TODO(ross): this is totally nasty un-idiomatic, but I'm
	// tired of googling how to copy a []byte from a char*
	return []byte(rv)
}

func closeDoc(doc *C.xmlDoc) {
	C.xmlFreeDoc(doc)
}

// Sign returns a version of docStr signed with key according to
// the XML-DSIG standard. docStr is a template document meaning
// that it contains a `Signature` element in the
// http://www.w3.org/2000/09/xmldsig# namespace.
func Sign(key []byte, doc []byte) ([]byte, error) {
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

	parsedDoc, err := newDoc(doc)
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
// this function returns ErrVarificationFailed.
func Verify(publicKey []byte, doc []byte) error {
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

	parsedDoc, err := newDoc(doc)
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
