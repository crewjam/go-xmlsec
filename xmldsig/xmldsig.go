package xmldsig

import (
	"errors"
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
// #include "libxml/parser.h"
// #include "libxml/parserInternals.h"
// #include "libxml/xmlmemory.h"
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

func newContext(pemFormatKey []byte) (*C.xmlSecDSigCtx, error) {
	ctx := C.xmlSecDSigCtxCreate(nil)
	if ctx == nil {
		return nil, errors.New("failed to create signature context")
	}

	ctx.signKey = C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&pemFormatKey[0])),
		C.xmlSecSize(len(pemFormatKey)),
		C.xmlSecKeyDataFormatPem,
		nil, nil, nil)
	if ctx.signKey == nil {
		return nil, errors.New("failed to load pem key")
	}
	return ctx, nil
}

func closeContext(ctx *C.xmlSecDSigCtx) {
	C.xmlSecDSigCtxDestroy(ctx)
}

func newDoc(s string) (*C.xmlDoc, error) {
	ctx := C.xmlCreateMemoryParserCtxt(C.CString(s), C.int(len(s)))
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

func dumpDoc(doc *C.xmlDoc) string {
	var buffer *C.xmlChar
	var bufferSize C.int
	C.xmlDocDumpMemory(doc, &buffer, &bufferSize)
	rv := C.GoStringN((*C.char)(unsafe.Pointer(buffer)), bufferSize)
	C.xmlMemFree(unsafe.Pointer(buffer))
	return rv
}

func closeDoc(doc *C.xmlDoc) {
	C.xmlFreeDoc(doc)
}

// Sign returns a version of docStr signed with key according to
// the XML-DSIG standard. docStr is a template document meaning
// that it contains a `Signature` element in the
// http://www.w3.org/2000/09/xmldsig# namespace.
func Sign(key []byte, docStr string) (string, error) {
	ctx, err := newContext(key)
	if err != nil {
		return "", err
	}
	defer closeContext(ctx)

	doc, err := newDoc(docStr)
	if err != nil {
		return "", err
	}
	defer closeDoc(doc)

	node := C.xmlSecFindNode(C.xmlDocGetRootElement(doc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeSignature)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecDSigNs)))
	if node == nil {
		return "", errors.New("cannot find start node")
	}

	if rv := C.xmlSecDSigCtxSign(ctx, node); rv < 0 {
		return "", errors.New("failed to sign")
	}

	return dumpDoc(doc), nil
}

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
func Verify(publicKey []byte, docStr string) error {
	ctx, err := newContext(publicKey)
	if err != nil {
		return err
	}
	defer closeContext(ctx)

	doc, err := newDoc(docStr)
	if err != nil {
		return err
	}
	defer closeDoc(doc)

	node := C.xmlSecFindNode(C.xmlDocGetRootElement(doc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeSignature)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecDSigNs)))
	if node == nil {
		return errors.New("cannot find start node")
	}

	if rv := C.xmlSecDSigCtxVerify(ctx, node); rv < 0 {
		return errors.New("failed to verify")
	}

	if ctx.status != xmlSecDSigStatusSucceeded {
		return ErrVerificationFailed
	}
	return nil
}
