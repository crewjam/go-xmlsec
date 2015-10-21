package xmlenc

import (
	"errors"
	"fmt"
	"unsafe"
)

// Note: on mac you need: brew install libxmlsec1 libxml2

// #cgo pkg-config: xmlsec1
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmlenc.h>
// #include <xmlsec/crypto.h>
// #include <xmlsec/app.h>
//
// static inline xmlSecKeyDataId MY_xmlSecKeyDataDesId() {
//   return xmlSecOpenSSLKeyDataDesGetKlass();
// }
// static inline xmlSecKeyDataId MY_xmlSecKeyDataDsaId() {
//   return xmlSecOpenSSLKeyDataDsaGetKlass();
// }
// static inline xmlSecKeyDataId MY_xmlSecKeyDataEcdsaId() {
//   return xmlSecOpenSSLKeyDataEcdsaGetKlass();
// }
// static inline xmlSecKeyDataId MY_xmlSecKeyDataRsaId() {
//   return xmlSecOpenSSLKeyDataRsaGetKlass();
// }
//
import "C"

// #cgo pkg-config: libxml-2.0
// #include <libxml/parser.h>
// #include <libxml/parserInternals.h>
// #include <libxml/xmlmemory.h>
// // Macro wrapper function
// static inline void MY_xmlFree(void *p) {
//   xmlFree(p);
// }
//
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

type Context struct {
	ctx      *C.xmlSecEncCtx
	keysMngr *C.xmlSecKeysMngr
}

func (c *Context) Close() {
	if c.ctx != nil {
		C.xmlSecEncCtxDestroy(c.ctx)
		c.ctx = nil
	}

	if c.keysMngr != nil {
		C.xmlSecKeysMngrDestroy(c.keysMngr)
		c.keysMngr = nil
	}
}

func (c *Context) init() error {
	if c.ctx != nil {
		return nil
	}

	c.keysMngr = C.xmlSecKeysMngrCreate()
	if c.keysMngr == nil {
		return errors.New("xmlSecKeysMngrCreate failed")
	}

	if rv := C.xmlSecCryptoAppDefaultKeysMngrInit(c.keysMngr); rv < 0 {
		return fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrInit failed: %d", rv)
	}

	c.ctx = C.xmlSecEncCtxCreate(c.keysMngr)
	if c.ctx == nil {
		return errors.New("xmlSecEncCtxCreate failed")
	}

	return nil
}

const (
	DES = iota
	DSA
	ECDSA
	RSA
)

func (c *Context) AddKey(data []byte) error {
	if err := c.init(); err != nil {
		return err
	}

	key := C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		C.xmlSecKeyDataFormatPem,
		nil,
		nil,
		nil)
	if key == nil {
		return errors.New("xmlSecCryptoAppKeyLoadMemory failed")
	}

	name := "k"
	C.xmlSecKeySetName(key, (*C.xmlChar)(unsafe.Pointer(C.CString(name))))

	if rv := C.xmlSecCryptoAppDefaultKeysMngrAdoptKey(c.keysMngr, key); rv < 0 {
		return errors.New("xmlSecCryptoAppDefaultKeysMngrAdoptKey failed")
	}

	return nil
}

func (c *Context) AddCert(data []byte) error {
	if err := c.init(); err != nil {
		return err
	}

	/*
		var xmlSecKeyType C.xmlSecKeyDataId
		switch keyType {
		case DES:
			xmlSecKeyType = C.MY_xmlSecKeyDataDesId()
		case DSA:
			xmlSecKeyType = C.MY_xmlSecKeyDataDsaId()
		case ECDSA:
			xmlSecKeyType = C.MY_xmlSecKeyDataEcdsaId()
		case RSA:
			xmlSecKeyType = C.MY_xmlSecKeyDataRsaId()
		default:
			return errors.New("unknown key type")
		}
	*/

	if rv := C.xmlSecCryptoAppKeysMngrCertLoadMemory(c.keysMngr,
		(*C.xmlSecByte)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		C.xmlSecKeyDataFormatCertPem, // https://www.aleksey.com/xmlsec/api/xmlsec-keysdata.html#XMLSECKEYDATAFORMAT
		C.xmlSecKeyDataTypePublic); rv < 0 {
		return errors.New("xmlSecCryptoAppKeysMngrCertLoadMemory failed")
	}

	return nil
}

// Encrypt encrypts `plaintext` according to the template `tmplDoc`.
func (c *Context) Encrypt(tmplDoc []byte, plaintext []byte) ([]byte, error) {
	if err := c.init(); err != nil {
		return nil, err
	}

	parsedDoc, err := newDoc(tmplDoc)
	if err != nil {
		return nil, err
	}
	defer closeDoc(parsedDoc)

	tmplNode := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeEncryptedData)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecEncNs)))
	if tmplNode == nil {
		return nil, errors.New("cannot find start node")
	}

	// TODO(ross): actually use the requested cipher
	c.ctx.encKey = C.xmlSecKeyGenerateByName(
		(*C.xmlChar)(unsafe.Pointer(C.CString("aes"))),
		128, C.xmlSecKeyDataTypeSession)
	if c.ctx.encKey == nil {
		return nil, errors.New("failed to generate session key")
	}

	if rv := C.xmlSecEncCtxXmlEncrypt(c.ctx, tmplNode,
		C.xmlDocGetRootElement(parsedDoc)); rv < 0 {
		return nil, errors.New("cannot encrypt")
	}

	return dumpDoc(parsedDoc), nil
}
func (c *Context) Decrypt(doc []byte) ([]byte, error) {
	if err := c.init(); err != nil {
		return nil, err
	}

	return nil, nil
}

/*
func Decrypt(key []byte, doc []byte) ([]byte, error) {

	parsedDoc, err := newDoc(doc)
	if err != nil {
		return nil, err
	}
	defer closeDoc(parsedDoc)

	node := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeEncryptedKey)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecEncNs)))
	if node == nil {
		return nil, errors.New("cannot find start node")
	}

	ctx, err := newContext(key)
	if err != nil {
		return nil, err
	}
	defer closeContext(ctx)

	ctx.mode = C.xmlEncCtxModeEncryptedKey

	if rv := C.xmlSecEncCtxDecrypt(ctx, node); rv < 0 {
		return nil, errors.New("cannot decrypt")
	}
	if ctx.result == nil {
		return nil, errors.New("cannot decrypt")
	}

	ctx2 := C.xmlSecEncCtxCreate(nil)
	if ctx2 == nil {
		return nil, errors.New("failed to create signature context")
	}

	ctx2.encKey = C.xmlSecKeyReadMemory(C.MY_xmlSecKeyDataDesId(),
		C.xmlSecBufferGetData(ctx.result),
		C.xmlSecBufferGetSize(ctx.result))
	if ctx2.encKey == nil {
		return nil, errors.New("cannot load session key")
	}
	ctx2.mode = C.xmlEncCtxModeEncryptedData

	node2 := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeEncryptedData)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecEncNs)))
	if node2 == nil {
		return nil, errors.New("cannot find start node")
	}

	if rv := C.xmlSecEncCtxDecrypt(ctx2, node2); rv < 0 {
		return nil, errors.New("cannot decrypt")
	}
	if ctx2.result == nil {
		return nil, errors.New("cannot decrypt")
	}

	log.Panic("%s", string(dumpDoc(parsedDoc)))

	// Apparently we can either have replaced the document or not, so if we
	// have return it with dump.
	if ctx2.resultReplaced != 0 {
		return dumpDoc(parsedDoc), nil
	} else {
		sz := C.xmlSecBufferGetSize(ctx2.result)
		buf := C.xmlSecBufferGetData(ctx2.result)
		rv := C.GoStringN((*C.char)(unsafe.Pointer(buf)), C.int(sz)) // TODO(ross): eliminate double copy
		return []byte(rv), nil
	}
}

// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
// x
*/
