package xmlsec

import (
	"errors"
	"unsafe"
)

// Note: on mac you need:
//   brew install libxmlsec1 libxml2
//   brew link libxml2 --force

// #cgo pkg-config: xmlsec1
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmlenc.h>
// #include <xmlsec/errors.h>
// #include <xmlsec/templates.h>
// #include <xmlsec/crypto.h>
import "C"

// #cgo pkg-config: libxml-2.0
// #include <libxml/parser.h>
// #include <libxml/parserInternals.h>
// #include <libxml/xmlmemory.h>
//
// // xmlFree is a macro, so we need to wrap it in order to be able to call
// // it from go code.
// static inline void MY_xmlFree(void *p) {
//   xmlFree(p);
// }
import "C"

// void onError_cgo(char *file, int line, char *funcName, char *errorObject, char *errorSubject, int reason, char *msg);
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

	C.xmlSecErrorsSetCallback((C.xmlSecErrorsCallback)(unsafe.Pointer(C.onError_cgo)))
}

func newDoc(buf []byte, idattrs []XMLIDOption) (*C.xmlDoc, error) {
	ctx := C.xmlCreateMemoryParserCtxt((*C.char)(unsafe.Pointer(&buf[0])),
		C.int(len(buf)))
	if ctx == nil {
		return nil, errors.New("error creating parser")
	}
	defer C.xmlFreeParserCtxt(ctx)

	C.xmlParseDocument(ctx)

	if ctx.wellFormed == C.int(0) {
		return nil, errors.New("malformed XML")
	}

	doc := ctx.myDoc
	if doc == nil {
		return nil, errors.New("parse failed")
	}

	for _, idattr := range idattrs {
		addIDAttr(C.xmlDocGetRootElement(doc),
			idattr.AttributeName, idattr.ElementName, idattr.ElementNamespace)
	}
	return doc, nil
}

func addIDAttr(node *C.xmlNode, attrName, nodeName, nsHref string) {
	// process children first because it does not matter much but does simplify code
	cur := C.xmlSecGetNextElementNode(node.children)
	for {
		if cur == nil {
			break
		}
		addIDAttr(cur, attrName, nodeName, nsHref)
		cur = C.xmlSecGetNextElementNode(cur.next)
	}

	if C.GoString((*C.char)(unsafe.Pointer(node.name))) != nodeName {
		return
	}
	if nsHref != "" && node.ns != nil && C.GoString((*C.char)(unsafe.Pointer(node.ns.href))) != nsHref {
		return
	}

	// the attribute with name equal to attrName should exist
	for attr := node.properties; attr != nil; attr = attr.next {
		if C.GoString((*C.char)(unsafe.Pointer(attr.name))) == attrName {
			id := C.xmlNodeListGetString(node.doc, attr.children, 1)
			if id == nil {
				continue
			}
			C.xmlAddID(nil, node.doc, id, attr)
		}
	}

	return
}
func closeDoc(doc *C.xmlDoc) {
	C.xmlFreeDoc(doc)
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

func constXMLChar(s string) *C.xmlChar {
	return (*C.xmlChar)(unsafe.Pointer(C.CString(s)))
}
