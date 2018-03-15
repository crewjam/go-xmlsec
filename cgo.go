package xmlsec

// #cgo pkg-config: xmlsec1 libxml-2.0
// #cgo linux CFLAGS: -w
// #cgo linux LDFLAGS: -lxml2 -lm
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
// #include <xmlsec/xmlenc.h>
// #include <xmlsec/templates.h>
// #include <xmlsec/crypto.h>
// #include <libxml/parser.h>
// #include <libxml/parserInternals.h>
// #include <libxml/xmlmemory.h>
import "C"
