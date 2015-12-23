package xmlsec

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/crewjam/errset"
)

// #include <pthread.h>
import "C"

var globalErrors = map[uintptr]errset.ErrSet{}

type Error struct {
	FileName string
	Line     int
	FuncName string
	Object   string
	Subject  string
	Reason   int
	Message  string
}

func (e Error) Error() string {
	return fmt.Sprintf(
		"func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s",
		e.FuncName,
		e.FileName,
		e.Line,
		e.Object,
		e.Subject,
		e.Reason,
		e.Message)
}

//export onError
func onError(file *C.char, line C.int, funcName *C.char, errorObject *C.char, errorSubject *C.char, reason C.int, msg *C.char) {
	err := Error{
		FuncName: C.GoString(funcName),
		FileName: C.GoString(file),
		Line:     int(line),
		Object:   C.GoString(errorObject),
		Subject:  C.GoString(errorSubject),
		Reason:   int(reason),
		Message:  C.GoString(msg)}
	threadID := uintptr(unsafe.Pointer(C.pthread_self()))
	globalErrors[threadID] = append(globalErrors[threadID], err)
}

// startProcessingXML is called whenever we enter a function exported by this package.
// It locks the current goroutine to the current thread and establishes a thread-local
// error object.
func startProcessingXML() {
	runtime.LockOSThread()
	threadID := uintptr(unsafe.Pointer(C.pthread_self()))
	globalErrors[threadID] = errset.ErrSet{}
}

// stopProcessingXML unlocks the goroutine-thread lock and deletes the current
// error stack.
func stopProcessingXML() {
	runtime.UnlockOSThread()
	threadID := uintptr(unsafe.Pointer(C.pthread_self()))
	delete(globalErrors, threadID)
}

// popError returns the global error for the current thread and resets it to
// an empty error. Returns nil if no errors have occurred.
func popError() error {
	threadID := uintptr(unsafe.Pointer(C.pthread_self()))
	rv := globalErrors[threadID].ReturnValue()
	globalErrors[threadID] = errset.ErrSet{}
	return rv
}
