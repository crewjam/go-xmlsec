package xmlsec

import "unsafe"

// #include <pthread.h>
import "C"

func getThreadID() uintptr {
	return uintptr(unsafe.Pointer(C.pthread_self()))
}
