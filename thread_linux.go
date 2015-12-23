package xmlsec

import "syscall"

func getThreadId() uintptr {
	return uintptr(syscall.Gettid())
}
