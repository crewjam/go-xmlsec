package xmlsec

import "syscall"

func getThreadID() uintptr {
	return uintptr(syscall.Gettid())
}
