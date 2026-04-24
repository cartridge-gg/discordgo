package dave

// #include <stdint.h>
import "C"

import (
	"runtime/cgo"
	"sync"
	"unsafe"
)

// MLSFailureFunc is invoked when libdave reports an MLS protocol failure on a
// session. "Source" is the libdave component that raised the failure (e.g.
// "externalSender", "welcome"); "reason" is a human-readable message. Treat
// this as a fatal-for-the-session signal — the caller should tear down the
// voice connection and reconnect.
type MLSFailureFunc func(source, reason string)

// LogFunc is called once per libdave log line if InstallLogSink is used.
// Libdave's log callback is process-global (not per-session).
type LogFunc func(severity LogSeverity, file string, line int, message string)

// goDaveOnMLSFailure is the C-callable trampoline libdave invokes on an MLS
// failure. We receive a cgo.Handle encoded in userData and use it to reach
// the Go-side Session.
//
//export goDaveOnMLSFailure
func goDaveOnMLSFailure(source *C.char, reason *C.char, userData unsafe.Pointer) {
	if userData == nil {
		return
	}
	h := cgo.Handle(uintptr(userData))
	v := h.Value()
	s, ok := v.(*Session)
	if !ok || s == nil {
		return
	}
	s.fireFailure(C.GoString(source), C.GoString(reason))
}

// Global log sink. libdave's log sink is process-global, not per-session.
var (
	logSinkMu   sync.RWMutex
	logSinkFunc LogFunc
)

// InstallLogSink wires libdave's global log callback to the provided LogFunc.
// Pass nil to disable logging. Calling this more than once replaces the
// previous sink.
func InstallLogSink(fn LogFunc) {
	logSinkMu.Lock()
	logSinkFunc = fn
	logSinkMu.Unlock()
	C.dave_install_log_sink()
}

//export goDaveOnLogSink
func goDaveOnLogSink(severity C.int, file *C.char, line C.int, message *C.char) {
	logSinkMu.RLock()
	fn := logSinkFunc
	logSinkMu.RUnlock()
	if fn == nil {
		return
	}
	fn(LogSeverity(severity), C.GoString(file), int(line), C.GoString(message))
}
