package dave

// This file carries the CGO directives for linking libdave. Kept separate from
// the Go code so the build flags are easy to adjust per-platform without
// touching the binding logic.

/*
#cgo CFLAGS: -I${SRCDIR}/libdave/cpp/includes
#cgo linux LDFLAGS: ${SRCDIR}/libdave/cpp/build/libdave.a -lstdc++ -lssl -lcrypto -lm -ldl -lpthread
#cgo darwin LDFLAGS: ${SRCDIR}/libdave/cpp/build/libdave.a -lc++ -lssl -lcrypto

#include <stdlib.h>
#include <dave/dave.h>

// Go cannot invoke C function pointers directly, and the //export functions
// we define in Go are referenced by name here so the linker can resolve them
// when libdave calls back. These are the trampolines libdave receives as
// callback pointers; they forward to the Go side.
extern void goDaveOnMLSFailure(const char* source, const char* reason, void* userData);
extern void goDaveOnLogSink(int severity, const char* file, int line, const char* message);

// A single static log sink pointer we can pass to daveSetLogSinkCallback once
// at init. libdave's log sink is global, not per-session, so there's no
// userData field — we multiplex into package-level Go state instead.
static inline void dave_install_log_sink(void) {
    daveSetLogSinkCallback((DAVELogSinkCallback)goDaveOnLogSink);
}

// Convenience wrapper so the Go side doesn't need to name-mangle the
// trampoline function-pointer cast for each daveSessionCreate call.
static inline DAVESessionHandle dave_session_create(const char* authSessionId, void* userData) {
    return daveSessionCreate(NULL, authSessionId, (DAVEMLSFailureCallback)goDaveOnMLSFailure, userData);
}
*/
import "C"
