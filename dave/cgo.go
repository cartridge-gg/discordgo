package dave

// This file carries the CGO #cgo directives (CFLAGS + LDFLAGS) for linking
// libdave. The C helper trampolines used from Go land (dave_session_create,
// dave_install_log_sink) live in the preamble of the file that calls them
// — cgo resolves C.xxx references against the preamble of the Go file
// where the reference appears, so a helper defined only here would be
// invisible to session.go or callbacks.go.

/*
#cgo CFLAGS: -I${SRCDIR}/libdave/cpp/includes
#cgo linux LDFLAGS: ${SRCDIR}/libdave/cpp/build/libdave.a -lstdc++ -lssl -lcrypto -lm -ldl -lpthread
#cgo darwin LDFLAGS: ${SRCDIR}/libdave/cpp/build/libdave.a -lc++ -lssl -lcrypto
*/
import "C"
