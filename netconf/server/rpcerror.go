// Package server — RFC 6241 §4.3 <rpc-error> construction.
//
// Earlier code only emitted <error-type>, <error-severity>, and <error-message>,
// omitting the <error-tag> mandated by RFC 6241 §4.3. It also lost detail by
// rewriting translib errors as the literal string "Failed to handle request".
//
// This file centralises:
//   - error classification (Go error → (error-type, error-tag))
//   - <rpc-error> XML construction
//   - text/attribute XML escaping
//
// Keeping it in a separate file (rather than handler.go) lets the unit-test
// sandbox include just this file without dragging in subhandlers.go, which
// transitively requires libyang via cgo.
package server

import (
	"fmt"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

// classifyError maps a Go error to (error-type, error-tag) per RFC 6241 §4.3.
//
// translib returns typed errors from sonic-mgmt-common's tlerr package whenever
// the failure is in the application layer (YANG validation, DB lookup, ...).
// Those types are mapped to the RFC 6241 §4.3 standardised <error-tag> values
// so clients can dispatch on the tag without parsing message text.
// Errors of unknown type default to (rpc, operation-failed).
func classifyError(err error) (errType, errTag string) {
	switch err.(type) {
	case tlerr.InvalidArgsError, *tlerr.InvalidArgsError,
		tlerr.TranslibSyntaxValidationError, *tlerr.TranslibSyntaxValidationError,
		tlerr.TranslibCVLFailure, *tlerr.TranslibCVLFailure:
		return "application", "invalid-value"
	case tlerr.NotFoundError, *tlerr.NotFoundError,
		tlerr.TranslibRedisClientEntryNotExist, *tlerr.TranslibRedisClientEntryNotExist:
		return "application", "data-missing"
	case tlerr.AlreadyExistsError, *tlerr.AlreadyExistsError:
		return "application", "data-exists"
	case tlerr.NotSupportedError, *tlerr.NotSupportedError:
		return "application", "operation-not-supported"
	case tlerr.AuthorizationError, *tlerr.AuthorizationError:
		return "application", "access-denied"
	case tlerr.InternalError, *tlerr.InternalError,
		tlerr.TranslibTransactionFail, *tlerr.TranslibTransactionFail,
		tlerr.TranslibDBCannotOpen, *tlerr.TranslibDBCannotOpen,
		tlerr.TranslibDBConnectionReset, *tlerr.TranslibDBConnectionReset:
		return "application", "operation-failed"
	}
	return "rpc", "operation-failed"
}

// createRpcErrorXML builds an RFC 6241 §4.3 compliant <rpc-error>.
//
// All mandatory elements are present: <error-type>, <error-tag>,
// <error-severity>. <error-path> and <error-message> are included when their
// inputs are non-empty.
//
// errPath is optional — pass "" to omit <error-path>. Callers that have the
// request path (xpath) should pass it so clients can correlate errors to the
// specific subtree.
func createRpcErrorXML(err error, errPath string) string {
	errType, errTag := classifyError(err)
	pathPart := ""
	if errPath != "" {
		pathPart = "<error-path>" + xmlEscape(errPath) + "</error-path>"
	}
	return fmt.Sprintf(
		"<rpc-error><error-type>%s</error-type><error-tag>%s</error-tag><error-severity>error</error-severity>%s<error-message xml:lang=\"en\">%s</error-message></rpc-error>",
		errType, errTag, pathPart, xmlEscape(err.Error()),
	)
}

// xmlEscape escapes the five XML entities. We escape all five (not just the
// three mandatory inside element text) so that the resulting string is also
// safe inside attribute values, in case a future caller relocates the content.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// createErrorXML is the no-path-context entry point. New callers should call
// createRpcErrorXML with an explicit path when one is available; this exists
// for backwards compatibility with sites that have no path information.
func createErrorXML(err error) string {
	return createRpcErrorXML(err, "")
}
