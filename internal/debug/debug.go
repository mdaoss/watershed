// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package debug

import (
	"runtime"
	"strings"
)

// CallerName retrieves the name of the function that called the function
// from which CallerName is invoked. The 'skip' parameter can be adjusted
// to go further up the call stack if necessary (e.g., if this function
// is wrapped in another helper function).
func CallerName(skip int) string {
	// pc: program counter
	// file: file name
	// line: line number
	// ok: success status
	pc, _, _, ok := runtime.Caller(skip + 1) // skip + 1 to get the actual caller of CallerName
	if !ok {
		return "unknown"
	}

	details := runtime.FuncForPC(pc)
	if details == nil {
		return "unknown"
	}

	// The full name typically includes the package path (e.g., "main.main" or "pkg/sub.MyFunc")
	fullFuncName := details.Name()

	// Extract just the function name part after the last dot
	lastDotIndex := strings.LastIndexByte(fullFuncName, '.')
	if lastDotIndex == -1 {
		return fullFuncName // Should not happen for a named function
	}

	return fullFuncName[lastDotIndex+1:]
}
