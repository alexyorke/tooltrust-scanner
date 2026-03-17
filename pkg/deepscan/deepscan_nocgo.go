//go:build !cgo
// +build !cgo

package deepscan

import (
	"context"
	"errors"
)

// Init provides a stub for builds with CGO disabled.
func Init(ctx context.Context) error {
	return errors.New("deepscan is not supported in this build (requires CGO)")
}

// Analyze provides a stub for builds with CGO disabled.
func Analyze(text string) (score int, found bool) {
	return 0, false
}
