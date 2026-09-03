// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package factors

import (
	"context"
	"errors"

	authn "github.com/go-authn/fido"
)

// ErrUnsupported is what this factor reports off Linux. It is wrapped as
// unavailable rather than as a refusal: a Mac has not failed anybody here, it
// simply has no hidraw. The macOS adapters are go-macos/factors and the
// Windows ones go-mswin/factors.
var ErrUnsupported = errors.New("factors: these are Linux factors")

func platformOpen(context.Context) (authn.Transport, error) {
	return nil, asUnavailable(ErrUnsupported, ErrUnsupported)
}
