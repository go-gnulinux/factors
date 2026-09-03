// Copyright (c) the go-gnulinux authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package factors

import (
	"context"

	authn "github.com/go-authn/fido"
	linuxfido "github.com/go-gnulinux/fido"
)

// platformOpen finds a security key over hidraw.
func platformOpen(context.Context) (authn.Transport, error) {
	t, err := linuxfido.Transport()
	if err != nil {
		return nil, asUnavailable(err, linuxfido.ErrNoKey, linuxfido.ErrPermission)
	}
	return t, nil
}
