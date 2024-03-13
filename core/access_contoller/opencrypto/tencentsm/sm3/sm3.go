/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm3

import "C"
import (
	"github.com/bigzoro/my_simplechain/core/access_contoller/opencrypto/tencentsm/tencentsm"
	"hash"
)

type digest struct {
	ctx *tencentsm.SM3_ctx_t
}

func New() hash.Hash {
	d := new(digest)
	var ctx tencentsm.SM3_ctx_t
	tencentsm.SM3Init(&ctx)
	d.ctx = &ctx
	return d
}

func NewDigestCtx() *digest {
	d := new(digest)
	var ctx tencentsm.SM3_ctx_t
	tencentsm.SM3Init(&ctx)
	d.ctx = &ctx
	return d
}

func (d *digest) BlockSize() int {
	return tencentsm.SM3_BLOCK_SIZE
}

func (d *digest) Size() int {
	return tencentsm.SM3_DIGEST_LENGTH
}

func (d *digest) Reset() {
	var ctx tencentsm.SM3_ctx_t
	tencentsm.SM3Init(&ctx)
	d.ctx = &ctx
}

func (d *digest) Write(p []byte) (int, error) {
	if p == nil {
		return 0, nil
	}
	tencentsm.SM3Update(d.ctx, p[:], len(p))
	return len(p), nil
}

func (d *digest) Sum(in []byte) []byte {
	dgst := make([]byte, tencentsm.SM3_DIGEST_LENGTH)
	_, _ = d.Write(in)
	tencentsm.SM3Final(d.ctx, dgst[:])
	return dgst
}
