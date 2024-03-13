/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdf

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/tjfoc/gmsm/sm3"

	bccrypto "chainmaker.org/chainmaker/common/v2/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	plain = []byte("chainmaker")
)

var (
	lib = "./libswsds.so"
)

func TestSM2(t *testing.T) {
	t.Skip("skip this test")

	sdfHandle, err := New(lib, 10)
	assert.NoError(t, err)
	defer sdfHandle.Close()

	bcPriv, err := NewPrivateKey(sdfHandle, "1", []byte("11111111"), bccrypto.SM2)
	assert.NoError(t, err)

	plain = sm3.Sm3Sum(plain)
	sig, err := bcPriv.SignWithOpts(plain, &bccrypto.SignOpts{Hash: bccrypto.HASH_TYPE_SM3})
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	ok, err := bcPriv.PublicKey().VerifyWithOpts(plain, sig, &bccrypto.SignOpts{Hash: bccrypto.HASH_TYPE_SM3})
	assert.NoError(t, err)
	assert.True(t, ok)

	sig, err = bcPriv.ToStandardKey().(crypto.Signer).Sign(rand.Reader, plain, nil)
	assert.NoError(t, err)
	ok, err = bcPriv.PublicKey().VerifyWithOpts(plain, sig, &bccrypto.SignOpts{Hash: bccrypto.HASH_TYPE_SM3})
	assert.NoError(t, err)
	assert.True(t, ok)
}
