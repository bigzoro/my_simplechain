/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm4

import (
	"github.com/simplechain-org/go-simplechain/core/access_contoller/opencrypto/gmssl/gmssl"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSM4(t *testing.T) {
	plain := []byte("hello world")

	sm4Key, err := generateSM4Key(t)
	assert.NoError(t, err)

	cipher, err := sm4Key.Encrypt(plain)
	assert.NoError(t, err)

	plain2, err := sm4Key.Decrypt(cipher)
	assert.NoError(t, err)

	assert.Equal(t, plain, plain2)
}

func generateSM4Key(t *testing.T) (SM4Key, error) {
	keylen, err := gmssl.GetCipherKeyLength("SMS4")
	assert.NoError(t, err)

	key, err := gmssl.GenerateRandom(keylen)
	assert.NoError(t, err)

	return SM4Key{Key: key}, nil
}
