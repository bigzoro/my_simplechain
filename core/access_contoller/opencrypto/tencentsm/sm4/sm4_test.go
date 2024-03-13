/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm4

import (
	"github.com/bigzoro/my_simplechain/core/access_contoller/opencrypto/tencentsm/tencentsm"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSM4(t *testing.T) {
	plain := []byte("hello world")

	sm4Key, err := generateSM4Key()
	assert.NoError(t, err)

	cipher, err := sm4Key.Encrypt(plain)
	assert.NoError(t, err)

	plain2, err := sm4Key.Decrypt(cipher)
	assert.NoError(t, err)

	assert.Equal(t, plain, plain2)
}

func generateSM4Key() (SM4Key, error) {
	var key [16]byte
	tencentsm.GenerateSM4Key(key[:])
	return SM4Key{Key: key[:]}, nil
}
