/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdf

import (
	"testing"

	"chainmaker.org/chainmaker/common/v2/crypto/sym/modes"

	bccrypto "chainmaker.org/chainmaker/common/v2/crypto"

	"github.com/stretchr/testify/assert"
)

func TestSM4(t *testing.T) {
	t.Skip()
	sdfHandle, err := New("./base/libswsds.dylib", 10)
	assert.NoError(t, err)
	defer sdfHandle.Close()

	key, err := NewSecretKey(sdfHandle, "1", []byte("11111111"), bccrypto.SM4)
	assert.NoError(t, err)

	//ecb mode
	cipherText, err := key.Encrypt(plain)
	assert.NoError(t, err)
	assert.NotNil(t, cipherText)

	plainText, err := key.Decrypt(cipherText)
	assert.NoError(t, err)
	assert.Equal(t, plain, plainText)

	//cbc mode
	cipherText, err = key.EncryptWithOpts(plain, &bccrypto.EncOpts{
		EncodingType: modes.PADDING_PKCS5,
		BlockMode:    modes.BLOCK_MODE_CBC,
	})
	assert.NoError(t, err)

	plainText, err = key.DecryptWithOpts(cipherText, &bccrypto.EncOpts{
		EncodingType: modes.PADDING_PKCS5,
		BlockMode:    modes.BLOCK_MODE_CBC,
	})
	assert.NoError(t, err)
	assert.Equal(t, plain, plainText)
}
