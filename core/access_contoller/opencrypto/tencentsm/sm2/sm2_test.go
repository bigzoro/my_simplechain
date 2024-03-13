/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm2

import (
	"crypto"
	"encoding/pem"
	"testing"

	tjsm2 "github.com/tjfoc/gmsm/sm2"

	"chainmaker.org/chainmaker/common/v2/opencrypto/tencentsm/sm3"

	"github.com/spf13/viper"
	tjx509 "github.com/tjfoc/gmsm/x509"

	"github.com/stretchr/testify/assert"
)

var (
	msg = []byte("hello world")
)

func TestSignAndVerify(t *testing.T) {
	priv, err := GenerateKeyPair()
	sig, err := priv.ToStandardKey().(crypto.Signer).Sign(nil, msg, nil)
	assert.NoError(t, err)

	pub, ok := priv.PublicKey().ToStandardKey().(*tjsm2.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, pub)
	ok = pub.Verify(msg, sig)
	assert.True(t, ok)

	ok, err = priv.pub.Verify(msg, sig)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestEncDec(t *testing.T) {

	priv, err := GenerateKeyPair()
	c, err := priv.pub.Encrypt(msg)
	assert.NoError(t, err)

	p, err := priv.Decrypt(c)
	assert.NoError(t, err)
	assert.Equal(t, msg, p)
}

func BenchmarkSM2_Sign(b *testing.B) {
	h := sm3.New()
	_, err := h.Write(msg)
	assert.NoError(b, err)
	digest := h.Sum(nil)
	priv, err := GenerateKeyPair()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		priv.ToStandardKey().(crypto.Signer).Sign(nil, digest, nil)
	}
}

func BenchmarkSM2_Verify(b *testing.B) {
	h := sm3.New()
	_, err := h.Write(msg)
	assert.NoError(b, err)
	digest := h.Sum(nil)

	viper.Set("common.tencentsm.ctx_pool_size", 10)

	priv, err := GenerateKeyPair()
	sig, _ := priv.ToStandardKey().(crypto.Signer).Sign(nil, digest, nil)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ok, err := priv.pub.Verify(digest, sig)
		assert.NoError(b, err)
		assert.True(b, ok)
	}
}

func TestAll(t *testing.T) {
	priv, err := GenerateKeyPair()
	assert.NoError(t, err)

	skPem, err := priv.String()
	assert.NoError(t, err)
	skBlock, _ := pem.Decode([]byte(skPem))

	pkPem, err := priv.pub.String()
	assert.NoError(t, err)
	pkBlock, _ := pem.Decode([]byte(pkPem))

	prv, err := UnmarshalPrivateKey(skBlock.Bytes)
	assert.NoError(t, err)
	pub, err := UnmarshalPublicKey(pkBlock.Bytes)
	assert.NoError(t, err)

	//sign and verify
	sig, err := prv.Sign(msg)
	assert.NoError(t, err)
	ok, err := pub.Verify(msg, sig)
	assert.NoError(t, err)
	assert.True(t, ok)

	tjpub, err := tjx509.ParseSm2PublicKey(pkBlock.Bytes)
	assert.NoError(t, err)
	ok = tjpub.Verify(msg, sig)
	assert.True(t, ok)

}
