/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tencentcloudkms

import (
	"crypto"
	"encoding/base64"
	"fmt"

	bccrypto "chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/json"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	kms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms/v20190118"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

type PrivateKey struct {
	kms      *kms.Client
	keyType  string
	keyId    string
	keyAlias string
	pubKey   bccrypto.PublicKey
}

func (sk *PrivateKey) Type() bccrypto.KeyType {
	return sk.PublicKey().Type()
}

func (sk *PrivateKey) Bytes() ([]byte, error) {
	keyConfig := KMSPrivateKeyConfig{
		KeyType:  sk.keyType,
		KeyId:    sk.keyId,
		KeyAlias: sk.keyAlias,
	}
	return json.Marshal(keyConfig)
}

func (sk *PrivateKey) String() (string, error) {
	skBytes, err := sk.Bytes()
	if err != nil {
		return "", err
	}
	return string(skBytes), nil
}

func (sk *PrivateKey) PublicKey() bccrypto.PublicKey {
	return sk.pubKey
}

func (sk *PrivateKey) Sign(data []byte) ([]byte, error) {
	msgBase64 := base64.StdEncoding.EncodeToString(data)

	request := kms.NewSignByAsymmetricKeyRequest()

	request.Algorithm = common.StringPtr(sk.keyType)
	request.MessageType = common.StringPtr(MODE_DIGEST)
	request.KeyId = common.StringPtr(sk.keyId)
	request.Message = common.StringPtr(msgBase64)

	response, err := sk.kms.SignByAsymmetricKey(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return nil, fmt.Errorf("KMS API error: %s", err)
	}
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(*(response.Response.Signature))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (sk *PrivateKey) SignWithOpts(msg []byte, opts *bccrypto.SignOpts) ([]byte, error) {
	if opts == nil {
		return sk.Sign(msg)
	}
	if opts.Hash == bccrypto.HASH_TYPE_SM3 && sk.Type() == bccrypto.SM2 {
		pkSM2, ok := sk.PublicKey().ToStandardKey().(*sm2.PublicKey)
		if !ok {
			return nil, fmt.Errorf("SM2 private key does not match the type it claims")
		}
		uid := opts.UID
		if len(uid) == 0 {
			uid = bccrypto.CRYPTO_DEFAULT_UID
		}

		za, err := sm2.ZA(pkSM2, []byte(uid))
		if err != nil {
			return nil, fmt.Errorf("PKCS11 error: fail to create SM3 digest for msg [%v]", err)
		}
		e := sm3.New()
		e.Write(za)
		e.Write(msg)
		dgst := e.Sum(nil)[:32]

		return sk.Sign(dgst)
	}
	dgst, err := hash.Get(opts.Hash, msg)
	if err != nil {
		return nil, err
	}
	return sk.Sign(dgst)
}

func (sk *PrivateKey) ToStandardKey() crypto.PrivateKey {
	return &Signer{sk}
}
