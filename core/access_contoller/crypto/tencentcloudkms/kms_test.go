/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tencentcloudkms

import (
	"fmt"

	"encoding/base64"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	kms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms/v20190118"
)

const (
	kmsServer = "kms.tencentcloudapi.com"
	kmsRegion = "ap-guangzhou"

	secretId  = "AKIDA9uPef95S0JOHQx0RzCF3qPilYUfrjNm"
	secretKey = "VllDRRBfCTVHn46sNYUKSqysWhdR0K0T"

	sm2KeyId = "e2920cd5-5a02-11eb-840b-525400e8e6ea"

	msgConst = "Valar morgulis."
)

func verifyKMS(msg string, sig []byte, sk *PrivateKey, client *kms.Client) (bool, error) {
	sigBase64 := base64.StdEncoding.EncodeToString(sig)
	msgBase64 := base64.StdEncoding.EncodeToString([]byte(msg))

	request := kms.NewVerifyByAsymmetricKeyRequest()

	request.KeyId = common.StringPtr(sk.keyId)
	request.SignatureValue = common.StringPtr(sigBase64)
	request.Message = common.StringPtr(msgBase64)
	request.Algorithm = common.StringPtr(sk.keyType)
	request.MessageType = common.StringPtr("RAW")

	response, err := client.VerifyByAsymmetricKey(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return false, fmt.Errorf("An API error has returned: %s", err)
	}
	if err != nil {
		return false, err
	}

	return *(response.Response.SignatureValid), nil
}

//func testKMS(t *testing.T) {
//	kmsConfig := &KMSConfig{
//		SecretId:      secretId,
//		SecretKey:     secretKey,
//		ServerAddress: kmsServer,
//		ServerRegion:  kmsRegion,
//	}
//
//	signOpts := &bccrypto.SignOpts{
//		Hash: bccrypto.HASH_TYPE_SM3,
//		UID:  bccrypto.CRYPTO_DEFAULT_UID,
//	}
//
//	client, err := CreateConnection(kmsConfig)
//	require.Nil(t, err)
//
//	keyConfig := &KMSPrivateKeyConfig{
//		KeyType:  bccrypto.CRYPTO_ALGO_SM2,
//		KeyId:    sm2KeyId,
//		KeyAlias: "",
//	}
//	sk, err := NewPrivateKey(client, keyConfig)
//	require.Nil(t, err)
//
//	sig, err := sk.SignWithOpts([]byte(msgConst), signOpts)
//	require.Nil(t, err)
//
//	isValidKMS, err := verifyKMS(msgConst, sig, sk.(*PrivateKey), client)
//	require.Nil(t, err)
//	require.Equal(t, true, isValidKMS)
//
//	isValid, err := sk.PublicKey().VerifyWithOpts([]byte(msgConst), sig, signOpts)
//	require.Nil(t, err)
//	require.Equal(t, true, isValid)
//
//	skInfo, err := sk.String()
//	require.Nil(t, err)
//
//	skLoaded, err := LoadPrivateKey(client, []byte(skInfo))
//	require.Nil(t, err)
//
//	sig, err = skLoaded.SignWithOpts([]byte(msgConst), signOpts)
//	require.Nil(t, err)
//
//	isValidKMS, err = verifyKMS(msgConst, sig, skLoaded.(*PrivateKey), client)
//	require.Nil(t, err)
//	require.Equal(t, true, isValidKMS)
//
//	isValid, err = skLoaded.PublicKey().VerifyWithOpts([]byte(msgConst), sig, signOpts)
//	require.Nil(t, err)
//	require.Equal(t, true, isValid)
//
//	isValidKMS, err = verifyKMS(msgConst, sig, sk.(*PrivateKey), client)
//	require.Nil(t, err)
//	require.Equal(t, true, isValidKMS)
//
//	isValid, err = sk.PublicKey().VerifyWithOpts([]byte(msgConst), sig, signOpts)
//	require.Nil(t, err)
//	require.Equal(t, true, isValid)
//
//	signer := &Signer{skLoaded.(*PrivateKey)}
//
//	sig, err = signer.Sign(nil, []byte(msgConst), nil)
//	require.Nil(t, err)
//
//	isValid, err = sk.PublicKey().VerifyWithOpts([]byte(msgConst), sig, signOpts)
//	require.Nil(t, err)
//	require.Equal(t, true, isValid)
//
//	fmt.Printf("KMS private key serialization: %s\n", skInfo)
//
//	fmt.Println("KMS test done")
//}
