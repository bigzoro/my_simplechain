/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdf

type SDFKeyType string

const (
	RSA   SDFKeyType = "RSA"
	ECDSA SDFKeyType = "ECDSA"
	SM2   SDFKeyType = "SM2"

	AES SDFKeyType = "AES"
	SM4 SDFKeyType = "SM4"

	UNKNOWN SDFKeyType = "UNKNOWN"
)
