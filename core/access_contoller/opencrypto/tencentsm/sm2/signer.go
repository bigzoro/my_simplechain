/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sm2

import (
	"crypto"
	"github.com/simplechain-org/go-simplechain/core/access_contoller/opencrypto/utils"
	"io"
)

type signer struct {
	PrivateKey
}

func (s *signer) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.PrivateKey.signWithSM3(msg, []byte(utils.SM2_DEFAULT_USER_ID))
}
