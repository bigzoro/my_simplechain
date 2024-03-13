//go:build !linux || !amd64
// +build !linux !amd64

/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bulletproofs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBulletproofs(t *testing.T) {
	var err error
	_, _, _, err = ProveRandomOpening(0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = ProveSpecificOpening(0, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = Verify(nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = ProveAfterAddNum(0, 0, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, _, err = ProveAfterAddCommitment(0, 0, nil, nil, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = ProveAfterSubNum(0, 0, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, _, err = ProveAfterSubCommitment(0, 0, nil, nil, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, _, err = ProveAfterMulNum(0, 0, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenRNG()
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = PedersenCommitRandomOpening(0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenCommitSpecificOpening(0, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenVerify(nil, nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenNeg(nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenNegOpening(nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenAddNum(nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenAddCommitment(nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenAddOpening(nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = PedersenAddCommitmentWithOpening(nil, nil, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenSubNum(nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenSubCommitment(nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenSubOpening(nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = PedersenSubCommitmentWithOpening(nil, nil, nil, nil)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenMulNum(nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, err = PedersenMulOpening(nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

	_, _, err = PedersenMulNumWithOpening(nil, nil, 0)
	require.EqualError(t, err, "bulletproofs: unsupported")

}
