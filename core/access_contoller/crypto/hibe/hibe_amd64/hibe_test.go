//go:build linux && amd64
// +build linux,amd64

/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hibe_amd64

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hibe/hibe_amd64/hibe"
	"github.com/stretchr/testify/require"
)

var (
	params    *hibe.Params
	masterKey hibe.MasterKey

	params2 *hibe.Params

	topLId_fake    = "org"
	secondLId_fake = "org1/ou"

	topLId     = "org1"
	topLKey    *hibe.PrivateKey
	topLHibeId []*big.Int

	secondLId     = "org1/ou1"
	secondLKey    *hibe.PrivateKey
	secondLHibeId []*big.Int

	thirdLId     = "org1/ou1/user1"
	thirdLKey    *hibe.PrivateKey
	thirdLHibeId []*big.Int

	otherLId     = "org1/ou2"
	otherLKey    *hibe.PrivateKey
	otherLHibeId []*big.Int

	noPermissionLId     = "org1/ou3"
	noPermissionLKey    *hibe.PrivateKey
	noPermissionLHibeId []*big.Int

	unsupportIdFmt = "///"

	msg = "这是一条测试数据"
)

func TestHibe(t *testing.T) {
	fmt.Println("=========================================Init front-end data=======================================")
	testInit(t)

	fmt.Println("==========================================Encrypt with SM4=========================================")
	var err error
	hibeMsgWithSM4, err := testEncrypt2HibeMsgMap([]byte(msg), crypto.SM4)
	require.Nil(t, err)
	t.Logf("[Encrypt Result]: %+v\n", hibeMsgWithSM4)

	fmt.Println("==========================================Encrypt with AES=========================================")
	hibeMsgWithAES, err := testEncrypt2HibeMsgMap([]byte(msg), crypto.AES)
	require.Nil(t, err)
	t.Logf("[Encrypt Result]: %+v\n", hibeMsgWithAES)

	fmt.Println("=========================================Encrypt with unsupport data============================")
	testEncrypt2HibeMsgMapWithUnsupportData(t, []byte(msg))

	fmt.Println("===============================================Decrypt================================")
	testDecryptHibeMsg(t, hibeMsgWithSM4, crypto.SM4)
	testDecryptHibeMsg(t, hibeMsgWithAES, crypto.AES)

	fmt.Println("===============================================Decrypt With unsupport data================================")
	testDecryptHibeMsgMapWitUnsupportData(t, hibeMsgWithAES, crypto.AES)
}

func testInit(t *testing.T) {
	var err error
	params, masterKey, err = hibe.Setup(rand.Reader, 10)
	require.Nil(t, err)

	params2, _, err = hibe.Setup(rand.Reader, 10)
	require.Nil(t, err)

	ids := strings.Split(topLId, "/")
	topLHibeId = make([]*big.Int, len(ids))
	for i, item := range ids {
		hashedId := sha256.Sum256([]byte(item))
		toBigBytes := hashedId[:]
		bigId := new(big.Int)
		bigId.SetBytes(toBigBytes)
		topLHibeId[i] = bigId
	}
	topLKey, err = hibe.KeyGenFromMaster(rand.Reader, params, masterKey, topLHibeId)

	ids2 := strings.Split(secondLId, "/")
	secondLHibeId = make([]*big.Int, len(ids2))
	for i, item := range ids2 {
		hashedId := sha256.Sum256([]byte(item))
		toBigBytes := hashedId[:]
		bigId := new(big.Int)
		bigId.SetBytes(toBigBytes)
		secondLHibeId[i] = bigId
	}
	secondLKey, err = hibe.KeyGenFromParent(rand.Reader, params, topLKey, secondLHibeId)
	require.Nil(t, err)

	ids3 := strings.Split(thirdLId, "/")
	thirdLHibeId = make([]*big.Int, len(ids3))
	for i, item := range ids3 {
		hashedId := sha256.Sum256([]byte(item))
		toBigBytes := hashedId[:]
		bigId := new(big.Int)
		bigId.SetBytes(toBigBytes)
		thirdLHibeId[i] = bigId
	}
	thirdLKey, err = hibe.KeyGenFromParent(rand.Reader, params, secondLKey, thirdLHibeId)
	require.Nil(t, err)

	ids4 := strings.Split(otherLId, "/")
	otherLHibeId = make([]*big.Int, len(ids4))
	for i, item := range ids4 {
		hashedId := sha256.Sum256([]byte(item))
		toBigBytes := hashedId[:]
		bigId := new(big.Int)
		bigId.SetBytes(toBigBytes)
		otherLHibeId[i] = bigId
	}
	otherLKey, err = hibe.KeyGenFromParent(rand.Reader, params, topLKey, otherLHibeId)
	require.Nil(t, err)

	ids5 := strings.Split(noPermissionLId, "/")
	noPermissionLHibeId = make([]*big.Int, len(ids4))
	for i, item := range ids5 {
		hashedId := sha256.Sum256([]byte(item))
		toBigBytes := hashedId[:]
		bigId := new(big.Int)
		bigId.SetBytes(toBigBytes)
		noPermissionLHibeId[i] = bigId
	}
	noPermissionLKey, err = hibe.KeyGenFromParent(rand.Reader, params, topLKey, noPermissionLHibeId)
	require.Nil(t, err)
}

func testEncrypt2HibeMsgMap(plaintext []byte, symKeyType crypto.KeyType) (map[string]string, error) {
	receiveIds := make([]string, 4)
	receiveIds[0] = secondLId
	receiveIds[1] = topLId
	receiveIds[2] = thirdLId
	receiveIds[3] = otherLId

	paramsList := make([]*hibe.Params, 4)
	paramsList[0] = params
	paramsList[1] = params
	paramsList[2] = params
	paramsList[3] = params

	return EncryptHibeMsg(plaintext, receiveIds, paramsList, symKeyType)
}

func testEncrypt2HibeMsgMapWithUnsupportData(t *testing.T, plaintext []byte) {
	tests := []struct {
		// input
		plaintext  []byte
		receiveIds []string
		paramsList []*hibe.Params
		symKeyType crypto.KeyType
		// output
		wantError error
	}{
		{ // 0.
			plaintext:  make([]byte, 0),
			receiveIds: make([]string, 0),
			paramsList: make([]*hibe.Params, 0),
			symKeyType: crypto.ECC_Ed25519,
			wantError:  errors.New("invalid parameters, plaintext is nil"),
		},
		{ // 1.
			plaintext:  plaintext,
			receiveIds: []string{},
			paramsList: make([]*hibe.Params, 0),
			symKeyType: crypto.ECC_Ed25519,
			wantError:  errors.New("invalid parameters, receiverIds is nil"),
		},
		{ // 2.
			plaintext:  plaintext,
			receiveIds: []string{unsupportIdFmt},
			paramsList: make([]*hibe.Params, 0),
			symKeyType: crypto.ECC_Ed25519,
			wantError:  fmt.Errorf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", unsupportIdFmt),
		},
		{ // 3.
			plaintext:  plaintext,
			receiveIds: []string{secondLId},
			paramsList: make([]*hibe.Params, 0),
			symKeyType: crypto.ECC_Ed25519,
			wantError:  errors.New("invalid parameters, paramsList is nil"),
		},
		{ // 4.
			plaintext:  plaintext,
			receiveIds: []string{secondLId},
			paramsList: []*hibe.Params{params, params},
			symKeyType: crypto.ECC_Ed25519,
			wantError:  errors.New("invalid parameters, receiverIds and paramsList do not match, place check them"),
		},
		{ // 5. UnsupportSymKey
			plaintext:  plaintext,
			receiveIds: []string{secondLId},
			paramsList: []*hibe.Params{params},
			symKeyType: crypto.ECC_Ed25519,
			wantError:  fmt.Errorf("invalid parameters, unsupported symmetric encryption algorithm type : %d", crypto.ECC_Ed25519),
		},
		{ // 6.
			plaintext:  plaintext,
			receiveIds: []string{secondLId, topLId},
			paramsList: []*hibe.Params{params, params2},
			symKeyType: crypto.AES,
			wantError:  fmt.Errorf("ID [%s] is matched, but Params are different, please check it", topLId),
		},
		{ // 7.
			plaintext:  plaintext,
			receiveIds: []string{topLId, secondLId},
			paramsList: []*hibe.Params{params, params2},
			symKeyType: crypto.AES,
			wantError:  fmt.Errorf("ID [%s] is matched, but Params are different, please check it", secondLId),
		},
		{ // 8.
			plaintext:  plaintext,
			receiveIds: []string{topLId_fake, thirdLId, secondLId_fake},
			paramsList: []*hibe.Params{params, params, params},
			symKeyType: crypto.AES,
			wantError:  nil,
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err := EncryptHibeMsg(tt.plaintext, tt.receiveIds, tt.paramsList, tt.symKeyType)
			//require.EqualError(t, err, tt.wantError)
			require.Equal(t, err, tt.wantError)
		})
	}
}

func testDecryptHibeMsg(t *testing.T, hibeMap map[string]string, symKeyType crypto.KeyType) {
	tests := []struct {
		// input
		localId    string
		hibeParams *hibe.Params
		prvKey     *hibe.PrivateKey
		hibeMsgMap map[string]string
		symKeyType crypto.KeyType
		// output
		wantError error
	}{
		{ // topLevel
			localId:    topLId,
			hibeParams: params,
			hibeMsgMap: hibeMap,
			prvKey:     topLKey,
			symKeyType: symKeyType,
			wantError:  nil,
		},
		{ // secondLId
			localId:    secondLId,
			hibeParams: params,
			hibeMsgMap: hibeMap,
			prvKey:     secondLKey,
			symKeyType: symKeyType,
			wantError:  nil,
		},
		{ // thirdLId
			localId:    thirdLId,
			hibeParams: params,
			hibeMsgMap: hibeMap,
			prvKey:     thirdLKey,
			symKeyType: symKeyType,
			wantError:  nil,
		},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			decryptMsg, err := DecryptHibeMsg(tt.localId, tt.hibeParams, tt.prvKey, tt.hibeMsgMap, tt.symKeyType)
			require.Nil(t, err)
			t.Logf("[%s] [Decrypt Result]: %s\n", tt.hibeParams, string(decryptMsg))
		})
	}
}

func testDecryptHibeMsgMapWitUnsupportData(t *testing.T, hibeMap map[string]string, symKeyType crypto.KeyType) {
	// format error
	var errFmtIDs = []string{
		"",
		"org1/",
		"/org1",
		"org1//user1",
		"org1/ /user1",
		"org1/o u/user1",
	}

	tests := []struct {
		// input
		localId    string
		hibeParams *hibe.Params
		prvKey     *hibe.PrivateKey
		hibeMsgMap map[string]string
		symKeyType crypto.KeyType
		// output
		wantError string
	}{
		// Decrypt with error Id
		{
			localId:   errFmtIDs[0],
			wantError: fmt.Sprintf("invalid parameters, id is nil"),
		},
		{
			localId:   errFmtIDs[1],
			wantError: fmt.Sprintf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", errFmtIDs[1]),
		},
		{
			localId:   errFmtIDs[2],
			wantError: fmt.Sprintf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", errFmtIDs[2]),
		},
		{
			localId:   errFmtIDs[3],
			wantError: fmt.Sprintf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", errFmtIDs[3]),
		},
		{
			localId:   errFmtIDs[4],
			wantError: fmt.Sprintf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", errFmtIDs[4]),
		},
		{
			localId:   errFmtIDs[5],
			wantError: fmt.Sprintf("invalid parameters, id: %s, format error, only like : \"A/B/C\" can be used", errFmtIDs[5]),
		},
		{ // Decrypt with invalid hibeParams
			localId:    topLId,
			hibeParams: nil,
			prvKey:     topLKey,
			hibeMsgMap: hibeMap,
			symKeyType: symKeyType,
			wantError:  "invalid parameters, hibeParams is nil",
		},
		{ // Decrypt with invalid prvKey
			localId:    topLId,
			hibeParams: params,
			prvKey:     nil,
			hibeMsgMap: hibeMap,
			symKeyType: symKeyType,
			wantError:  "invalid parameters, prvKey is nil",
		},
		{ // Decrypt with invalid hibeMsgMap
			localId:    topLId,
			hibeParams: params,
			prvKey:     topLKey,
			hibeMsgMap: nil,
			symKeyType: symKeyType,
			wantError:  "invalid parameters, hibeMsgMap is nil",
		},
		{ // Decrypt with unsupport sym key
			localId:    topLId,
			hibeParams: params,
			prvKey:     topLKey,
			hibeMsgMap: hibeMap,
			symKeyType: crypto.ECC_NISTP384,
			wantError:  fmt.Sprintf("invalid parameters, unsupported symmetric encryption algorithm type : %d", crypto.ECC_NISTP384),
		},
		{ // Decrypt with no permission key
			localId:    noPermissionLId,
			hibeParams: params,
			prvKey:     noPermissionLKey,
			hibeMsgMap: hibeMap,
			symKeyType: symKeyType,
			wantError:  "no permission",
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err := DecryptHibeMsg(tt.localId, tt.hibeParams, tt.prvKey, tt.hibeMsgMap, tt.symKeyType)
			require.EqualError(t, err, tt.wantError)
		})
	}
}
