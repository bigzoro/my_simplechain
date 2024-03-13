//+build linux,amd64

/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bulletproofs_cgo

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestBulletproofs(t *testing.T) {
	commitment, opening, err := PedersenCommitRandomOpening(10)
	if err != nil {
		panic(err)
	}
	commitment2, err := PedersenCommitSpecificOpening(10, opening)
	if err != nil {
		panic(err)
	}
	commitment3, opening3, err := PedersenCommitRandomOpening(100)
	if err != nil {
		panic(err)
	}
	commitment4, err := PedersenAddNum(commitment, 5)
	if err != nil {
		panic(err)
	}
	commitment5, opening5, err := PedersenAddCommitmentWithOpening(commitment, commitment3, opening, opening3)
	if err != nil {
		panic(err)
	}
	commitment6, err := PedersenSubNum(commitment3, 20)
	if err != nil {
		panic(err)
	}
	commitment7, opening7, err := PedersenSubCommitmentWithOpening(commitment3, commitment, opening3, opening)
	if err != nil {
		panic(err)
	}
	commitment8, opening8, err := PedersenSubCommitmentWithOpening(commitment3, commitment6, opening3, opening3)
	if err != nil {
		panic(err)
	}
	commitment9, opening9, err := PedersenSubCommitmentWithOpening(commitment3, commitment3, opening3, opening3)
	if err != nil {
		panic(err)
	}

	commitmentMul, openingMul, err := PedersenMulNumWithOpening(commitment3, opening3, 20)
	if err != nil {
		panic(err)
	}

	ret, err := PedersenVerify(commitment, opening, 10)
	fmt.Println("1: ", ret)
	ret, err = PedersenVerify(commitment2, opening, 10)
	fmt.Println("2: ", ret)
	ret, err = PedersenVerify(commitment3, opening3, 100)
	fmt.Println("3: ", ret)
	ret, err = PedersenVerify(commitment, opening, 100)
	fmt.Println("4: ", ret)
	ret, err = PedersenVerify(commitment3, opening, 10)
	fmt.Println("5: ", ret)
	ret, err = PedersenVerify(commitment4, opening, 15)
	fmt.Println("6: ", ret)
	ret, err = PedersenVerify(commitment5, opening5, 110)
	fmt.Println("7: ", ret)

	ret, err = PedersenVerify(commitment6, opening3, 80)
	fmt.Println("sub1: ", ret)
	ret, err = PedersenVerify(commitment7, opening7, 90)
	fmt.Println("sub2: ", ret)
	ret, err = PedersenVerify(commitment8, opening8, 20)
	fmt.Println("sub3: ", ret)
	ret, err = PedersenVerify(commitment9, opening9, 0)
	fmt.Println("sub4: ", ret)

	ret, err = PedersenVerify(commitmentMul, openingMul, 2000)
	fmt.Println("Mul: ", ret)

	proof, commitmentf, openingf, err := ProveRandomOpening(10)
	if err != nil {
		panic(err)
	}
	proof2, commitmentf2, err := ProveSpecificOpening(10, openingf)
	if err != nil {
		panic(err)
	}
	proof3, commitmentf3, _, err := ProveRandomOpening(100)
	if err != nil {
		panic(err)
	}

	proof1Base64 := base64.StdEncoding.EncodeToString(proof)
	proof2Base64 := base64.StdEncoding.EncodeToString(proof2)

	fmt.Println("proof1: " + proof1Base64)
	fmt.Println("proof2: " + proof2Base64)

	ret, err = Verify(proof, commitmentf)
	fmt.Println("1: ", ret)
	ret, err = Verify(proof2, commitmentf2)
	fmt.Println("2: ", ret)
	ret, err = Verify(proof2, commitmentf)
	fmt.Println("3: ", ret)
	ret, err = Verify(proof, commitmentf2)
	fmt.Println("4: ", ret)
	ret, err = Verify(proof3, commitmentf3)
	fmt.Println("5: ", ret)
	ret, err = Verify(proof3, commitmentf)
	fmt.Println("6: ", ret)

	proofAdd, commitmentAdd, err := ProveAfterAddNum(10, 30, opening, commitment)
	if err != nil {
		panic(err)
	}
	proofAddC, commitmentAddC, openingAddC, err := ProveAfterAddCommitment(100, 10, opening3, opening, commitment3, commitment)
	if err != nil {
		panic(err)
	}

	ret, err = Verify(proofAdd, commitmentAdd)
	fmt.Println("Add num proof: ", ret)
	ret, err = PedersenVerify(commitmentAdd, opening, 40)
	fmt.Println("Add num commit: ", ret)
	ret, err = Verify(proofAddC, commitmentAddC)
	fmt.Println("Add commit proof: ", ret)
	ret, err = PedersenVerify(commitmentAddC, openingAddC, 110)
	fmt.Println("Add commit commit: ", ret)

	proofSub, commitmentSub, err := ProveAfterSubNum(100, 10, opening3, commitment3)
	if err != nil {
		panic(err)
	}
	proofSubC, commitmentSubC, openingSubC, err := ProveAfterSubCommitment(100, 10, opening3, opening, commitment3, commitment)
	if err != nil {
		panic(err)
	}

	ret, err = Verify(proofSub, commitmentSub)
	fmt.Println("Add num proof: ", ret)
	ret, err = PedersenVerify(commitmentSub, opening3, 90)
	fmt.Println("Add num commit: ", ret)
	ret, err = Verify(proofSubC, commitmentSubC)
	fmt.Println("Add commit proof: ", ret)
	ret, err = PedersenVerify(commitmentSubC, openingSubC, 90)
	fmt.Println("Add commit commit: ", ret)

	proofMult, commitmentMult, openingMult, err := ProveAfterMulNum(100, 10, opening3, commitment3)
	if err != nil {
		panic(err)
	}

	ret, err = Verify(proofMult, commitmentMult)
	fmt.Println("Mul num proof: ", ret)
	ret, err = PedersenVerify(commitmentMult, openingMult, 1000)
	fmt.Println("Mul num commit: ", ret)

	randomOpening, err := PedersenRNG()
	if err != nil {
		panic(err)
	}
	commitmentRandom, err := PedersenCommitSpecificOpening(100, randomOpening)
	if err != nil {
		panic(err)
	}
	ret, err = PedersenVerify(commitmentRandom, randomOpening, 100)
	fmt.Println("random commitment: ", ret)

	commitment0, opening0, err := PedersenCommitRandomOpening(0)
	if err != nil {
		panic(err)
	}
	commitment0Neg, err := PedersenNeg(commitment0)
	if err != nil {
		panic(err)
	}
	opening0Neg, err := PedersenNegOpening(opening0)
	if err != nil {
		panic(err)
	}
	ret, err = PedersenVerify(commitment0Neg, opening0Neg, 0)
	fmt.Println("Negated commitment: ", ret)
}
