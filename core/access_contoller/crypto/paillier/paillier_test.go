/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package paillier

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// plaintext
	p1          *big.Int
	p10         *big.Int
	p_10        *big.Int
	p_15        *big.Int
	p20         *big.Int
	p_20        *big.Int
	p0          *big.Int
	pMax        *big.Int
	pMaxPlusOne *big.Int
	pMin        *big.Int
	pMixSubOne  *big.Int
	bigOne      *big.Int
	bigTwo      *big.Int
	bigNegOne   *big.Int
	bigZero     *big.Int

	// ciphertext
	c10          *Ciphertext
	c_10         *Ciphertext
	c_15         *Ciphertext
	c20          *Ciphertext
	c0           *Ciphertext
	cMax         *Ciphertext
	cMin         *Ciphertext
	cBigOne      *Ciphertext
	cBigTwo      *Ciphertext
	cBigNegOne   *Ciphertext
	cBigZero     *Ciphertext
	cBigMax      *Ciphertext
	c10_testKey2 *Ciphertext
	// ciphertext
	cEmpty = "" // nolint: varcheck

	// key
	prv1                *PrvKey
	pub1                *PubKey
	prv2                *PrvKey
	pub2                *PubKey
	prvKeyFromUnmarshal *PrvKey
	pubKeyFromUnmarshal *PubKey
	// keyBytes
	prvBytes  []byte
	prv2Bytes []byte
	pubBytes  []byte
)

func BenchmarkPaillier(b *testing.B) {

	bP10, _ := new(big.Int).SetString("10", 10)
	bP20, _ := new(big.Int).SetString("20", 10)
	for n := 0; n < b.N; n++ {

		prv, _ := GenKey()
		pub, _ := prv.GetPubKey()
		bC10, err := pub.Encrypt(bP10)
		if err != nil {
			return
		}

		add, err := pub.AddPlaintext(bC10, bP20)
		if err != nil {
			return
		}

		_, err = prv.Decrypt(add)
		if err != nil {
			return
		}
	}
}

func TestPaillier(t *testing.T) {
	fmt.Printf("=================================init=================================\n")
	testInitPlaintext(t)

	// Construct Key
	fmt.Printf("=============================Gen Key & Marshal & Unmarshal=============================\n")
	testGenKey(t)

	fmt.Printf("====================================Encrypt2Ciphertext Marshal & Unmarshal====================================\n")
	testEncrypt(t)

	fmt.Printf("====================================Decrypt test====================================\n")
	testDecrypt(t)

	fmt.Printf("====================================AddCiphertext test====================================\n")
	testAddCiphertext(t)

	fmt.Printf("====================================AddPlaintext test====================================\n")
	testAddPlaintext(t)

	fmt.Printf("====================================SubCiphertext test====================================\n")
	testSubCiphertext(t)

	fmt.Printf("====================================SubPlaintext test====================================\n")
	testSubPlaintext(t)

	fmt.Printf("====================================NumMul test====================================\n")
	testNumMul(t)

	fmt.Printf("====================================Boundary test====================================\n")
	testBoundary(t)

	fmt.Printf("===================================== Bug test ====================================\n")
	testBug(t)

}

func testInitPlaintext(t *testing.T) {
	p10, _ = new(big.Int).SetString("10", 10)
	p_10, _ = new(big.Int).SetString("-10", 10)
	p_15, _ = new(big.Int).SetString("-15", 10)
	p20, _ = new(big.Int).SetString("20", 10)
	p_20, _ = new(big.Int).SetString("-20", 10)
	p0, _ = new(big.Int).SetString("0", 10)
	pMax, _ = new(big.Int).SetString("9223372036854775807", 10)
	pMaxPlusOne, _ = new(big.Int).SetString("9223372036854775808", 10)
	pMin, _ = new(big.Int).SetString("-9223372036854775808", 10)
	pMixSubOne, _ = new(big.Int).SetString("-9223372036854775809", 10)
	p1, _ = new(big.Int).SetString("1", 10)
	bigOne, _ = new(big.Int).SetString("1", 10)
	bigTwo, _ = new(big.Int).SetString("2", 10)
	bigNegOne, _ = new(big.Int).SetString("-1", 10)
	bigZero, _ = new(big.Int).SetString("0", 10)
}

func testGenKey(t *testing.T) {
	var err error
	prv1, err = GenKey()
	require.Nil(t, err)

	pub1, err = prv1.GetPubKey()
	require.Nil(t, err)

	prv2, err = GenKey()
	require.Nil(t, err)

	pub2, err = prv2.GetPubKey()
	require.Nil(t, err)

	_, err = new(PrvKey).GetPubKey()
	require.EqualError(t, err, ErrInvalidPrivateKey.Error())

	pubBytes, err = pub1.Marshal()
	require.Nil(t, err)

	_, err = new(PubKey).Marshal()
	require.EqualError(t, err, ErrInvalidPublicKey.Error())

	fmt.Printf("pubBytes -> %s\n", pubBytes)
	prvBytes, err = prv1.Marshal()
	require.Nil(t, err)
	fmt.Printf("prvBytes -> %s\n", prvBytes)

	_, err = new(PrvKey).Marshal()
	require.EqualError(t, err, ErrInvalidPrivateKey.Error())

	prv2, err = GenKey()
	require.Nil(t, err)
	prv2Bytes, err = prv2.Marshal()
	require.Nil(t, err)

	pubKeyFromUnmarshal = new(PubKey)
	err = pubKeyFromUnmarshal.Unmarshal(pubBytes)
	require.Nil(t, err)

	err = pubKeyFromUnmarshal.Unmarshal(nil)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())

	err = new(PubKey).Unmarshal(pubBytes)
	require.Nil(t, err)

	prvKeyFromUnmarshal = new(PrvKey)

	err = prvKeyFromUnmarshal.Unmarshal(prvBytes)
	require.Nil(t, err)

	err = new(PrvKey).Unmarshal(nil)
	require.EqualError(t, err, ErrInvalidPrivateKey.Error())

	err = new(PrvKey).Unmarshal([]byte("啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊aaaaaaaa"))
	require.EqualError(t, err, ErrInvalidPrivateKey.Error())

	err = new(PrvKey).Unmarshal(prvBytes)
	require.Nil(t, err)
	//require.EqualError(t, err, ErrInvalidPrivateKey.Error())

	new(big.Int).Bytes()
	new(big.Int).SetBytes(nil)
}

func testEncrypt(t *testing.T) {
	var err error
	// Encrypt 10, -15, 20, 0
	c10 = new(Ciphertext)
	c10, err = pub1.Encrypt(p10)
	require.Nil(t, err)
	c_10, err = pub1.Encrypt(p_10)
	require.Nil(t, err)
	c_15, err = pub1.Encrypt(p_15)
	require.Nil(t, err)
	c20, err = pub1.Encrypt(p20)
	require.Nil(t, err)
	c0, err = pub1.Encrypt(p0)
	require.Nil(t, err)
	cMax, err = pub1.Encrypt(pMax)
	require.Nil(t, err)
	cMin, err = pub1.Encrypt(pMin)
	// Encrypt BigInt
	var bigMax *big.Int
	bigZero, _ = new(big.Int).SetString("0", 10)
	bigOne, _ = new(big.Int).SetString("1", 10)
	bigTwo, _ = new(big.Int).SetString("2", 10)
	bigNegOne, _ = new(big.Int).SetString("-1", 10)
	bigMax, _ = new(big.Int).SetString("9223372036854775807", 10)
	cBigZero, err = pub1.Encrypt(bigZero)
	require.Nil(t, err)
	cBigOne, err = pub1.Encrypt(bigOne)
	require.Nil(t, err)
	cBigTwo, err = pub1.Encrypt(bigTwo)
	require.Nil(t, err)
	cBigNegOne, err = pub1.Encrypt(bigNegOne)
	require.Nil(t, err)
	cBigMax, err = pub1.Encrypt(bigMax)

	c10Bytes, err := c10.Marshal()
	require.Nil(t, err)

	c_ := new(Ciphertext)
	_, err = c_.Marshal()
	require.EqualError(t, err, "paillier: invalid ciphertext")

	err = c10.Unmarshal(c10Bytes)
	require.Nil(t, err)

	err = c10.Unmarshal(nil)
	require.EqualError(t, err, ErrInvalidCiphertext.Error())

	_, err = new(Ciphertext).GetChecksum()
	require.EqualError(t, err, ErrInvalidCiphertext.Error())

	_, err = new(Ciphertext).GetCtBytes()
	require.EqualError(t, err, ErrInvalidCiphertext.Error())

	_, err = new(Ciphertext).GetCtStr()
	require.EqualError(t, err, ErrInvalidCiphertext.Error())

	cBytes, err := c10.Marshal()
	require.Nil(t, err)
	err = new(Ciphertext).Unmarshal(cBytes)
	require.Nil(t, err)

	//var pubKeyBad Pub
	tests := []struct {
		pubKey  *PubKey
		pt      *big.Int
		wantErr string
	}{
		{
			pubKey:  new(PubKey),
			pt:      p10,
			wantErr: ErrInvalidPublicKey.Error(),
		},
		{
			pubKey:  pub1,
			pt:      nil,
			wantErr: ErrInvalidPlaintext.Error(),
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err = tt.pubKey.Encrypt(tt.pt)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func testDecrypt(t *testing.T) {
	// Decrypt 10, -15, 20, 0
	d10, err := prvKeyFromUnmarshal.Decrypt(c10)
	require.Nil(t, err)
	d_15, err := prvKeyFromUnmarshal.Decrypt(c_15)
	require.Nil(t, err)
	d20, err := prvKeyFromUnmarshal.Decrypt(c20)
	require.Nil(t, err)
	d0, err := prvKeyFromUnmarshal.Decrypt(c0)
	require.Nil(t, err)
	dMax, err := prvKeyFromUnmarshal.Decrypt(cMax)
	require.Nil(t, err)
	dMin, err := prvKeyFromUnmarshal.Decrypt(cMin)
	require.Nil(t, err)
	fmt.Printf("[ decrypt ciphertext 10 ] %d\n", d10)
	fmt.Printf("[ decrypt ciphertext _15 ] %d\n", d_15)
	fmt.Printf("[ decrypt ciphertext 20 ] %d\n", d20)
	fmt.Printf("[ decrypt ciphertext 0 ] %d\n", d0)
	fmt.Printf("[ decrypt ciphertext Max ] %d\n", dMax)
	fmt.Printf("[ decrypt ciphertext Min ] %d\n", dMin)

	// Decrypt big.Int
	dBigOne, err := prvKeyFromUnmarshal.Decrypt(cBigOne)
	require.Nil(t, err)
	dBigTwo, err := prvKeyFromUnmarshal.Decrypt(cBigTwo)
	require.Nil(t, err)
	fmt.Printf("[ decrytp ciphertext bigInt 1 ] %d\n", dBigOne)
	fmt.Printf("[ decrytp ciphertext bigInt 2 ] %d\n", dBigTwo)

	tests := []struct {
		prvKey  *PrvKey
		ct      *Ciphertext
		wantErr string
	}{
		{
			prvKey:  new(PrvKey),
			ct:      c10,
			wantErr: ErrInvalidPrivateKey.Error(),
		},
		{
			prvKey:  prv1,
			ct:      new(Ciphertext),
			wantErr: ErrInvalidCiphertext.Error(),
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err = tt.prvKey.Decrypt(tt.ct)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func testAddCiphertext(t *testing.T) {
	pubKey2FromUnmarshal := new(PubKey)

	rAddC10C20, err := pub1.AddCiphertext(c10, c20)
	require.Nil(t, err)

	checkPrvKey := new(PrvKey)
	err = checkPrvKey.Unmarshal(prvBytes)
	require.Nil(t, err)

	err = checkPrvKey.Unmarshal(prvBytes)
	require.Nil(t, err)

	err = checkPrvKey.Unmarshal(prv2Bytes)
	require.Nil(t, err)

	dRAddC10C20, err := prv1.Decrypt(rAddC10C20)
	require.Nil(t, err)
	fmt.Printf("[ c10 + c20] %d\n", dRAddC10C20)

	// operand verify
	rAddC10C_15, err := pub1.AddCiphertext(c10, c_15)
	require.Nil(t, err)

	ok := pubKey2FromUnmarshal.ChecksumVerify(rAddC10C_15)
	require.False(t, ok)

	ok = prv1.ChecksumVerify(nil)
	require.False(t, ok)

	dRAddC10C_15, err := prv1.Decrypt(rAddC10C_15)
	require.Nil(t, err)
	fmt.Printf("[ c10 + c(-15)] %d\n", dRAddC10C_15)

	// AddCiphertext
	rAddCBig, err := pub1.AddCiphertext(cBigOne, cBigTwo)
	require.Nil(t, err)
	dRAddCBig, err := prv1.Decrypt(rAddCBig)
	require.Nil(t, err)
	fmt.Printf("[ c1 + c2 ] %s\n", dRAddCBig.String())

	// 0
	// AddCiphertext
	rB3, err := pub1.AddCiphertext(cBigOne, cBigNegOne)
	require.Nil(t, err)
	dRB3, err := prv1.Decrypt(rB3)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%s\n", dRB3.String())
	// AddCiphertextStr
	rB4, err := pub1.AddCiphertext(c10, c_10)
	require.Nil(t, err)
	dRB4, err := prv1.Decrypt(rB4)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%d\n", dRB4)

	_, err = new(PubKey).AddCiphertext(c10, c20)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())

	c10_testKey2, err = pub2.Encrypt(p10)
	require.Nil(t, err)

	_, err = pub1.AddCiphertext(c10, c10_testKey2)
	require.EqualError(t, err, ErrInvalidMismatch.Error())

}

func testAddPlaintext(t *testing.T) {
	// AddPlaintext
	rAddC10P20, err := pub1.AddPlaintext(c10, p20)
	require.Nil(t, err)
	dRAddC10P20, err := prv1.Decrypt(rAddC10P20)
	require.Nil(t, err)
	fmt.Printf("[ c10 + p20] %d\n", dRAddC10P20)
	rAddC10P_15, _ := pub1.AddPlaintext(c10, p_15)
	dRAddC10P_15, err := prv1.Decrypt(rAddC10P_15)
	require.Nil(t, err)
	fmt.Printf("[ c10 + p(-15)] %d\n", dRAddC10P_15)

	// AddPlaintext
	rAddPlainCBig, err := pub1.AddPlaintext(cBigOne, bigTwo)
	require.Nil(t, err)
	dRAddPlainCBig, err := prv1.Decrypt(rAddPlainCBig)
	require.Nil(t, err)
	fmt.Printf("[ c1 + p2 ] %s\n", dRAddPlainCBig.String())

	// 0
	// AddPlaintextInt
	rB1, _ := pub1.AddPlaintext(c10, p_10)
	dRB1, err := prv1.Decrypt(rB1)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%d\n", dRB1)
	// AddPlaintext
	fmt.Printf("[ -1 ]%s\n", bigNegOne.String())
	rB2, _ := pub1.AddPlaintext(cBigOne, bigNegOne)
	dRB2, err := prv1.Decrypt(rB2)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%s\n", dRB2.String())

	_, err = new(PubKey).AddPlaintext(new(Ciphertext), nil)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())
	_, err = pub1.AddPlaintext(new(Ciphertext), p10)
	require.EqualError(t, err, ErrInvalidCiphertext.Error())
	_, err = pub1.AddPlaintext(c_10, nil)
	require.EqualError(t, err, ErrInvalidPlaintext.Error())
	_, err = pub1.AddPlaintext(c10_testKey2, p10)
	require.EqualError(t, err, ErrInvalidMismatch.Error())

}

func testSubCiphertext(t *testing.T) {
	// SubCiphertextWithString
	rSubC10C20, _ := pub1.SubCiphertext(c10, c20)
	dRSubC10C20, err := prv1.Decrypt(rSubC10C20)
	require.Nil(t, err)
	fmt.Printf("[ c10 - c20] %d\n", dRSubC10C20)

	rSubC10C_15, _ := pub1.SubCiphertext(c10, c_15)
	dRSubC10C_15, err := prv1.Decrypt(rSubC10C_15)
	require.Nil(t, err)
	fmt.Printf("[ c10 - c(-15)] %d\n", dRSubC10C_15)

	rSubC10C10, _ := pub1.SubCiphertext(c10, c10)
	dRSubC10C10, err := prv1.Decrypt(rSubC10C10)
	require.Nil(t, err)
	fmt.Printf("[ c10 - c100] %d\n", dRSubC10C10)

	// SubCiphertext
	rSubCBig, err := pub1.SubCiphertext(cBigOne, cBigTwo)
	require.Nil(t, err)
	dRSubCBig, err := prv1.Decrypt(rSubCBig)
	require.Nil(t, err)
	fmt.Printf("[ c1 - c2 ] %s\n", dRSubCBig.String())

	// 0
	// SubCiphertext
	rB5, err := pub1.SubCiphertext(cBigOne, cBigOne)
	require.Nil(t, err)
	dRB5, err := prv1.Decrypt(rB5)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%s\n", dRB5.String())
	// SubCiphertextStr
	rB6, err := pub1.SubCiphertext(c10, c10)
	require.Nil(t, err)
	dRB6, err := prv1.Decrypt(rB6)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%d\n", dRB6)

	_, err = new(PubKey).SubCiphertext(c10, c20)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())

	_, err = pub1.SubCiphertext(c10, new(Ciphertext))
	require.EqualError(t, err, ErrInvalidCiphertext.Error())

	c10_testKey2, err = pub2.Encrypt(p10)
	require.Nil(t, err)

	_, err = pub1.SubCiphertext(c10, c10_testKey2)
	require.EqualError(t, err, ErrInvalidMismatch.Error())

}

func testSubPlaintext(t *testing.T) {
	// SunPlaintext
	rSubC10P20, _ := pub1.SubPlaintext(c10, p20)
	//rSubC10P20, _ := prv1.SubPlaintextInt64(c10, 1)
	dRSubC10P20, err := prv1.Decrypt(rSubC10P20)
	require.Nil(t, err)
	fmt.Printf("[ c10 - p20] %d\n", dRSubC10P20)

	rSubC10P_15, _ := pub1.SubPlaintext(c10, p_15)
	dRSubC10P_15, err := prv1.Decrypt(rSubC10P_15)
	require.Nil(t, err)
	fmt.Printf("[ c10 - p(-15)] %d\n", dRSubC10P_15)

	rSubC10p10, _ := pub1.SubPlaintext(c10, p10)
	dRSubC10p10, err := prv1.Decrypt(rSubC10p10)
	require.Nil(t, err)
	fmt.Printf("[ c10 - p10] %d\n", dRSubC10p10)

	// SubPlaintext
	rSubPlainCBig, err := pub1.SubPlaintext(cBigOne, bigTwo)
	require.Nil(t, err)
	dRSubPlainCBig, err := prv1.Decrypt(rSubPlainCBig)
	require.Nil(t, err)
	fmt.Printf("[ c1 - p2 ] %s\n", dRSubPlainCBig.String())

	// 0
	// SubPlaintext
	rB7, err := pub1.SubPlaintext(cBigOne, bigOne)
	require.Nil(t, err)
	dRB7, err := prv1.Decrypt(rB7)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%s\n", dRB7.String())
	// SubPlaintextStr
	rB8, err := pub1.SubPlaintext(c10, p10)
	require.Nil(t, err)
	dRB8, err := prv1.Decrypt(rB8)
	require.Nil(t, err)
	fmt.Printf("[ 0 ]%d\n", dRB8)

	_, err = new(PubKey).SubPlaintext(new(Ciphertext), nil)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())
	_, err = pub1.SubPlaintext(new(Ciphertext), p10)
	require.EqualError(t, err, ErrInvalidCiphertext.Error())
	_, err = pub1.SubPlaintext(c_10, nil)
	require.EqualError(t, err, ErrInvalidPlaintext.Error())
	_, err = pub1.SubPlaintext(c10_testKey2, p10)
	require.EqualError(t, err, ErrInvalidMismatch.Error())
}

func testNumMul(t *testing.T) {
	// NumMulSimple test
	rMulC10P20, _ := pub1.NumMul(c10, p20)
	dRMulC10P20, err := prv1.Decrypt(rMulC10P20)
	require.Nil(t, err)
	fmt.Printf("[ c10 * p20] %d\n", dRMulC10P20)

	rMulC_15P20, _ := pub1.NumMul(c_15, p20)
	dRMulC_15P20, err := prv1.Decrypt(rMulC_15P20)
	require.Nil(t, err)
	fmt.Printf("[ c(-15) * p20] %d\n", dRMulC_15P20)

	rMulC_15P_20, _ := pub1.NumMul(c_15, p_20)
	dRMulC_15P_20, err := prv1.Decrypt(rMulC_15P_20)
	require.Nil(t, err)
	fmt.Printf("[ c(-15) * p(-20)] %d\n", dRMulC_15P_20)

	// NumMul
	rMulCBig, err := pub1.NumMul(cBigOne, bigTwo)
	require.Nil(t, err)
	dRMulCBig, err := prv1.Decrypt(rMulCBig)
	require.Nil(t, err)
	fmt.Printf("[ c1 * p2 ] %s\n", dRMulCBig.String())

	rMulCMax, err := pub1.NumMul(cBigMax, pMax)
	require.Nil(t, err)
	dRMulCMax, err := prv1.Decrypt(rMulCMax)
	require.Nil(t, err)
	fmt.Printf("[ cMax * cMax ] %s\n", dRMulCMax.String())

	// 0
	// NumMul
	rB9, err := pub1.NumMul(cBigOne, bigZero)
	require.Nil(t, err)
	dRB9, err := prv1.Decrypt(rB9)
	require.Nil(t, err)
	fmt.Printf("[ 0 ] %s\n", dRB9.String())
	rB11, err := pub1.NumMul(cBigZero, bigTwo)
	require.Nil(t, err)
	dRB11, err := prv1.Decrypt(rB11)
	require.Nil(t, err)
	fmt.Printf("[ 0 ] %s\n", dRB11.String())
	// NumMulInt64
	rB10, _ := pub1.NumMul(c_15, p0)
	dRB10, err := prv1.Decrypt(rB10)
	require.Nil(t, err)
	fmt.Printf("[ 0 ] %d\n", dRB10)

	// ciphertext * ciphertext
	rB12, err := pub1.NumMul(cBigTwo, p10)
	require.Nil(t, err)
	dRB12, err := prv1.Decrypt(rB12)
	require.Nil(t, err)
	fmt.Printf("[ c2 * p10] %s\n", dRB12.String())

	_, err = new(PubKey).NumMul(new(Ciphertext), nil)
	require.EqualError(t, err, ErrInvalidPublicKey.Error())
	_, err = pub1.NumMul(new(Ciphertext), p10)
	require.EqualError(t, err, ErrInvalidCiphertext.Error())
	_, err = pub1.NumMul(c_10, nil)
	require.EqualError(t, err, ErrInvalidPlaintext.Error())
	_, err = pub1.NumMul(c10_testKey2, p10)
	require.EqualError(t, err, ErrInvalidMismatch.Error())
}

func testBoundary(t *testing.T) {
	var err error
	rMulMax, _ := pub1.AddPlaintext(cMax, p1)
	_, err = prv1.Decrypt(rMulMax)
	require.Nil(t, err)

	rMulMin, _ := pub1.SubPlaintext(cMin, p1)
	_, err = prv1.Decrypt(rMulMin)
	require.Nil(t, err)
}

func testBug(t *testing.T) {
	var err error
	// empty ciphertext
	_, err = pub1.AddCiphertext(c10, new(Ciphertext))
	require.EqualError(t, err, "paillier: invalid ciphertext")

	_, err = prv1.Decrypt(new(Ciphertext))
	require.EqualError(t, err, "paillier: invalid ciphertext")

	pubBytes = append(pubBytes, []byte("啊")...)

	err = pubKeyFromUnmarshal.Unmarshal(pubBytes)
	require.EqualError(t, err, "paillier: invalid public key")
}
