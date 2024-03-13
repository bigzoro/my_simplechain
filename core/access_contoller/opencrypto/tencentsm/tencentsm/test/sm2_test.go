//nolint
package test

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker/common/v2/opencrypto/tencentsm/tencentsm"

	"github.com/stretchr/testify/assert"

	. "github.com/smartystreets/goconvey/convey"
)

func TestVersion(t *testing.T) {
	Convey("TestVersion not nil", t, func() {
		ret := tencentsm.Version()
		So(ret, ShouldNotBeNil)

	})
}

func TestInitCtx(t *testing.T) {
	Convey("TestInitCtx init ctx", t, func() {
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		fmt.Println(ctx.Context)
		So(ctx.Context, ShouldNotBeNil)

	})
}

func TestSM2InitCtxWithPubKey(t *testing.T) {
	Convey("SM2InitCtxWithPubKey And free", t, func() {
		pubkey := []byte("0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtxWithPubKey(&ctx, pubkey)
		So(ctx.Context, ShouldNotBeNil)
		tencentsm.SM2FreeCtx(&ctx)
	})
}

func TestGeneratePrivateKey(t *testing.T) {
	Convey("generatePrivateKey", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var ret = tencentsm.GeneratePrivateKey(&ctx, prikey[:])
		fmt.Println(prikey)
		So(ret, ShouldNotBeNil)
	})
}

func TestGeneratePublicKey(t *testing.T) {
	Convey("GeneratePublicKey", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var ret = tencentsm.GeneratePrivateKey(&ctx, prikey[:])
		So(ret, ShouldBeZeroValue)
		fmt.Println(prikey)
		var pubkey [131]byte
		ret = tencentsm.GeneratePublicKey(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		So(ret, ShouldBeZeroValue)
	})
}

func TestSM2(t *testing.T) {
	Convey("GenerateKeyPair and encrypt decrypt sign verify", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		var ret = tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		So(ret, ShouldBeZeroValue)
		plaintext := []byte("tencent")
		fmt.Printf("plaintext:%s\n", string(plaintext))
		var out [131]byte
		outlen := len(out)
		tencentsm.SM2Encrypt(&ctx, plaintext, len(plaintext), pubkey[:], len(pubkey), out[:], &outlen)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		tencentsm.SM2Decrypt(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))
		//签名&验签
		id := []byte("123456")
		ret = tencentsm.SM2Sign(&ctx, plaintext, len(plaintext), id, len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("sign:%x\n", out[:outlen])
		ret = tencentsm.SM2Verify(&ctx, plaintext, len(plaintext), id, len(id), out[:outlen], outlen, pubkey[:], len(pubkey))
		fmt.Printf("verify:%d\n", ret)
		So(ret, ShouldBeZeroValue)
	})
}

func BenchmarkSM2(b *testing.B) {
	var prikey [65]byte
	var ctx tencentsm.SM2_ctx_t
	tencentsm.SM2InitCtx(&ctx)
	var pubkey [131]byte
	var ret = tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
	fmt.Println(pubkey)
	fmt.Println(prikey)
	plaintext := []byte("tencent")
	fmt.Printf("plaintext:%s\n", string(plaintext))
	var out [131]byte
	outlen := len(out)
	id := []byte("123456")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var ctx2 tencentsm.SM2_ctx_t
			tencentsm.SM2InitCtx(&ctx2)
			//签名&验签
			ret = tencentsm.SM2Sign(&ctx2, plaintext, len(plaintext), id, len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen)
			assert.Equal(b, 0, ret)
			fmt.Printf("sign:%x\n", out[:outlen])
			ret = tencentsm.SM2Verify(&ctx2, plaintext, len(plaintext), id, len(id), out[:outlen], outlen, pubkey[:], len(pubkey))
			fmt.Printf("verify:%d\n", ret)
			assert.Equal(b, 0, ret)
		}
	})

}

func TestSM2Mode1(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C3C2_ASN1 success, sign two mode test", t, func() {
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		var prikey [65]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))
		id := []byte("123456")
		//outlen = 131
		ret = tencentsm.SM2SignWithMode(&ctx, in, len(in), id[:], len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2SignMode_RS_ASN1)
		So(ret, ShouldBeZeroValue)
		ret = tencentsm.SM2VerifyWithMode(&ctx, in, len(in), id[:], len(id), out[:], outlen, pubkey[:], len(pubkey), tencentsm.SM2SignMode_RS_ASN1)
		So(ret, ShouldBeZeroValue)
		ret = tencentsm.SM2SignWithMode(&ctx, in, len(in), id[:], len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2SignMode_RS_ASN1)
		So(ret, ShouldBeZeroValue)
		ret = tencentsm.SM2VerifyWithMode(&ctx, in, len(in), id[:], len(id), out[:], outlen, pubkey[:], len(pubkey), tencentsm.SM2SignMode_RS)
		So(ret, ShouldNotBeZeroValue)
		ret = tencentsm.SM2SignWithMode(&ctx, in, len(in), id[:], len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2SignMode_RS)
		So(ret, ShouldBeZeroValue)
		ret = tencentsm.SM2VerifyWithMode(&ctx, in, len(in), id[:], len(id), out[:], outlen, pubkey[:], len(pubkey), tencentsm.SM2SignMode_RS_ASN1)
		So(ret, ShouldNotBeZeroValue)
		ret = tencentsm.SM2SignWithMode(&ctx, in, len(in), id[:], len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2SignMode_RS)
		So(ret, ShouldBeZeroValue)
		ret = tencentsm.SM2VerifyWithMode(&ctx, in, len(in), id[:], len(id), out[:], outlen, pubkey[:], len(pubkey), tencentsm.SM2SignMode_RS)
		So(ret, ShouldBeZeroValue)
	})
}

func BenchmarkSM2Mode1(b *testing.B) {
	var ctx tencentsm.SM2_ctx_t
	tencentsm.SM2InitCtx(&ctx)
	var pubkey [131]byte
	var prikey [65]byte
	tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
	fmt.Println(pubkey)
	fmt.Println(prikey)
	in := []byte("hello world")
	var out [131]byte
	outlen := len(out)
	id := []byte("123456")
	//outlen = 131
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var ctx2 tencentsm.SM2_ctx_t
			tencentsm.SM2InitCtx(&ctx2)

			ret := tencentsm.SM2SignWithMode(&ctx, in, len(in), id[:], len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2SignMode_RS_ASN1)
			assert.Equal(b, 0, ret)
			ret = tencentsm.SM2VerifyWithMode(&ctx, in, len(in), id[:], len(id), out[:], outlen, pubkey[:], len(pubkey), tencentsm.SM2SignMode_RS_ASN1)
			assert.Equal(b, 0, ret)
		}
	})
}

func TestSM2Mode2(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C3C2_ASN1 failed", t, func() {
		var prikey [65]byte
		var pubkey [131]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2)
		So(ret, ShouldNotBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode3(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C3C2 success", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode4(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C3C2 failed", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldNotBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode5(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C2C3_ASN1 success", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode6(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C2C3_ASN1 failed", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3_ASN1)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldNotBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode7(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C2C3 success", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2Mode8(t *testing.T) {
	Convey("base. mode SM2CipherMode_C1C2C3 failed", t, func() {
		var prikey [65]byte
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		var pubkey [131]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		in := []byte("hello world")
		var out [131]byte
		outlen := len(out)
		ret := tencentsm.SM2EncryptWithMode(&ctx, in, len(in), pubkey[:], len(pubkey), out[:], &outlen, tencentsm.SM2CipherMode_C1C2C3)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("encrypt:%x\n", out[:outlen])
		ret = tencentsm.SM2DecryptWithMode(&ctx, out[:outlen], outlen, prikey[:], len(prikey), out[:], &outlen, tencentsm.SM2CipherMode_C1C3C2_ASN1)
		So(ret, ShouldNotBeZeroValue)
		fmt.Printf("decrypt:%s\n", string(out[:outlen]))

	})
}

func TestSM2RandomSign(t *testing.T) {
	Convey("base. sign with input random", t, func() {
		var ctx tencentsm.SM2_ctx_t
		tencentsm.SM2InitCtx(&ctx)
		//random := []byte("12345609876")
		//base.SM2SetRandomDataCtx(&ctx, random[:])
		//ret := base.IsSM2CtxRandomDataVaild(&ctx)
		//So(ret, ShouldBeZeroValue)
		// var ret = base.SM2ReSeed(&ctx, random[:], len(random))
		// So(ret, ShouldBeZeroValue)
		var pubkey [131]byte
		var prikey [65]byte
		tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
		fmt.Println(pubkey)
		fmt.Println(prikey)
		plaintext := []byte("tencent")
		fmt.Printf("plaintext:%s\n", string(plaintext))
		var out [131]byte
		outlen := len(out)
		//签名&验签
		id := []byte("123456")
		ret := tencentsm.SM2Sign(&ctx, plaintext, len(plaintext), id, len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen)
		So(ret, ShouldBeZeroValue)
		fmt.Printf("sign:%x\n", out[:outlen])
		ret = tencentsm.SM2Verify(&ctx, plaintext, len(plaintext), id, len(id), out[:outlen], outlen, pubkey[:], len(pubkey))
		fmt.Printf("verify:%d\n", ret)
		So(ret, ShouldBeZeroValue)
	})
}

/**
func SM2GenerateCSR(ctx *SM2_cert_ctx_t, country_name []byte, province []byte, locality_name []byte, organization_name []byte,
	organization_unit_name []byte, common_name []byte, email []byte, challenge_password []byte, public_key []byte,
	private_key []byte, temp_public_key []byte, out []byte, outlen *int, mode SM2CSRMode) int {
	return int(C.SM2GenerateCSR(&ctx.Context, (*C.char)(unsafe.Pointer(&country_name[0])),
		(*C.char)(unsafe.Pointer(&province[0])), (*C.char)(unsafe.Pointer(&locality_name[0])),
		(*C.char)(unsafe.Pointer(&organization_name[0])), (*C.char)(unsafe.Pointer(&organization_unit_name[0])),
		(*C.char)(unsafe.Pointer(&common_name[0])), (*C.char)(unsafe.Pointer(&email[0])),
		(*C.char)(unsafe.Pointer(&challenge_password[0])), (*C.char)(unsafe.Pointer(&public_key[0])),
		(*C.char)(unsafe.Pointer(&private_key[0])), (*C.char)(unsafe.Pointer(&temp_public_key[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.int)(unsafe.Pointer(outlen)), ConvertSM2CsrModeToC(mode)))
}
**/

func BenchmarkSigning(b *testing.B) {
	var prikey [65]byte
	var ctx tencentsm.SM2_ctx_t
	tencentsm.SM2InitCtx(&ctx)
	var pubkey [131]byte
	var ret = tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])

	if ret != 0 {
		b.Fatal("can't GenerateKeyPair")
	}
	plaintext := []byte("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345")
	id := []byte("123456")
	var out [131]byte
	outlen := len(out)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ret = tencentsm.SM2Sign(&ctx, plaintext, len(plaintext), id, len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen)
		if ret != 0 {
			b.Fatal("can't GenerateKeyPair")
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	var prikey [65]byte
	var ctx tencentsm.SM2_ctx_t
	tencentsm.SM2InitCtx(&ctx)
	var pubkey [131]byte
	var ret = tencentsm.GenerateKeyPair(&ctx, prikey[:], pubkey[:])
	if ret != 0 {
		b.Fatal("can't GenerateKeyPair")
	}

	plaintext := []byte("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345")
	var out [131]byte
	outlen := len(out)
	//签名&验签
	id := []byte("123456")
	ret = tencentsm.SM2Sign(&ctx, plaintext, len(plaintext), id, len(id), pubkey[:], len(pubkey), prikey[:], len(prikey), out[:], &outlen)
	if ret != 0 {
		b.Fatal("can't GenerateKeyPair")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ret = tencentsm.SM2Verify(&ctx, plaintext, len(plaintext), id, len(id), out[:outlen], outlen, pubkey[:], len(pubkey))
		if ret != 0 {
			b.Fatal("can't GenerateKeyPair")
		}
	}
}
