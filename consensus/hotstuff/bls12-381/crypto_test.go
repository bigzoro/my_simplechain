package bls

import (
	"encoding/hex"
	"testing"

	bls12381 "github.com/kilic/bls12-381"
	"gotest.tools/assert"
)

func TestPrimitiveSign(t *testing.T) {
	privkey := GeneratePrivateKey()
	msg := []byte("primitive signing test")

	compressed := bls12381.NewG1().ToCompressed(privkey.Public().point)
	t.Log(hex.EncodeToString(compressed), len(compressed))

	sig, _ := sign(privkey.sec, msg)
	assert.Equal(t, true, verify(privkey.Public().point, msg, sig))
}

func TestPrimitiveAggregate(t *testing.T) {
	msg := []byte("primitive signing test ")

	pointg1 := make([]*bls12381.PointG1, 0, 10)
	pointg2 := make([]*bls12381.PointG2, 0, 10)
	for i := 0; i < 10; i++ {
		privkey := GeneratePrivateKey()
		sig, _ := sign(privkey.sec, msg)
		pointg1 = append(pointg1, privkey.Public().point)
		pointg2 = append(pointg2, sig)
	}

	assert.Equal(t, true, fastAggregateVerify(msg, combine(pointg2...), pointg1...))
}
