package bls

import (
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

var (
	domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

	// the order r of G1
	curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
)

func subgroupCheck(point *bls12381.PointG2) bool {
	g2, p := bls12381.NewG2(), new(bls12381.PointG2)
	g2.MulScalarBig(p, point, curveOrder)
	return g2.IsZero(p)
}

func sign(sec *big.Int, msg []byte) (*bls12381.PointG2, error) {
	g2 := bls12381.NewG2()
	point, err := g2.HashToCurve(msg, domain)
	if err != nil {
		return nil, err
	}
	g2.MulScalarBig(point, point, sec)
	return point, nil
}

func verify(pub *bls12381.PointG1, msg []byte, sig *bls12381.PointG2) bool {
	if !subgroupCheck(sig) {
		return false
	}
	g2 := bls12381.NewG2()
	point, err := g2.HashToCurve(msg, domain)
	if err != nil {
		return false
	}
	engine := bls12381.NewEngine()
	engine.AddPairInv(&bls12381.G1One, sig)
	engine.AddPair(pub, point)
	return engine.Result().IsOne()
}

func fastAggregateVerify(msg []byte, sig *bls12381.PointG2, pubs ...*bls12381.PointG1) bool {
	engine, aggregate := bls12381.NewEngine(), new(bls12381.PointG1)
	for _, pub := range pubs {
		engine.G1.Add(aggregate, aggregate, pub)
	}
	return verify(aggregate, msg, sig)
}

func combine(sigs ...*bls12381.PointG2) *bls12381.PointG2 {
	g2, aggregate := bls12381.NewG2(), new(bls12381.PointG2)
	for _, sig := range sigs {
		g2.Add(aggregate, aggregate, sig)
	}
	return aggregate
}
