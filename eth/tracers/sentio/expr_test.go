package sentio

import (
	"testing"

	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon/core/vm"
	"github.com/erigontech/erigon/core/vm/stack"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
)

func TestEval(t *testing.T) {
	raw := "((($op) == ($literal(SUB))) || (($op) == ($literal(EQ)))) && (((($stack(0)) == ($caller)) && (($stack(1)) == ($origin))) || ((($stack(0)) == ($origin)) && (($stack(1)) == ($caller))))"

	e, err := ParseExpr(raw)
	assert.NoError(t, err)
	assert.NotNil(t, e)

	ctx1 := &EvalCtx{
		Op:     vm.EQ,
		Origin: libcommon.HexToAddress("0xe86142af1321eaac4270422081c1EdA31eEcFf0c"),
		Scope: &vm.ScopeContext{
			Stack: &stack.Stack{
				Data: []uint256.Int{
					*uint256.MustFromHex("0xe86142af1321eaac4270422081c1EdA31eEcFf0c"),
					*uint256.MustFromHex("0xe86142af1321eaac4270422081c1EdA31eEcFf00"),
				},
			},
			Contract: &vm.Contract{
				CallerAddress: libcommon.HexToAddress("0xe86142af1321eaac4270422081c1EdA31eEcFf00"),
			},
		},
	}
	ret, err := e.Eval(ctx1)
	assert.NoError(t, err)
	assert.Equal(t, ret, "true")

	ctx2 := &EvalCtx{
		Op:     vm.EQ,
		Origin: libcommon.HexToAddress("0xe86142af1321eaac4270422081c1EdA31eEcFf0c"),
		Scope: &vm.ScopeContext{
			Stack: &stack.Stack{
				Data: []uint256.Int{
					*uint256.MustFromHex("0xe86142af1321eaac4270422081c1EdA31eEcFf0c"),
					*uint256.MustFromHex("0xe86142af1321eaac4270422081c1EdA31eEcFf01"),
				},
			},
			Contract: &vm.Contract{
				CallerAddress: libcommon.HexToAddress("0xe86142af1321eaac4270422081c1EdA31eEcFf00"),
			},
		},
	}
	ret, err = e.Eval(ctx2)
	assert.NoError(t, err)
	assert.Equal(t, ret, "false")
}
