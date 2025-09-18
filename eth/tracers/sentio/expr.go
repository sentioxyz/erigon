package sentio

import (
	"fmt"
	"strconv"
	"strings"

	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon/core/tracing"
	"github.com/erigontech/erigon/core/vm"
	"github.com/holiman/uint256"
)

const (
	OpEq      string = "=="
	OpNeq     string = "!="
	OpAnd     string = "&&"
	OpOr      string = "||"
	OpVmOp    string = "$op"
	OpStack   string = "$stack"
	OpCaller  string = "$caller"
	OpOrigin  string = "$origin"
	OpLiteral string = "$literal"
)

var (
	FuncOpArgCount = map[string]int{
		OpVmOp:    0,
		OpStack:   1,
		OpCaller:  0,
		OpOrigin:  0,
		OpLiteral: 1,
	}
	BinaryOps = map[string]func(string, string) string{
		OpEq:  func(a, b string) string { return boolToString(a == b) },
		OpNeq: func(a, b string) string { return boolToString(a != b) },
		OpAnd: func(a, b string) string { return boolToString(a == "true" && b == "true") },
		OpOr:  func(a, b string) string { return boolToString(a == "true" || b == "true") },
	}
)

type Expr struct {
	Left  *Expr
	Right *Expr
	Op    string
	Args  []string
}

type EvalCtx struct {
	Op     vm.OpCode
	Scope  tracing.OpContext
	Origin libcommon.Address
	Debug  bool
}

func (e *Expr) Eval(ctx *EvalCtx) (ret string, err error) {
	if ctx.Debug {
		defer func() {
			fmt.Println(FormatExpr(e), ":", ret, err)
		}()
	}
	if f, ok := BinaryOps[e.Op]; ok {
		l, err := e.Left.Eval(ctx)
		if err != nil {
			return "", err
		}
		r, err := e.Right.Eval(ctx)
		if err != nil {
			return "", err
		}
		return f(l, r), nil
	}
	switch e.Op {
	case OpLiteral:
		if len(e.Args) == 0 {
			return "", fmt.Errorf("not enough arguments to %s", e.Op)
		}
		return e.Args[0], nil
	case OpStack:
		if len(e.Args) == 0 {
			return "", fmt.Errorf("not enough arguments to %s", e.Op)
		}
		stack := ctx.Scope.StackData()
		idx, err := strconv.Atoi(e.Args[0])
		if err != nil {
			return "", err
		}
		if idx >= len(stack) {
			return "", fmt.Errorf("stack index out of bounds: %d", idx)
		}
		return stack[len(stack)-idx].Hex(), nil
	case OpVmOp:
		return ctx.Op.String(), nil
	case OpCaller:
		t := uint256.Int{}
		t.SetBytes(ctx.Scope.Caller().Bytes())
		return t.Hex(), nil
	case OpOrigin:
		t := uint256.Int{}
		t.SetBytes(ctx.Origin.Bytes())
		return t.Hex(), nil
	default:
		return "", fmt.Errorf("unknown op %s", e.Op)
	}
}

func FormatExpr(expr *Expr) string {
	if expr == nil {
		return ""
	}
	ops := expr.Op
	if len(expr.Args) > 0 {
		ops = fmt.Sprintf("%s(%s)", expr.Op, strings.Join(expr.Args, ", "))
	}
	if expr.Left == nil && expr.Right == nil {
		return ops
	}
	return fmt.Sprintf("(%s %s %s)", FormatExpr(expr.Left), expr.Op, FormatExpr(expr.Right))
}

func ParseExpr(expr string) (*Expr, error) {
	expr = strings.ReplaceAll(expr, " ", "")
	return parse(expr)
}

func parse(expr string) (*Expr, error) {
	errInvalidExpr := fmt.Errorf("invalid expression %q", expr)
	if expr[0] == '(' {
		s := 0
		for i := 0; i < len(expr); i++ {
			if expr[i] == '(' {
				s++
			} else if expr[i] == ')' {
				s--
			}
			if s == 0 {
				if i == len(expr)-1 {
					return parse(expr[1:i])
				}
				for op := range BinaryOps {
					if !strings.HasPrefix(expr[i+1:], op) {
						continue
					}
					left, err := parse(expr[1:i])
					if err != nil {
						return nil, err
					}
					t := strings.TrimPrefix(expr[i+1:], op)
					if t[0] != '(' || t[len(t)-1] != ')' {
						return nil, errInvalidExpr
					}
					right, err := parse(t[1 : len(t)-1])
					if err != nil {
						return nil, err
					}
					return &Expr{
						Left:  left,
						Right: right,
						Op:    op,
					}, nil
				}
				return nil, errInvalidExpr
			}
		}
		return nil, errInvalidExpr
	}

	for op, argCnt := range FuncOpArgCount {
		if !strings.HasPrefix(expr, op) {
			continue
		}

		if argCnt == 0 {
			if expr != op {
				return nil, errInvalidExpr
			}
			return &Expr{
				Op: op,
			}, nil
		}

		if expr[len(op)] != '(' || expr[len(expr)-1] != ')' {
			return nil, errInvalidExpr
		}
		args := strings.Split(expr[len(op)+1:len(expr)-1], ",")
		if len(args) != argCnt {
			return nil, errInvalidExpr
		}
		return &Expr{
			Op:   op,
			Args: args,
		}, nil
	}
	return nil, errInvalidExpr
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
