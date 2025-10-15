package sentio

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/erigontech/erigon-lib/common"
	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/hexutil"
	"github.com/erigontech/erigon-lib/common/math"
	"github.com/erigontech/erigon-lib/crypto"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/erigontech/erigon/core/tracing"
	"github.com/erigontech/erigon/core/vm"
	"github.com/erigontech/erigon/core/vm/evmtypes"
	"github.com/erigontech/erigon/eth/tracers"
	"github.com/erigontech/erigon/execution/abi"
	"github.com/erigontech/erigon/execution/types"
	"github.com/holiman/uint256"
)

type functionInfo struct {
	address       string
	Name          string `json:"name"`
	SignatureHash string `json:"signatureHash"`

	Pc           uint64 `json:"pc"`
	InputSize    int    `json:"inputSize"`
	InputMemory  bool   `json:"inputMemory"`
	OutputSize   int    `json:"outputSize"`
	OutputMemory bool   `json:"outputMemory"`
}

type sentioTracerConfig struct {
	Functions         map[string][]functionInfo `json:"functions"`
	Calls             map[string][]uint64       `json:"calls"`
	Debug             bool                      `json:"debug"`
	WithInternalCalls bool                      `json:"withInternalCalls"`
	WithStorage       bool                      `json:"withStorage"`
	WithStorageKeys   bool                      `json:"withStorageKeys"`
	ExtraCaptureRules []string                  `json:"extraCaptureRules"`
}

func newSentioTracer(name string, ctx *tracers.Context, cfg json.RawMessage) (*tracers.Tracer, error) {
	if name != "sentioTracer" {
		return nil, errors.New("not sentioTracer")
	}

	var config sentioTracerConfig
	var extraCaptureRules []*Expr
	functionMap := map[string]map[uint64]functionInfo{}
	callMap := map[string]map[uint64]bool{}

	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}

		for address, functions := range config.Functions {
			checkSumAddress := libcommon.HexToAddress(address).String()
			functionMap[checkSumAddress] = make(map[uint64]functionInfo)

			for _, function := range functions {
				function.address = checkSumAddress
				functionMap[checkSumAddress][function.Pc] = function
			}
		}

		for address, calls := range config.Calls {
			checkSumAddress := libcommon.HexToAddress(address).String()
			callMap[checkSumAddress] = make(map[uint64]bool)

			for _, call := range calls {
				callMap[checkSumAddress][call] = true
			}
		}

		for _, rule := range config.ExtraCaptureRules {
			expr, err := ParseExpr(rule)
			if err != nil {
				return nil, err
			}
			extraCaptureRules = append(extraCaptureRules, expr)
		}
	}

	t := &sentioTracer{
		ctx:               ctx,
		config:            config,
		functionMap:       functionMap,
		callMap:           callMap,
		entryPc:           map[uint64]bool{},
		extraCaptureRules: extraCaptureRules,
	}
	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.CaptureStart,
			OnTxEnd:   t.CaptureTxEnd,
			OnEnter:   t.CaptureEnter,
			OnExit:    t.CaptureExit,
			OnOpcode:  t.CaptureState,
		},
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

func init() {
	tracers.RegisterLookup(false, newSentioTracer)
}

type Trace struct {
	//	only in debug mode
	Name string `json:"name,omitempty"`

	Type string `json:"type"`
	Pc   uint64 `json:"pc"`
	// Global index of the trace
	StartIndex int `json:"startIndex"`
	EndIndex   int `json:"endIndex"`

	// Gas remaining before the OP
	Gas math.HexOrDecimal64 `json:"gas"`
	// Gas for the entire call
	GasUsed math.HexOrDecimal64 `json:"gasUsed"`

	From *libcommon.Address `json:"from,omitempty"`
	// Used by call
	To *libcommon.Address `json:"to,omitempty"`
	// Input
	Input string `json:"input,omitempty"` // TODO better struct it and make it bytes
	// Ether transfered
	Value *hexutil.Big `json:"value,omitempty"`
	// Return for calls
	Output   hexutil.Bytes `json:"output,omitempty"`
	Error    string        `json:"error,omitempty"`
	Revertal string        `json:"revertReason,omitempty"`

	// Used by jump
	InputStack   []uint256.Int `json:"inputStack,omitempty"`
	InputMemory  *[]string     `json:"inputMemory,omitempty"`
	OutputStack  []uint256.Int `json:"outputStack,omitempty"`
	OutputMemory *[]string     `json:"outputMemory,omitempty"`
	FunctionPc   uint64        `json:"functionPc,omitempty"`

	// Used by log
	Address     *libcommon.Address `json:"address,omitempty"`
	CodeAddress *libcommon.Address `json:"codeAddress,omitempty"`
	Data        hexutil.Bytes      `json:"data,omitempty"`

	Topics []libcommon.Hash `json:"topics,omitempty"`

	// Used by sload/sstore
	StorageAddress *libcommon.Address `json:"storageAddress,omitempty"`
	StorageSlot    *libcommon.Hash    `json:"storageSlot,omitempty"`
	StorageValue   *libcommon.Hash    `json:"storageValue,omitempty"`

	StorageKeys []StorageKey `json:"storageKeys,omitempty"`

	// Only used by root
	Traces []Trace `json:"traces,omitempty"`

	// used by custom capture
	MatchRuleIds []int         `json:"matchRuleIds,omitempty"`
	Stack        []uint256.Int `json:"stack,omitempty"`
	Memory       *[]string     `json:"memory,omitempty"`

	// Use for internal call stack organization
	// The jump to go into the function
	//enterPc uint64
	exitPc uint64

	// the function get called
	function *functionInfo
}

type StorageKey struct {
	Address     libcommon.Address  `json:"address"`
	CodeAddress *libcommon.Address `json:"codeAddress"`
	BaseSlot    libcommon.Hash     `json:"baseSlot"`
	KeySlot     libcommon.Hash     `json:"keySlot"`
	Key         libcommon.Hash     `json:"key"`
}

type Receipt struct {
	Nonce            uint64          `json:"nonce"`
	TxHash           *libcommon.Hash `json:"transactionHash,omitempty"`
	BlockNumber      *hexutil.Big    `json:"blockNumber,omitempty"`
	BlockHash        *libcommon.Hash `json:"blockHash,omitempty"`
	TransactionIndex uint            `json:"transactionIndex"`
	GasPrice         *hexutil.Big    `json:"gasPrice,omitempty"`
}

type sentioTracer struct {
	config            sentioTracerConfig
	env               *tracing.VMContext
	ctx               *tracers.Context
	functionMap       map[string]map[uint64]functionInfo
	callMap           map[string]map[uint64]bool
	receipt           Receipt
	refund            uint64
	activePrecompiles []common.Address // Updated on CaptureStart based on given rules
	origin            common.Address

	previousJump *Trace
	index        int
	entryPc      map[uint64]bool

	callstack []Trace
	gasLimit  uint64

	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption

	extraCaptureRules []*Expr
}

func (t *sentioTracer) CaptureTxEnd(receipt *types.Receipt, err error) {
	if err != nil {
		return
	}
	if receipt == nil {
		panic("tx success but receipt is nil")
	}
	if len(t.callstack) == 0 {
		return
	}
	t.callstack[0].EndIndex = t.index
	t.callstack[0].GasUsed = math.HexOrDecimal64(receipt.GasUsed)
	if t.callstack[0].StartIndex == -1 {
		// It's possible that we can't correctly locate the PC that match the entry function (check why), in this case we need to 0 for the user
		t.callstack[0].StartIndex = 0
	}
}

func (t *sentioTracer) CaptureStart(env *tracing.VMContext, tx types.Transaction, from common.Address) {
	t.gasLimit = tx.GetGasLimit()
	t.origin = from
	to := tx.GetTo()
	data := tx.GetData()
	value := tx.GetValue()
	create := tx.IsContractDeploy()

	t.env = env
	blockContext := evmtypes.BlockContext{
		BlockNumber: env.BlockNumber,
		Time:        env.Time,
	}
	rules := blockContext.Rules(env.ChainConfig)
	t.activePrecompiles = vm.ActivePrecompiles(rules)

	t.receipt.TxHash = &t.ctx.TxHash
	t.receipt.BlockHash = &t.ctx.BlockHash
	t.receipt.TransactionIndex = uint(t.ctx.TxIndex)
	t.receipt.BlockNumber = (*hexutil.Big)(big.NewInt(int64(env.BlockNumber)))
	t.receipt.GasPrice = (*hexutil.Big)(env.GasPrice.ToBig())
	nonce, _ := t.env.IntraBlockState.GetNonce(from)
	t.receipt.Nonce = nonce - 1

	root := Trace{
		StartIndex: -1,
		Type:       vm.CALL.String(),
		From:       &from,
		To:         to,
		Gas:        math.HexOrDecimal64(t.gasLimit),
		Input:      hexutil.Bytes(data).String(),
	}
	if value != nil {
		root.Value = (*hexutil.Big)(value.ToBig())
	}
	if create {
		root.Type = vm.CREATE.String()
	}

	if !create && !t.isPrecompiled(to) && len(data) >= 4 {
		m, ok := t.functionMap[to.String()]
		if ok {
			sigHash := "0x" + common.Bytes2Hex(data[0:4])
			for pc, fn := range m {
				if fn.SignatureHash == sigHash {
					t.entryPc[pc] = true
				}
			}
			//log.Info(fmt.Sprintf("entry pc match %s (%d times) ", sigHash, len(t.entryPc)))
		}
	}
	t.callstack = append(t.callstack, root)
}

func (t *sentioTracer) isPrecompiled(addr *common.Address) bool {
	if addr == nil {
		return false
	}
	for _, p := range t.activePrecompiles {
		if p == *addr {
			return true
		}
	}
	return false
}

func (t *sentioTracer) captureEnd(output []byte, usedGas uint64, err error, reverted bool) {
	t.callstack[0].EndIndex = t.index
	t.callstack[0].GasUsed = math.HexOrDecimal64(usedGas)
	t.callstack[0].Output = common.CopyBytes(output)

	stackSize := len(t.callstack)
	t.popStack(1, output, uint64(t.callstack[stackSize-1].Gas)-usedGas, err)

	t.callstack[0].processError(output, err)
}

func (t *sentioTracer) CaptureEnter(depth int, typByte byte, from common.Address, to common.Address, precompile bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		return
	}

	typ := vm.OpCode(typByte)
	if depth == 0 && typ != vm.CREATE && typ != vm.CREATE2 {
		return
	}
	if typ == vm.CALL || typ == vm.CALLCODE {
		// After enter, make the assumped transfer as function call
		topElementTraces := t.callstack[len(t.callstack)-1].Traces
		call := topElementTraces[len(topElementTraces)-1]
		topElementTraces = topElementTraces[:len(topElementTraces)-1]
		t.callstack[len(t.callstack)-1].Traces = topElementTraces
		t.callstack = append(t.callstack, call)
	}

	size := len(t.callstack)

	t.callstack[size-1].From = &from
	t.callstack[size-1].To = &to
	t.callstack[size-1].Input = hexutil.Bytes(input).String()
	t.callstack[size-1].Gas = math.HexOrDecimal64(gas)

	if value != nil {
		t.callstack[size-1].Value = (*hexutil.Big)(value.ToBig())
	}
}

func (t *sentioTracer) CaptureExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		t.captureEnd(output, gasUsed, err, reverted)
		return
	}
	size := len(t.callstack)
	if size <= 1 {
		return
	}

	//log.Info(fmt.Sprintf("CaptureExit pop frame %s", t.callstack[size-1].Type))

	stackSize := len(t.callstack)
	for i := stackSize - 1; i >= 0; i-- {
		if t.callstack[i].function != nil {
			continue
		}

		//if stackSize-i > 1 {
		//	log.Info(fmt.Sprintf("tail call optimization [external] size %d", stackSize-i))
		//}

		call := &t.callstack[i]
		//call.EndIndex = t.index
		//call.GasUsed = math.HexOrDecimal64(usedGas)
		call.processError(output, err)

		t.popStack(i, output, uint64(call.Gas)-gasUsed, err)
		return
	}

	log.Error(fmt.Sprintf("failed to pop stack"))
}

func (t *sentioTracer) popStack(to int, output []byte, currentGas uint64, err error) { // , scope *vm.ScopeContext
	stackSize := len(t.callstack)
	for j := stackSize - 1; j >= to; j-- {
		t.callstack[j].Output = common.CopyBytes(output)
		t.callstack[j].EndIndex = t.index
		t.callstack[j].GasUsed = math.HexOrDecimal64(uint64(t.callstack[j].Gas) - currentGas)

		// TODO consider pass scopeContext so that popStack also record this
		//if t.callstack[j].function != nil {
		//	t.callstack[j].OutputStack = copyStack(scope.Stack, t.callstack[j].function.OutputSize)
		//	if t.callstack[j].function.OutputMemory {
		//		t.callstack[j].OutputMemory = formatMemory(scope.Memory)
		//	}
		//}
		//if err != nil {
		//	t.callstack[j].Error = err.Error()
		//}
		t.callstack[j-1].Traces = append(t.callstack[j-1].Traces, t.callstack[j])
	}

	t.callstack = t.callstack[:to]
}

func (t *sentioTracer) CaptureState(pc uint64, opByte byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	op := vm.OpCode(opByte)
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		return
	}
	t.index++

	if t.callstack[0].StartIndex == -1 && t.entryPc[pc] {
		//fillback the index and PC for root
		t.callstack[0].Pc = pc
		t.callstack[0].StartIndex = t.index - 1
		t.previousJump = nil
		return
	}

	var mergeBase = func(trace Trace) Trace {
		trace.Pc = pc
		trace.Type = op.String()
		trace.Gas = math.HexOrDecimal64(gas)
		trace.StartIndex = t.index - 1
		trace.EndIndex = t.index

		// Assume it's single instruction, adjust it for jump and call
		trace.GasUsed = math.HexOrDecimal64(cost)
		if err != nil {
			// set error for instruction
			trace.Error = err.Error()
		}
		return trace
	}

	stack := scope.StackData()
	stackBack := func(i int) *uint256.Int {
		return &stack[len(stack)-1-i]
	}

	// TODO need test
	addr := scope.Address()
	codeAddress := scope.CodeAddress()

	switch op {
	case vm.CALL, vm.CALLCODE:
		call := mergeBase(Trace{})
		call.Gas = math.HexOrDecimal64(stackBack(0).Uint64())
		call.From = &addr
		// TODO need test
		call.CodeAddress = codeAddress
		to := common.BigToAddress(stackBack(1).ToBig())
		call.To = &to
		call.Value = (*hexutil.Big)(stackBack(2).ToBig())

		v, _ := uint256.FromBig(call.Value.ToInt())
		if !v.IsZero() {
			balance, _ := t.env.IntraBlockState.GetBalance(addr)
			canTransfer := balance.Cmp(v) >= 0
			if !canTransfer {
				if call.Error == "" {
					call.Error = "insufficient funds for transfer"
				}
			}
		}

		// Treat this call as pure transfer until it enters the CaptureEnter
		t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, call)
	case vm.CREATE, vm.CREATE2, vm.DELEGATECALL, vm.STATICCALL, vm.SELFDESTRUCT:
		// more info to be add at CaptureEnter
		call := mergeBase(Trace{})
		t.callstack = append(t.callstack, call)
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		topicCount := int(op - vm.LOG0)
		logOffset := stackBack(0)
		logSize := stackBack(1)
		if logOffset.Uint64()+logSize.Uint64() > uint64(len(scope.MemoryData())) {
			log.Error("logOffset overflow", "tx", t.env.TxHash)
		}
		data := copyMemory(scope.MemoryData(), logOffset.Uint64(), logSize.Uint64())
		var topics []common.Hash
		//stackLen := scope.Stack.Len()
		for i := 0; i < topicCount; i++ {
			topics = append(topics, stackBack(2+i).Bytes32())
		}
		l := mergeBase(Trace{
			Address:     &addr,
			CodeAddress: codeAddress,
			Data:        data,
			Topics:      topics,
		})
		t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, l)
	case vm.JUMP:
		if !t.config.WithInternalCalls {
			break
		}

		jump := mergeBase(Trace{
			From:        codeAddress,
			CodeAddress: codeAddress,
			//InputStack: append([]uint256.Int(nil), scope.Stack.Data...), // TODO only need partial
		})
		if t.previousJump != nil {
			log.Error("Unexpected previous jump", t.previousJump)
		}
		if err == nil {
			t.previousJump = &jump
		} else {
			log.Error("error in jump", "err", err)
			// error happend, attach to current frame
			t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, jump)
		}
	case vm.JUMPDEST:
		if !t.config.WithInternalCalls {
			break
		}
		from := addr
		fromStr := from.String()

		if t.previousJump != nil { // vm.JumpDest and match with a previous jump (otherwise it's a jumpi)
			defer func() {
				t.previousJump = nil
			}()
			// Check if this is return
			// TODO pontentially maintain a map for fast filtering
			//log.Info("fromStr" + fromStr + ", callstack size" + fmt.Sprint(len(t.callStack)))
			stackSize := len(t.callstack)

			// Part 1: try process the trace as function call exit
			for i := stackSize - 1; i >= 0; i-- {
				// process internal call within the same contract
				// no function info means another external call
				functionInfo := t.callstack[i].function
				if functionInfo == nil {
					break
				}

				if functionInfo.address != fromStr {
					break
				}

				// find a match
				if t.callstack[i].exitPc == pc {
					// find a match, pop the stack, copy memory if needed

					//if stackSize-i > 1 {
					//	log.Info(fmt.Sprintf("tail call optimization size %d", stackSize-i))
					//}

					// TODO maybe don't need return all
					for j := stackSize - 1; j >= i; j-- {
						call := &t.callstack[j]
						functionJ := call.function
						call.EndIndex = t.index - 1 // EndIndex should before the jumpdest
						call.GasUsed = math.HexOrDecimal64(uint64(t.callstack[j].Gas) - gas)
						if functionJ.OutputSize > len(stack) {
							log.Error(fmt.Sprintf("stack size not enough (%d vs %d) for function %s %s. pc: %d",
								len(stack), functionJ.OutputSize, functionJ.address, functionJ.Name, pc))
							if err == nil {
								log.Error("stack size not enough has error", "err", err)
							}
						} else {
							call.OutputStack = copyStack(stack, t.callstack[j].function.OutputSize)
						}
						if call.function.OutputMemory {
							call.OutputMemory = formatMemory(scope.MemoryData())
						}
						//if err != nil {
						//	call.Error = err.Error()
						//}
						t.callstack[j-1].Traces = append(t.callstack[j-1].Traces, *call)
					}
					t.callstack = t.callstack[:i]
					return
				}
			}

			// Part 2: try process the trace as function call entry
			funcInfo := t.getFunctionInfo(fromStr, pc)
			//log.Info("function info" + fmt.Sprint(funcInfo))

			if funcInfo != nil {
				// filter those jump are not call site
				if !t.isCall(t.previousJump.From.String(), t.previousJump.Pc) {
					return
				}

				if funcInfo.InputSize >= len(stack) {
					// TODO this check should not needed after frist check
					log.Error("Unexpected stack size for function:" + fmt.Sprint(funcInfo) + ", stack" + fmt.Sprint(stack))
					log.Error("previous jump" + fmt.Sprint(*t.previousJump))
					return
				}

				// confirmed that we are in an internal call
				//t.internalCallStack = append(t.internalCallStack, internalCallStack{
				//	enterPc:  t.previousJump.Pc,
				//	exitPc:   scope.Stack.Back(funcInfo.InputSize).Uint64(),
				//	function: funcInfo,
				//})
				//jump.enterPc = t.previousJump.Pc
				t.previousJump.exitPc = stackBack(funcInfo.InputSize).Uint64()
				t.previousJump.function = funcInfo
				t.previousJump.FunctionPc = pc
				t.previousJump.InputStack = copyStack(stack, funcInfo.InputSize)
				if t.config.Debug {
					t.previousJump.Name = funcInfo.Name
				}
				if funcInfo.InputMemory {
					t.previousJump.InputMemory = formatMemory(scope.MemoryData())
				}
				t.callstack = append(t.callstack, *t.previousJump)
			}
		}
	case vm.REVERT:
		if !t.config.WithInternalCalls {
			break
		}
		logOffset := stackBack(0)
		logSize := stackBack(1)
		output := scope.MemoryData()[logOffset.Uint64() : logOffset.Uint64()+logSize.Uint64()]
		//data := copyMemory(logOffset, logSize)

		trace := mergeBase(Trace{
			Output: output,
			Error:  "execution reverted",
		})
		if unpacked, err := abi.UnpackRevert(output); err == nil {
			trace.Revertal = unpacked
		}
		t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, trace)
	case vm.SLOAD, vm.SSTORE:
		if !t.config.WithStorage {
			break
		}
		slot := libcommon.Hash(stackBack(0).Bytes32())
		var val libcommon.Hash
		if op == vm.SLOAD {
			var v uint256.Int
			_ = t.env.IntraBlockState.GetState(addr, slot, &v)
			val = v.Bytes32()
		} else {
			val = stackBack(1).Bytes32()
		}
		trace := mergeBase(Trace{
			StorageAddress: &addr,
			CodeAddress:    codeAddress,
			StorageSlot:    &slot,
			StorageValue:   &val,
		})
		t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, trace)
	// FIXME TLOAD/TSTORE
	//case vm.TLOAD, vm.TSTORE:
	//	if !t.config.WithStorage {
	//		break
	//	}
	//	slot := libcommon.Hash(stackBack(0).Bytes32())
	//	var val libcommon.Hash
	//	if op == vm.TLOAD {
	//		v := t.env.IntraBlockState.GetTransientState(addr, slot)
	//		val = v.Bytes32()
	//	} else {
	//		val = scope.Stack.Back(1).Bytes32()
	//	}
	//	trace := mergeBase(Trace{
	//		StorageAddress: &addr,
	//		CodeAddress:    &codeAddress,
	//		StorageSlot:    &slot,
	//		StorageValue:   &val,
	//	})
	//	t.callstack[len(t.callstack)-1].Traces = append(t.callstack[len(t.callstack)-1].Traces, trace)
	case vm.KECCAK256:
		if !t.config.WithStorageKeys {
			break
		}
		size := stackBack(1)
		if size.Uint64() == 64 {
			offset := stackBack(0)
			rawkey := copyMemory(scope.MemoryData(), offset.Uint64(), 64)

			// only cares 64 bytes for mapping key
			hashOfKey := crypto.Keccak256(rawkey)
			key := common.Hash(rawkey[:32])
			baseSlot := common.Hash(rawkey[32:])
			valueSlot := common.Hash(hashOfKey)
			t.callstack[len(t.callstack)-1].StorageKeys = append(t.callstack[len(t.callstack)-1].StorageKeys, StorageKey{
				Address:     addr,
				CodeAddress: codeAddress,
				BaseSlot:    baseSlot,
				KeySlot:     valueSlot,
				Key:         key,
			})
		}
	default:
		frame := &t.callstack[len(t.callstack)-1]
		evalEnv := &EvalCtx{
			Scope:  scope,
			Op:     op,
			Origin: t.origin,
			Debug:  t.config.Debug,
		}

		var matchRuleIds []int
		for i, rule := range t.extraCaptureRules {
			ret, err := rule.Eval(evalEnv)
			if err != nil {
				continue
			}
			if ret == "true" {
				matchRuleIds = append(matchRuleIds, i)
			}
		}
		if len(matchRuleIds) > 0 {
			frame.Traces = append(frame.Traces, mergeBase(Trace{
				MatchRuleIds: matchRuleIds,
				Stack:        copyStack(scope.StackData(), len(scope.StackData())),
				Memory:       formatMemory(scope.MemoryData()),
			}))
		}
		if !t.config.WithInternalCalls {
			break
		}
		if err != nil {
			// Error happen, attach the error OP if not already processed
			frame.Traces = append(frame.Traces, mergeBase(Trace{}))
		}
	}
}

func (t *sentioTracer) GetResult() (json.RawMessage, error) {
	type RootTrace struct {
		Trace
		TracerConfig *sentioTracerConfig `json:"tracerConfig,omitempty"`
		Receipt      Receipt             `json:"receipt"`
		Refund       hexutil.Uint64      `json:"refund"`
	}
	root := RootTrace{
		Trace:   t.callstack[0],
		Receipt: t.receipt,
		Refund:  hexutil.Uint64(t.refund),
	}

	if t.config.Debug {
		root.TracerConfig = &t.config
	}

	if len(t.callstack) != 1 {
		log.Error("callstack length is not 1, is " + fmt.Sprint(len(t.callstack)))
	}

	res, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return res, t.reason
}

func (t *sentioTracer) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}

func (t *sentioTracer) getFunctionInfo(address string, pc uint64) *functionInfo {
	m, ok := t.functionMap[address]
	if !ok || m == nil {
		return nil
	}
	info, ok := m[pc]
	if ok {
		return &info
	}

	return nil
}

func (t *sentioTracer) isCall(address string, pc uint64) bool {
	m, ok := t.callMap[address]
	if !ok || m == nil {
		return false
	}
	info, ok := m[pc]
	if ok {
		return info
	}
	return false
}

// Only used in non detail mode
func (f *Trace) processError(output []byte, err error) {
	//output = common.CopyBytes(output)
	if err == nil {
		//f.Output = output
		return
	}
	f.Error = err.Error()
	if f.Type == vm.CREATE.String() || f.Type == vm.CREATE2.String() {
		f.To = &libcommon.Address{}
	}
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) == 0 {
		return
	}
	//f.Output = output
	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.Revertal = unpacked
	}
}

func copyMemory(m []byte, offset uint64, size uint64) hexutil.Bytes {
	// it's important to get copy
	res := make([]byte, size)
	copy(res, m[offset:offset+size])
	return res
}

func formatMemory(m []byte) *[]string {
	res := make([]string, 0, (len(m)+31)/32)
	for i := 0; i+32 <= len(m); i += 32 {
		res = append(res, fmt.Sprintf("%x", m[uint64(i):uint64(i)+32]))
	}
	return &res
}

func copyStack(s []uint256.Int, copySize int) []uint256.Int {
	if copySize == 0 {
		return nil
	}
	stackSize := len(s)
	res := make([]uint256.Int, stackSize)
	for i := stackSize - copySize; i < stackSize; i++ {
		res[i] = s[i]
	}
	return res
}
