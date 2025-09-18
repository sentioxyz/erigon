package common

import "github.com/erigontech/erigon-lib/common/hexutil"

type SentioTraceConfig struct {
	IgnoreGas             bool                                 // set gas costs to 0
	IgnoreCodeSizeLimit   bool                                 // cancel code size limit for creates
	TxOriginOverride      *Address                             // override tx.orgin
	MockFunctions         map[Address]map[string]hexutil.Bytes // contract address => function selector => return data
	CallerOverride        map[Address]map[string]Address       // caller address => function selector => new caller
	CreationOverrides     map[Address]CreationOverride         // original address => override
	CreateAddressOverride *Address
}

type CreationOverride struct {
	NewAddress *Address
	NewCode    hexutil.Bytes
}
