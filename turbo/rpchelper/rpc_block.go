// Copyright 2024 The Erigon Authors
// This file is part of Erigon.
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package rpchelper

import (
	"fmt"

	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/kv"

	"github.com/erigontech/erigon/core/rawdb"
	"github.com/erigontech/erigon/eth/stagedsync/stages"
	"github.com/erigontech/erigon/rpc"
)

var UnknownBlockError = &rpc.CustomError{
	Code:    -39001,
	Message: "Unknown block",
}

func GetLatestBlockNumber(tx kv.Tx) (uint64, error) {
	headHash := rawdb.ReadHeadBlockHash(tx)
	headNumber := rawdb.ReadHeaderNumber(tx, headHash)
	if headNumber == nil {
		return 0, fmt.Errorf("getting latest block number: head is not set")
	}

	// On PoS networks, the forkchoice head is the latest block that has been finalized.
	// Only exception is when syncing (header updated but the rest have not yet), in which case we use the head block instead.
	forkchoiceHeadHash := rawdb.ReadForkchoiceHead(tx)
	if forkchoiceHeadHash != (libcommon.Hash{}) {
		forkchoiceHeadNum := rawdb.ReadHeaderNumber(tx, forkchoiceHeadHash)
		if forkchoiceHeadNum != nil && *forkchoiceHeadNum <= *headNumber {
			return *forkchoiceHeadNum, nil
		}
	}

	return *headNumber, nil
}

func GetFinalizedBlockNumber(tx kv.Tx) (uint64, error) {
	forkchoiceFinalizedHash := rawdb.ReadForkchoiceFinalized(tx)
	if forkchoiceFinalizedHash != (libcommon.Hash{}) {
		forkchoiceFinalizedNum := rawdb.ReadHeaderNumber(tx, forkchoiceFinalizedHash)
		if forkchoiceFinalizedNum != nil {
			return *forkchoiceFinalizedNum, nil
		}
	}

	return 0, UnknownBlockError
}

func GetSafeBlockNumber(tx kv.Tx) (uint64, error) {
	forkchoiceSafeHash := rawdb.ReadForkchoiceSafe(tx)
	if forkchoiceSafeHash != (libcommon.Hash{}) {
		forkchoiceSafeNum := rawdb.ReadHeaderNumber(tx, forkchoiceSafeHash)
		if forkchoiceSafeNum != nil {
			return *forkchoiceSafeNum, nil
		}
	}
	return 0, UnknownBlockError
}

func GetLatestExecutedBlockNumber(tx kv.Tx) (uint64, error) {
	blockNum, err := stages.GetStageProgress(tx, stages.Execution)
	if err != nil {
		return 0, err
	}
	return blockNum, err
}
