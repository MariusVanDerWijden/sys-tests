package systest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/params"
)

var code7251 = "0x3373fffffffffffffffffffffffffffffffffffffffe1460cf573615156028575f545f5260205ff35b366060141561019a5760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f821115608057810190830284830290049160010191906065565b90939004341061019a57600154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b5f5260605f60143760745fa0600101600355005b6003546002548082038060011160e3575060015b5f5b8181146101295780607402838201600402600401805490600101805490600101805490600101549260601b84529083601401528260340152906054015260010160e5565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b6001546001828201116101885750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd"

const (
	RECORD_SIZE_7251 = 116
)

// https://github.com/lightclient/sys-asm/blob/main/src/withdrawals/main.eas
func testCode7251(caller common.Address, calldata []byte, value *big.Int, state *state.StateDB) ([]byte, []byte, error) {
	addr := common.HexToAddress(precompileAddress)

	if caller == common.Address(common.FromHex("0xfffffffffffffffffffffffffffffffffffffffe")) {
		tail_idx := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(queue_tail)))).Bytes()) // sload(queue_tail)
		head_idx := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(queue_head)))).Bytes()) // sload(queue_head)
		count := new(big.Int).Sub(tail_idx, head_idx).Uint64()
		if count > 16 {
			count = 16
		}
		var memory []byte
		for i := 0; i < int(count); i++ {
			offset := i * RECORD_SIZE_7251
			addr_slot := int(head_idx.Uint64())*4 + offset + queue_offset
			address := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot)))).Bytes()         // sload(addr[i])
			source := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot+1)))).Bytes()        // sload(pk_0:32[i])
			source_target := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot+2)))).Bytes() // sload(pk2_am[i])
			target := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot+3)))).Bytes()        // sload(pk2_am[i])
			memory = append(memory, address[12:32]...)
			memory = append(memory, source...)
			memory = append(memory, source_target...)
			memory = append(memory, target...)
			//memory = append(memory, make([]byte, 20)...)
		}
		if head_idx.Uint64()+count == tail_idx.Uint64() {
			// reset queue
			state.SetState(addr, Uint64ToHash(uint64(queue_head)), common.Hash{}) // sstore(queue_head, 0)
			state.SetState(addr, Uint64ToHash(uint64(queue_tail)), common.Hash{}) // sstore(queue_tail, 0)
		} else {
			newHead := head_idx.Add(head_idx, big.NewInt(int64(count)))
			state.SetState(addr, Uint64ToHash(uint64(queue_tail)), common.BigToHash(newHead)) // sstore(queue_head, new_head)
		}
		// update new excess consolidation requests
		excess := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))).Bytes()) // sload(queue_head)
		if bytes.Equal(excess.Bytes(), common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) {
			excess.SetUint64(0)
		}
		countSlot := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_count)))).Bytes()) // sload(slot_count)
		if excess.Uint64()+countSlot.Uint64() > 2 {
			// compute excess
			countExcess := countSlot.Add(countSlot, excess)
			countExcess.Sub(countExcess, big.NewInt(2))
			excess.Set(countExcess)
		} else {
			excess.SetUint64(0)
		}
		state.SetState(addr, Uint64ToHash(uint64(slot_excess)), common.BigToHash(excess))   // sstore(slot_excess, excess)
		state.SetState(addr, Uint64ToHash(uint64(slot_count)), common.BigToHash(countSlot)) // sstore(slot_count, countSlot)
		return memory, nil, nil
	} else {
		if len(calldata) == 0 {
			excess_reqs := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))) // sload(excess_reqs)
			return excess_reqs[:], nil, nil
		} else {
			if len(calldata) != 96 {
				return nil, nil, errors.New("invalid size")
			}
			excess_reqs := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))) // sload(excess_reqs)
			if bytes.Equal(excess_reqs.Bytes(), common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) {
				return nil, nil, errExcessInhibitorRevert
			}
			req_fee := calcReqFee(big.NewInt(1), new(big.Int).SetBytes(excess_reqs.Bytes()), big.NewInt(17))
			if value.Cmp(req_fee) < 0 {
				return nil, nil, errors.New("to little fee")
			}
			// request can pay, increment request count
			req_count := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_count)))) // sload(slot_count)
			newCount := new(big.Int).Add(new(big.Int).SetBytes(req_count[:]), common.Big1)
			state.SetState(addr, Uint64ToHash(uint64(slot_count)), common.BigToHash(newCount)) // sstore(slot_count, newCount)
			fmt.Printf("Setting %x to %x\n", Uint64ToHash(uint64(slot_count)), common.BigToHash(newCount))
			// insert req into queue
			tail_idx := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(queue_tail)))).Bytes()) // sload(queue_tail)
			slot := new(big.Int).Add(new(big.Int).Mul(tail_idx, big.NewInt(4)), big.NewInt(queue_offset))                                                    // 4 * tail_idx + queue_offset
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(caller.Bytes()))                                                                 // sstore(slot, caller)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(caller.Bytes()))
			slot = slot.Add(slot, common.Big1)                                               // slot += 1
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(calldata[0:32])) // sstore(slot, calldata[0:32])
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(calldata[0:32]))
			slot = slot.Add(slot, common.Big1)                                                // slot += 1
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(calldata[32:64])) // sstore(slot, calldata[32:64])
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(calldata[32:64]))
			slot = slot.Add(slot, common.Big1)                                              // slot += 1
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(calldata[64:])) // sstore(slot, pk[32:48]..amount)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(calldata[64:]))
			// assemble log data
			var logData []byte
			logData = append(logData, caller.Bytes()...)
			logData = append(logData, calldata...)
			// store queue tail
			tail_idx.Add(tail_idx, big.NewInt(1))
			state.SetState(addr, common.BigToHash(big.NewInt(queue_tail)), common.BytesToHash(tail_idx.Bytes())) // sstore(queue_tail, tail_idx)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(big.NewInt(queue_tail)), common.BytesToHash(tail_idx.Bytes()))
			return nil, logData, nil
		}
	}
}

func get7251(statedb, statedb2 *state.StateDB) {
	addr := common.HexToAddress(precompileAddress)
	store := common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")
	out, logs, err := testCode7251(store, []byte{}, new(big.Int), statedb)
	if err != nil {
		panic(err)
	}
	_ = logs

	logger := logger.NewMarkdownLogger(nil, os.Stdout)
	config := vm.Config{Tracer: logger}
	out2, _, err := runtime.Call(addr, []byte{}, &runtime.Config{ChainConfig: params.AllDevChainProtocolChanges, Origin: store, State: statedb2, Debug: true, EVMConfig: config})
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(out, out2) {
		panic(fmt.Sprintf("out missmatch %x\n%x\n", out, out2))
	}
}

func set7251(input []byte, value *big.Int, statedb, statedb2 *state.StateDB) error {
	addr := common.HexToAddress(precompileAddress)
	caller := common.HexToAddress("0x1")

	out, _, err1 := testCode7251(caller, input, value, statedb)

	logger := logger.NewMarkdownLogger(nil, os.Stdout)
	config := vm.Config{Tracer: logger}
	out2, _, err2 := runtime.Call(addr, input, &runtime.Config{ChainConfig: params.AllDevChainProtocolChanges, Origin: caller, Value: value, Time: 0, State: statedb2, Debug: true, EVMConfig: config})
	if err1 != nil && err2 != nil {
		// if we have two errors, return from our implementation, so we can check its the correct error
		return err1
	}
	if err1 != nil || err2 != nil {
		panic(fmt.Sprintf("%v%v", err1, err2))
	}
	if !bytes.Equal(out, out2) {
		panic(fmt.Sprintf("out missmatch %v \n%v\n", out, out2))
	}
	return nil
}
