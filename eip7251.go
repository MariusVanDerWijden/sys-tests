package systest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

var code7251 = "0x3373fffffffffffffffffffffffffffffffffffffffe1460cf573615156028575f545f5260205ff35b366060141561019a5760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f821115608057810190830284830290049160010191906065565b90939004341061019a57600154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b5f5260605f60143760745fa0600101600355005b6003546002548082038060011160e3575060015b5f5b8181146101295780607402838201600402600401805490600101805490600101805490600101549260601b84529083601401528260340152906054015260010160e5565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b6001546001828201116101885750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd"

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
			offset := i * RECORD_SIZE
			addr_slot := int(head_idx.Uint64())*3 + offset + queue_offset
			address := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot)))).Bytes() // sload(addr[i])
			pk := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot+1)))).Bytes()    // sload(pk_0:32[i])
			pk_am := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(addr_slot+2)))).Bytes() // sload(pk2_am[i])
			memory = append(memory, address[12:32]...)
			memory = append(memory, pk...)
			memory = append(memory, pk_am[0:24]...)
			memory = append(memory, make([]byte, 20)...)
		}
		if head_idx.Uint64()+count == tail_idx.Uint64() {
			// reset queue
			state.SetState(addr, Uint64ToHash(uint64(queue_head)), common.Hash{}) // sstore(queue_head, 0)
			state.SetState(addr, Uint64ToHash(uint64(queue_tail)), common.Hash{}) // sstore(queue_tail, 0)
		} else {
			newHead := head_idx.Add(head_idx, big.NewInt(int64(count)))
			state.SetState(addr, Uint64ToHash(uint64(queue_tail)), common.BigToHash(newHead)) // sstore(queue_head, new_head)
		}
		// update new excess withdrawal requests
		excess := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))).Bytes()) // sload(queue_head)
		if excess.Uint64() == 1181 {
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
		return nil, memory, nil
	} else {
		if len(calldata) == 0 {
			excess_reqs := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))) // sload(excess_reqs)
			return excess_reqs[:], nil, nil
		} else {
			if len(calldata) != 96 {
				return nil, nil, errors.New("invalid size")
			}
			excess_reqs := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_excess)))) // sload(excess_reqs)
			req_fee := calcReqFee(big.NewInt(1), new(big.Int).SetBytes(excess_reqs.Bytes()), big.NewInt(17))
			if value.Cmp(req_fee) < 0 {
				return nil, nil, errors.New("to little fee")
			}
			// request can pay, increment withdrawal count
			req_count := state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(slot_count)))) // sload(slot_count)
			newCount := new(big.Int).Add(new(big.Int).SetBytes(req_count[:]), common.Big1)
			state.SetState(addr, Uint64ToHash(uint64(slot_count)), common.BigToHash(newCount)) // sstore(slot_count, newCount)
			fmt.Printf("Setting %x to %x\n", Uint64ToHash(uint64(slot_count)), common.BigToHash(newCount))
			// insert req into queue
			tail_idx := new(big.Int).SetBytes(state.GetState(addr, common.BytesToHash(binary.BigEndian.AppendUint32([]byte{}, uint32(queue_tail)))).Bytes()) // sload(queue_tail)
			slot := new(big.Int).Add(new(big.Int).Mul(tail_idx, big.NewInt(3)), big.NewInt(queue_offset))                                                    // 3 * tail_idx + queue_offset
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(caller.Bytes()))                                                                 // sstore(slot, caller)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(caller.Bytes()))
			slot = slot.Add(slot, common.Big1)                                               // slot += 1
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(calldata[0:32])) // sstore(slot, pk[0:32])
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(calldata[0:32]))
			slot = slot.Add(slot, common.Big1)                                                                                                                 // slot += 1
			state.SetState(addr, common.BigToHash(slot), common.BytesToHash(append(calldata[32:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))) // sstore(slot, pk[32:48]..amount)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(slot), common.BytesToHash(calldata[32:]))
			// assemble log data
			var logData []byte
			logData = append(logData, caller.Bytes()...)
			logData = append(logData, calldata...)
			// store queue tail
			tail_idx.Add(tail_idx, big.NewInt(1))
			state.SetState(addr, common.BigToHash(big.NewInt(queue_tail)), common.BytesToHash(tail_idx.Bytes())) // sstore(slot, pk[32:48]..amount)
			fmt.Printf("Setting %x to %x\n", common.BigToHash(big.NewInt(queue_tail)), common.BytesToHash(tail_idx.Bytes()))
			return nil, logData, nil
		}
	}
}
