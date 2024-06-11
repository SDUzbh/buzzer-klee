// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	pb "buzzer/proto/ebpf_go_proto"
	"fmt"
)

var (
	UnknownOperationCodeType = fmt.Errorf("Unknown operation error type")
	UnknownOpcodeType        = fmt.Errorf("Unknown opcode type")
)

type Src interface {
	pb.Reg | int32 | int | int64
}

func encodeAluJmpOpcode(opcode, insClass, source uint8) (uint8, error) {
	result := uint8(0)

	// The 3 least significant bits are the instruction class.
	result |= (insClass & 0x07)

	// The fourth bit is the source operand.
	result |= (source & 0x08)

	// Finally the 4 MSB are the operation code.
	result |= (opcode & 0xF0)

	return result, nil
}

func encodeMemOpcode(op *pb.MemOpcode) (uint8, error) {
	opcode := uint8(0)

	// The 3 LSB are the instruction class.
	opcode |= (uint8(op.InstructionClass) & 0x07)

	// The next 2 bits are the size
	opcode |= (uint8(op.Size) & 0x18)

	// The 3 most significant bits are the mode
	opcode |= (uint8(op.Mode) & 0xE0)

	return opcode, nil
}

// EncodeInstructions transforms the given array to ebpf bytecode.
func EncodeInstructions(program *pb.Program) ([]uint64, error) {
	result := []uint64{}
	for _, instruction := range program.Instructions {
		encoding, err := encodeInstruction(instruction)
		if err != nil {
			return nil, err
		}
		result = append(result, encoding...)
	}
	return result, nil
}

// To understand what each part of the encoding mean, please refer to
// http://shortn/_mFOBeQLg2s.
func encodeInstruction(i *pb.Instruction) ([]uint64, error) {
	encoding := uint64(0)

	opcode := uint8(0)
	var err error

	switch c := i.Opcode.(type) {
	case *pb.Instruction_AluOpcode:
		op := uint8(c.AluOpcode.OperationCode)
		insClass := uint8(c.AluOpcode.InstructionClass)
		src := uint8(c.AluOpcode.Source)
		opcode, err = encodeAluJmpOpcode(op, insClass, src)
		if err != nil {
			return nil, err
		}
	case *pb.Instruction_JmpOpcode:
		op := uint8(c.JmpOpcode.OperationCode)
		insClass := uint8(c.JmpOpcode.InstructionClass)
		src := uint8(c.JmpOpcode.Source)
		opcode, err = encodeAluJmpOpcode(op, insClass, src)
		if err != nil {
			return nil, err
		}
	case *pb.Instruction_MemOpcode:
		opcode, err = encodeMemOpcode(c.MemOpcode)
		if err != nil {
			return nil, err
		}
	default:
		return nil, UnknownOpcodeType
	}

	// The first 8 bits are the opcode.
	encoding |= uint64(opcode)

	// The LSB of the registers portion of the encoding is the destination
	// register.
	registers := uint8(uint8(i.DstReg) & 0x0F)

	// And the MSB are the source register.
	registers |= ((uint8(i.SrcReg) & 0x0F) << 4)

	encoding |= uint64(uint16(registers) << 8)

	encoding |= uint64(uint32(i.Offset) << 16)

	encoding |= (uint64(i.Immediate) << 32)

	result := []uint64{encoding}
	switch p := i.PseudoInstruction.(type) {
	case *pb.Instruction_PseudoValue:
		resultPseudoValue, err := encodeInstruction(p.PseudoValue)
		if err != nil {
			return nil, err
		}
		result = append(result, resultPseudoValue[0])
	}
	return result, nil
}

// GetBpfFuncName returns the C macro name of the provided bpf helper function.
func GetBpfFuncName(funcNumber int32) string {
	switch funcNumber {
	case MapLookup:
		return "BPF_FUNC_map_lookup_elem"
	default:
		return "unknown"
	}
}
