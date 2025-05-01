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

package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
	pb "buzzer/proto/ebpf_go_proto"
)

// Generator is responsible for constructing the ebpf for this strategy.
type Generator struct {
	instructionCount int

	// The number of instructions generated excluding instrumentation instructions.
	logCount int32

	// File Descriptor of the map to store the logs.
	logMapFd int

	headerSize int32

	// A map from the generated instruction number to the assembled instruction offset.
	offsetMap map[int32]int32

	// A map from generated instruction number to the size (in bytes) of the
	// generated code including instrumentation instructions.
	sizeMap map[int32]int32

	// A map from the generated instruction number to the destination register
	// of the instruction.
	regMap map[int32]uint8
}

// MarkRegisterInitialized adds `reg` to the list of registers that have been
// initialized.
//func MarkRegisterInitialized(a *pb.Program, reg pb.Reg) {
//	if !(reg >= R0 && reg <= R10) {
//		return
//	}
//	a.trackedRegs = append(a.trackedRegs, reg)
//}

func (g *Generator) generateHeader(prog *pb.Program) []*pb.Instruction {
	root, _ := InstructionSequence(LdMapByFd(R6, g.logMapFd))
	//MarkRegisterInitialized(prog, R6.RegisterNumber())
	// Initializing R6 to a pointer value via a 8-byte immediate
	// generates a wide instruction. So, two 8-byte values.
	hSize := int32(2)

	for reg := R0; reg <= R10; reg++ {
		regVal := int32(rand.SharedRNG.RandInt())
		inst := Mov64(reg, regVal)
		root = append(root, inst)
		//MarkRegisterInitialized(prog, R6.RegisterNumber())
		hSize++
	}
	g.headerSize = hSize
	return root
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree
func (g *Generator) generateBody() []*pb.Instruction {
	r := []*pb.Instruction{}
	for i := 0; i < g.instructionCount; i++ {
		instr := RandomAluInstruction()
		var dstReg pb.Reg

		dstReg = instr.GetDstReg()

		stInst := g.generateStateStoringSnippet(&dstReg)
		//instrLen :=
		//instrOffset := int32(0)
		//if g.logCount == 0 {
		//	instrOffset = g.headerSize
		//} else {
		//	instrOffset = g.offsetMap[g.logCount-1] + g.sizeMap[g.logCount-1]
		//}

		//g.offsetMap[g.logCount] = instrOffset
		//g.regMap[g.logCount] = dstReg
		//g.sizeMap[g.logCount] = instrLen
		//g.logCount++

		//var stInstPtrs []*pb.Instruction
		//for i := range stInst {
		//	stInstPtrs = append(stInstPtrs, &stInst[i])
		//}

		r = append(r, instr)
		r = append(r, stInst...)
	}
	return r
}

func (g *Generator) generateFooter() []*pb.Instruction {
	ins, _ := InstructionSequence(Mov64(R0, 0), Exit())
	return ins
}

// Generate is the main function that builds the ebpf for this strategy.
func (g *Generator) Generate(prog *pb.Program) []*pb.Instruction {

	root := g.generateHeader(prog)
	root = append(root, g.generateBody()...)
	root = append(root, g.generateFooter()...)
	return root
}

func (g *Generator) generateStateStoringSnippet(dstReg *pb.Reg) []*pb.Instruction {
	// The storing snippet looks something like this:
	// - r0 = logCount
	// - *(r10 - 4) = r0; Where R10 is the stack pointer, we store the value
	// of logCount into the stack so we can write it into the map.
	// - r1 = r6; where r6 contains the map file descriptor
	// - r2 = r10
	// - r2 -= 4; We make r2 point to the count value we stored.
	// - r0 = bpf_map_lookup_element(map_fd, element_index)
	// - if r0 == null exit(); We need to check for null pointers.
	// - *(r0) = rX; where rX is the register that was the destination of
	//   the random operation.
	root, _ := InstructionSequence(
		Mov64(R0, g.logCount),
		StW(R10, R0, -4),
		Mov64(R1, R6),
		Mov64(R2, R10),
		Add64(R2, -4),
		Call(MapLookup),
		JmpNE(R0, 0, 1),
		Exit(),
		StDW(R0, *dstReg, 0),
	)

	return root
}

// GetProgramOffset returns the program offset corresponding to the n'th
// randomly generated instruction.
func (g *Generator) GetProgramOffset(n int32) int32 {
	return g.offsetMap[n]
}

// GetDestReg returns the destination registers of the n'th randomly
// generated instruction.
func (g *Generator) GetDestReg(n int32) uint8 {
	return g.regMap[n]
}
