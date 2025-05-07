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

// Package parseverifier implements a strategy of generating random
// ALU operations and then attempting to hunt verifier logic errors by parsing
// the output of the vierifier log and comparing the values the verifier thinks
// the registers will have vs the actual values that are observed at run time.
package strategies

//#include <stdlib.h>
//void close_fd(int fd);
import "C"

import (
	"fmt"

	"buzzer/pkg/rand"
	"buzzer/pkg/units/units"

	. "buzzer/pkg/ebpf/ebpf"

	btfpb "buzzer/proto/btf_go_proto"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
)

const (
	// StrategyName exposes the value of the flag that should be used to
	// invoke this strategy.
	StrategyName = "parse_verifier_log"
)

// StrategyParseVerifierLog Implements a fuzzing strategy where the results of
// the ebpf verifier will be parsed and then compared with the actual values
// observed at run time.
type StrategyParseVerifierLog struct {
	isFinished        bool
	mapFd             int
	programCount      int
	validProgramCount int
	log               string
}

func (pg *StrategyParseVerifierLog) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	pg.programCount += 1
	fmt.Printf("Generated %d programs, %d were valid               \r", pg.programCount, pg.validProgramCount)

	// Setup BTF Section
	btf := &btfpb.Btf{}
	SetHeaderSection(btf, 0xeb9f, 0x01, 0x0)
	btf.TypeSection = &btfpb.TypeSection{BtfType: types()}
	btf.StringSection = &btfpb.StringSection{Str: "buzzer"}

	mapFd := ffi.CreateMapArray(2)
	ffi.CloseFD(pg.mapFd)
	pg.mapFd = mapFd

	// Generate Random Function
	instructionCount := rand.SharedRNG.RandInt() % 1000
	functionBody, _ := InstructionSequence()

	for i := uint64(0); i < instructionCount; i++ {
		instruction := RandomAluInstruction() // Generate random ALU instruction
		functionBody = append(functionBody, instruction)
	}

	// Function Exit
	functionBody = append(functionBody, Mov(R0, 0), Exit())

	btfBuffer, err := GetBuffer(btf)
	if err != nil {
		return nil, err
	}

	prog := &pb.Program{
		Program: &pb.Program_Ebpf{
			Ebpf: &epb.Program{
				Functions: []*epb.Functions{
					{Instructions: functionBody, FuncInfo: &btfpb.FuncInfo{InsnOff: 0, TypeId: 2}},
				},
				Btf: btfBuffer,
			},
		},
	}

	return prog, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pg *StrategyParseVerifierLog) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult.VerifierLog)
	pg.isFinished = true
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pg *StrategyParseVerifierLog) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (pg *StrategyParseVerifierLog) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (pg *StrategyParseVerifierLog) IsFuzzingDone() bool {
	return pg.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (pg *StrategyParseVerifierLog) Name() string {
	return "ParseVerifier"
}

func NewParseVerifierStrategy() *StrategyParseVerifierLog {
	return &StrategyParseVerifierLog{isFinished: false}
}
