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
	"errors"
	"fmt"
	"log"

	. "buzzer/pkg/units/units"

	"buzzer/pkg/ebpf/ebpf"
	. "buzzer/pkg/strategies/oracle"

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

func (o *RegisterOracle) Dump() {
	for offset, regMap := range o.values {
		for regNum, value := range regMap {
			fmt.Printf("Offset: %d, Register: R%d, Value: %d\n", offset, regNum, value)
		}
	}
}

func (st *StrategyParseVerifierLog) generateAndValidateProgram(e ExecutorInterface, gen *Generator) (*GeneratorResult, error) {
	for i := 0; i < 100_000; i++ {
		prog, err := ebpf.New( /*mapSize=*/ 1000 /*minReg=*/, ebpf.RegR7.RegisterNumber() /*maxReg=*/, ebpf.RegR9.RegisterNumber())
		gen.logMapFd = prog.LogMap()
		prog.Instructions = gen.Generate(prog)
		if err != nil {
			return nil, err
		}
		byteCode := prog.GenerateBytecode()
		res, err := e.ValidateProgram(byteCode)
		if err != nil {
			prog.Cleanup()
			return nil, err
		}

		if res.GetIsValid() {
			result := &GeneratorResult{
				Prog:         prog,
				ProgByteCode: byteCode,
				ProgFD:       res.GetProgramFd(),
				VerifierLog:  res.GetVerifierLog(),
			}

			return result, nil
		}
		prog.Cleanup()
	}
	return nil, errors.New("could not generate a valid program")
}

// Fuzz implements the main fuzzing logic.
func (st *StrategyParseVerifierLog) Fuzz(e ExecutorInterface, cm CoverageManager) error {
	fmt.Printf("running fuzzing strategy %s\n", StrategyName)
	i := 0
	for {
		gen := &Generator{
			instructionCount: 10,
			offsetMap:        make(map[int32]int32),
			sizeMap:          make(map[int32]int32),
			regMap:           make(map[int32]uint8),
		}
		fmt.Printf("Fuzzer run no %d.                               \r", i)
		i++
		gr, err := st.generateAndValidateProgram(e, gen)

		if err != nil {
			return err
		}

		// Build a new execution request.
		logCount := gen.logCount
		mapDescription := &fpb.ExecutionRequest_MapDescription{
			MapFd:   int64(gen.logMapFd),
			MapSize: uint64(logCount),
		}
		executionRequest := &fpb.ExecutionRequest{
			ProgFd: gr.ProgFD,
			Maps:   []*fpb.ExecutionRequest_MapDescription{mapDescription},
		}

		defer func() {
			C.close_fd(C.int(executionRequest.GetProgFd()))
			C.close_fd(C.int(mapDescription.GetMapFd()))
		}()

		programFlaked := true

		var exRes *fpb.ExecutionResult
		maxAttempts := 1000

		for programFlaked && maxAttempts != 0 {
			maxAttempts--
			eR, err := e.RunProgram(executionRequest)
			if err != nil {
				return err
			}

			if !eR.GetDidSucceed() {
				return fmt.Errorf("execute Program did not succeed")
			}
			mapElements := eR.GetMapElements()[0].GetElements()
			for i := 0; i < len(mapElements); i++ {
				if mapElements[i] != 0 {
					programFlaked = false
					exRes = eR
					break
				}
			}
		}

		if maxAttempts == 0 {
			fmt.Println("program flaked")
			SaveExecutionResults(gr)
			continue
		}

		// Program succeeded, let's validate the execution map.
		regOracle, err := FromVerifierTrace(gr.VerifierLog)
		if err != nil {
			log.Fatalf("Failed to build oracle: %v", err)
		}

		regOracle.Dump()

		mapSize := int32(executionRequest.GetMaps()[0].GetMapSize())
		mapElements := exRes.GetMapElements()[0].GetElements()
		for mapIndex := int32(0); mapIndex < mapSize; mapIndex++ {
			offset := gen.GetProgramOffset(mapIndex)
			dstReg := gen.GetDestReg(mapIndex)
			verifierValue, known, err := regOracle.LookupRegValue(offset, dstReg)
			if err != nil {
				return err
			}
			actualValue := mapElements[mapIndex]
			if known && verifierValue != actualValue {
				if err := SaveExecutionResults(gr); err != nil {
					return err
				}
			}
		}

		C.close_fd(C.int(executionRequest.GetProgFd()))
		C.close_fd(C.int(mapDescription.GetMapFd()))
	}
	return nil
}

func (pg *StrategyParseVerifierLog) GenerateProgram(ffi *FFI) (*pb.Program, error) {

	insn, err := InstructionSequence(
		Mov(R0, 0),
		Exit(),
	)
	if err != nil {
		return nil, err
	}
	prog := &pb.Program{
		Program: &pb.Program_Ebpf{
			Ebpf: &epb.Program{
				Functions: []*epb.Functions{
					{Instructions: insn},
				},
			},
		}}
	return prog, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pg *StrategyParseVerifierLog) OnVerifyDone(ffi *FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult.VerifierLog)
	pg.isFinished = true
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pg *StrategyParseVerifierLog) OnExecuteDone(ffi *FFI, executionResult *fpb.ExecutionResult) bool {
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
