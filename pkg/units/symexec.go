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

// Package units implements the business logic to make the fuzzer work
package units

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"

	"buzzer/pkg/ebpf/ebpf"
	cpb "buzzer/proto/cbpf_go_proto"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
)

// SymControl manages symbolic execution flow.
type SymControl struct {
	strategy Strategy
	ffi      *FFI
	coverage *CoverageManager
	ready    bool
}

func (c *SymControl) Init(ffi *FFI, cm *CoverageManager, strat Strategy) error {
	if strat == nil {
		return NilStrategyError
	}
	c.ffi = ffi
	c.coverage = cm
	c.strategy = strat
	c.ready = true
	return nil
}

func (c *SymControl) IsReady() bool {
	return c.ready
}

func (c *SymControl) RunFuzzer() error {
	for !c.strategy.IsFuzzingDone() {
		prog, err := c.strategy.GenerateProgram(c.ffi)
		if err != nil {
			fmt.Printf("Generate error: %v\n", err)
			if !c.strategy.OnError(err) {
				return err
			}
			continue
		}

		switch p := prog.Program.(type) {
		case *pb.Program_Cbpf:
			if err := c.runCbpf(p.Cbpf); err != nil && !c.strategy.OnError(err) {
				return err
			}
		case *pb.Program_Ebpf:
			if err := c.runEbpf(p.Ebpf); err != nil && !c.strategy.OnError(err) {
				return err
			}
		}
	}
	return nil
}

func (c *SymControl) runEbpf(prog *epb.Program) error {
	encoded, funcInfo, err := ebpf.EncodeInstructions(prog)
	if err != nil {
		return err
	}

	validation := &fpb.EncodedProgram{
		Program:  encoded,
		Btf:      prog.Btf,
		Function: funcInfo,
	}
	result, err := c.ffi.ValidateEbpfProgram(validation)
	if err != nil || !result.IsValid || !c.strategy.OnVerifyDone(c.ffi, result) {
		c.ffi.CloseFD(int(result.ProgramFd))
		return err
	}
	defer c.ffi.CloseFD(int(result.ProgramFd))

	// Call symexec.py for symbolic execution
	cmd := exec.Command("python3", "symexec.py", strconv.Itoa(int(result.ProgramFd)))
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Symbolic execution failed: %v\nOutput: %s\n", err, string(output))
		return err
	}

	fmt.Printf("Symbolic execution result:\n%s\n", string(output))

	// Parse symbolic execution output into ExecutionResult and pass to strategy
	symResult := &fpb.ExecutionResult{}
	if err := json.Unmarshal(output, symResult); err != nil {
		fmt.Printf("Failed to parse symbolic execution result: %v\n", err)
		return err
	}

	if !c.strategy.OnExecuteDone(c.ffi, symResult) {
		fmt.Println("Symbolic execution reported unexpected results")
		ebpf.GeneratePoc(prog)
	}

	return nil
}

func (c *SymControl) runCbpf(prog *cpb.Program) error {
	encoded := encodeCbpfInstructions(prog)
	result, err := c.ffi.ValidateCbpfProgram(encoded)
	if err != nil || !result.IsValid || !c.strategy.OnVerifyDone(c.ffi, result) {
		c.ffi.CloseFD(int(result.ProgramFd))
		return err
	}
	defer c.ffi.CloseFD(int(result.ProgramFd))

	// Call symexec.py for symbolic execution of cBPF
	cmd := exec.Command("python3", "symexec.py", strconv.Itoa(int(result.ProgramFd)))
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Symbolic execution failed (cBPF): %v\nOutput: %s\n", err, string(output))
		return err
	}

	fmt.Printf("Symbolic execution (cBPF) result:\n%s\n", string(output))

	symResult := &fpb.ExecutionResult{}
	if err := json.Unmarshal(output, symResult); err != nil {
		fmt.Printf("Failed to parse cBPF symbolic execution result: %v\n", err)
		return err
	}

	if !c.strategy.OnExecuteDone(c.ffi, symResult) {
		fmt.Println("Symbolic execution reported unexpected results (cBPF)")
	}
	return nil
}
