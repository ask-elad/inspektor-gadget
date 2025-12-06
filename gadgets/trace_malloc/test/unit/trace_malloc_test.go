// Copyright 2025 The Inspektor Gadget authors
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

package tests
 
import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
 
	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	utils "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
 
	"github.com/cilium/ebpf"
)
 
type ExpectedTraceMallocEvent struct {
	Proc         types.Process `json:"proc"`
	OperationRaw int           `json:"operation_raw"`
	Size         uint64        `json:"size"`
	Addr         uint64        `json:"addr"`
}
 
type testDef struct {
	runnerConfig   *utils.RunnerConfig
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
	generateEvent  func() (int, error)
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedTraceMallocEvent)
}
 
func TestTraceMallocGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
 
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: nil,
			generateEvent:  generateEvent,
			validateEvent:  validateEventBasic,
		},
 
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateEvent,
			validateEvent: validateNoEvent,
		},
 
		"captures_events_with_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: validateEventBasic,
		},
	}
 
	for name, testCase := range testCases {
		tc := testCase
 
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, tc.runnerConfig)
 
			var mntnsMap *ebpf.Map
			if tc.mntnsFilterMap != nil {
				mntnsMap = tc.mntnsFilterMap(runner.Info)
				defer mntnsMap.Close()
			}
 
			var pid int
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					var err error
					pid, err = tc.generateEvent()
					return err
				})
				return nil
			}
 
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceMallocEvent]{
				Image:          "trace_malloc",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsMap,
				OnGadgetRun:    onGadgetRun,
			}
 
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
 
			gadgetRunner.RunGadget()
 
			tc.validateEvent(t, runner.Info, pid, gadgetRunner.CapturedEvents)
		})
	}
}
 
func generateEvent() (int, error) {
	cProgram := `
        #include <stdlib.h>
        #include <unistd.h>
 
        int main() {
            void *p = malloc(1234);
            if (!p) return 1;
            sleep(1);
            return 0;
        }
    `
 
	tmpFile, err := os.CreateTemp("", "trace_malloc_test_*.c")
	if err != nil {
		return 0, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
 
	if _, err := tmpFile.Write([]byte(cProgram)); err != nil {
		return 0, fmt.Errorf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()
 
	exeFile := tmpFile.Name() + ".out"
 
	cmd := exec.Command("gcc", tmpFile.Name(), "-o", exeFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("failed to compile C program: %v", err)
	}
 
	runCmd := exec.Command(exeFile)
 
	if err := runCmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start compiled program: %v", err)
	}
 
	pid := runCmd.Process.Pid
 
	go func() {
		_ = runCmd.Wait()
		_ = os.Remove(exeFile)
	}()
 
	return pid, nil
}
 
func validateEventBasic(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedTraceMallocEvent) {
	t.Helper()
	var matched *ExpectedTraceMallocEvent
	for i := range events {
		ev := &events[i]
 
		if ev.Proc.Pid == uint32(pid) && ev.OperationRaw == 0 && ev.Size == 1234 && ev.Addr != 0 {
			matched = ev
			break
		}
	}
 
	if matched == nil {
		t.Fatalf("expected malloc event for pid=%d, but none was found. captured=%+v", pid, events)
	}
}
 
func validateNoEvent(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedTraceMallocEvent) {
	t.Helper()
 
	for i := range events {
		ev := &events[i]
 
		if ev.Proc.Pid == uint32(pid) && ev.OperationRaw == 0 {
			t.Fatalf("did not expect malloc events for pid=%d, but found: %+v", pid, ev)
		}
	}
}

