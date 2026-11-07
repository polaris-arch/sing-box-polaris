//go:build windows && amd64

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// These are inert custody/parser fixtures. They never open a SYSTEM store,
// query/kill a process/job, run Core, or claim observed cleanup/native proof.
func custodyFixture() custodyRecord {
	id := strings.Repeat("1", 32)
	parent := `C:\Windows\SystemTemp`
	native := `\Device\HarddiskVolume1\Windows\SystemTemp`
	volume := strings.Repeat("1", 16)
	c := cohortFact{ID: id, Path: filepath.Join(parent, "polaris-native-"+id), NativePath: native + `\polaris-native-` + id, VolumeSerial: volume, FileID: strings.Repeat("2", 32), FileSystem: "NTFS", OwnerSID: systemSID, ProtectedDACL: true, SystemOnlyDACL: true, CreatedNew: true}
	r := custodyRecord{Schema: custodySchema, SourceCommit: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), RunID: 1, RunAttempt: 1, Owner: actorFact{systemSID, "primary", false, 12, "0000000000000001"}, Parent: custodyDirectoryID{native, volume, strings.Repeat("3", 32)}, Store: custodyDirectoryID{native + `\` + custodyDirectory, volume, strings.Repeat("4", 32)}, CohortID: id, Cohort: &c, Objects: []objectFact{}, Jobs: []custodyJob{}}
	for index, name := range []string{"sing-box.exe", "libcronet.dll"} {
		fileID := strings.Repeat("5", 32)
		if index == 1 {
			fileID = strings.Repeat("6", 32)
		}
		r.Objects = append(r.Objects, objectFact{Path: filepath.Join(c.Path, name), NativePath: c.NativePath + `\` + name, VolumeSerial: volume, FileID: fileID, OwnerSID: systemSID, ProtectedDACL: true, SystemOnlyDACL: true, Bytes: 1, SHA256: strings.Repeat("7", 64), LinkCount: 1, ShareReadOnly: true})
	}
	return r
}

func TestNativeCustodyRecordRejectsAmbiguousAndTruncatedDebt(t *testing.T) {
	raw, err := json.Marshal(custodyFixture())
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeCustody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateCustody(r, `C:\Windows\SystemTemp`); err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err = json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){func(v map[string]any) { v["RunID"] = v["runId"] }, func(v map[string]any) { delete(v, "closed") }, func(v map[string]any) { v["owner"].(map[string]any)["processId"] = true }, func(v map[string]any) { v["foreign"] = true }} {
		var v map[string]any
		json.Unmarshal(raw, &v)
		change(v)
		candidate, _ := json.Marshal(v)
		if _, err = decodeCustody(candidate); err == nil {
			t.Fatal("ambiguous custody debt admitted")
		}
	}
	for _, candidate := range [][]byte{raw[:len(raw)-1], []byte(`{"schema":"x","schema":"y"}`), []byte(strings.Repeat(" ", custodyLimit+1))} {
		if _, err = decodeCustody(candidate); err == nil {
			t.Fatal("unbounded/truncated debt admitted")
		}
	}
}

func TestNativeCustodyRejectsForeignObjectAndJobRecoveryTargets(t *testing.T) {
	mutations := []func(*custodyRecord){func(r *custodyRecord) { r.Owner.ThreadImpersonation = true }, func(r *custodyRecord) { r.Owner.CreationTime = strings.Repeat("0", 16) }, func(r *custodyRecord) { r.Cohort.Path = `C:\other` }, func(r *custodyRecord) { r.Cohort.VolumeSerial = strings.Repeat("f", 16) }, func(r *custodyRecord) { r.Objects[0].Path = `C:\other\sing-box.exe` }, func(r *custodyRecord) { r.Objects[0].FileID = r.Objects[1].FileID }, func(r *custodyRecord) { r.Objects[0].SystemOnlyDACL = false }, func(r *custodyRecord) { r.Objects[0].LinkCount = 2 }, func(r *custodyRecord) { r.Jobs = []custodyJob{{"Global\\foreign"}} }, func(r *custodyRecord) { r.Jobs = make([]custodyJob, 257) }, func(r *custodyRecord) { r.Cohort = nil }, func(r *custodyRecord) { r.Objects = nil }}
	mutations = append(mutations,
		func(r *custodyRecord) { r.Parent.FileID = strings.Repeat("0", 32) },
		func(r *custodyRecord) { r.Store.VolumeSerial = strings.Repeat("0", 16) },
		func(r *custodyRecord) { r.Cohort.FileID = strings.Repeat("0", 32) },
		func(r *custodyRecord) { r.Objects[0].FileID = strings.Repeat("0", 32) })
	for index, change := range mutations {
		r := custodyFixture()
		change(&r)
		if err := validateCustody(r, `C:\Windows\SystemTemp`); err == nil {
			t.Fatalf("foreign/unknown recovery target %d admitted", index)
		}
	}
}

func TestNativeCustodyReconciliationNeverGrantsAdmission(t *testing.T) {
	called := false
	err := reconcileBeforeAdmission(func() error { called = true; return nil })
	if !called || !errors.Is(err, errCustodyReconciled) {
		t.Fatal("cleanup-only invocation was admitted as a new proof attempt")
	}
	debt := errors.New("exact FileID/active job remains unknown")
	if err = reconcileBeforeAdmission(func() error { return debt }); !errors.Is(err, debt) || errors.Is(err, errCustodyReconciled) {
		t.Fatal("unknown cleanup debt was cleared")
	}
}

func TestNativeCooperativeControlFramesOnlyCancelOriginalOwner(t *testing.T) {
	for _, frame := range []string{"cancel\n", "", "run arbitrary\n", strings.Repeat("x", 32)} {
		ctx, cancel := context.WithCancel(context.Background())
		watchNativeCancellation(bufio.NewReaderSize(strings.NewReader(frame), 16), cancel)
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("control frame selected an operation or failed to cancel")
		}
	}
	for _, frame := range []string{`{}` + "\n", `{}`} {
		raw, err := readNativeRequest(bufio.NewReader(strings.NewReader(frame)))
		if strings.HasSuffix(frame, "\n") {
			if err != nil || string(raw) != `{}` {
				t.Fatal("fixed request framing differs")
			}
		} else if err == nil {
			t.Fatal("EOF request silently admitted")
		}
	}
}

func TestNativeCleanupRequiresActualWaitAndReaderClosure(t *testing.T) {
	for _, state := range []struct {
		children, waited, joined int
		active                   uint32
		quiescent                bool
	}{{0, 0, 0, 0, true}, {1, 1, 1, 0, true}, {1, 0, 1, 0, false}, {1, 1, 0, 0, false}, {1, 1, 1, 1, false}, {2, 1, 1, 0, false}} {
		c := cohort{children: state.children, waited: state.waited, joined: state.joined, active: state.active}
		if c.resourcesQuiescent() != state.quiescent {
			t.Fatal("unknown native wait/readers/job state permits cohort removal")
		}
	}
}
