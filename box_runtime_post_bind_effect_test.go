package box

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type postBindFixture struct {
	name                             string
	events                           *[]string
	stageErr, suspendErr, restoreErr error
	panicSuspend                     bool
}

func (f *postBindFixture) RuntimeConflictKeys() []string { return []string{f.name} }
func (f *postBindFixture) StageRuntime(context.Context) error {
	*f.events = append(*f.events, "stage:"+f.name)
	return f.stageErr
}

func (f *postBindFixture) SuspendRuntime(context.Context) error {
	*f.events = append(*f.events, "suspend:"+f.name)
	if f.panicSuspend {
		panic("suspend")
	}
	return f.suspendErr
}

func (f *postBindFixture) RestoreRuntime(context.Context) error {
	*f.events = append(*f.events, "restore:"+f.name)
	return f.restoreErr
}
func (f *postBindFixture) RuntimeExternalEffects() bool { return true }
func (f *postBindFixture) RuntimeActivate()             {}
func (f *postBindFixture) RuntimeStop()                 {}
func TestPostBindFailedStageStillRequiresAbsence(t *testing.T) {
	var events []string
	failed := errors.New("register response unknown")
	f := &postBindFixture{name: "new", events: &events, stageErr: failed, suspendErr: failed}
	old := &postBindFixture{name: "old", events: &events}
	g := &preparedRuntimeGraph{postBindNext: []runtimePostBindRecord{{effect: f}}, postBindSuspended: []runtimePostBindRecord{{effect: old}}}
	if !errors.Is(g.stageRuntimePostBindEffects(context.Background()), failed) {
		t.Fatal("missing stage error")
	}
	if g.suspendRuntimeCandidateEffects() {
		g.restoreRuntimePreviousEffects()
	}
	if !reflect.DeepEqual(events, []string{"stage:new", "suspend:new"}) {
		t.Fatal(events)
	}
	if g.postBindError == nil || !g.externalEffectsAttempted {
		t.Fatal("lost uncertain remote evidence")
	}
}

func TestPostBindCompensationUsesReverseActualOrder(t *testing.T) {
	var events []string
	a := &postBindFixture{name: "a", events: &events}
	b := &postBindFixture{name: "b", events: &events}
	g := &preparedRuntimeGraph{postBindNext: []runtimePostBindRecord{{effect: a}, {effect: b}}, postBindSuspended: []runtimePostBindRecord{{effect: a}, {effect: b}}}
	if err := g.stageRuntimePostBindEffects(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !g.suspendRuntimeCandidateEffects() {
		t.Fatal(g.postBindError)
	}
	g.restoreRuntimePreviousEffects()
	if !reflect.DeepEqual(events, []string{"stage:a", "stage:b", "suspend:b", "suspend:a", "restore:b", "restore:a"}) {
		t.Fatal(events)
	}
}

func TestPostBindPanicNeverAuthorizesRestore(t *testing.T) {
	var events []string
	f := &postBindFixture{name: "new", events: &events, panicSuspend: true}
	g := &preparedRuntimeGraph{postBindStaged: []runtimePostBindRecord{{effect: f}}}
	if g.suspendRuntimeCandidateEffects() || g.postBindError == nil {
		t.Fatal("panic certified remote absence")
	}
}

func TestPostBindCancellationBeforeStageHasNoAttempt(t *testing.T) {
	var events []string
	f := &postBindFixture{name: "new", events: &events}
	g := &preparedRuntimeGraph{postBindNext: []runtimePostBindRecord{{effect: f}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(g.stageRuntimePostBindEffects(ctx), context.Canceled) || len(events) != 0 || len(g.postBindStaged) != 0 {
		t.Fatal("canceled candidate touched remote state")
	}
}
