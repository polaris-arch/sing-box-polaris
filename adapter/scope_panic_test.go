package adapter

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func TestScopeCloseDrainsAfterCallbackPanic(t *testing.T) {
	for panicAt := range 3 {
		t.Run([]string{"first-registered", "middle", "last-registered"}[panicAt], func(t *testing.T) {
			scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
			var order []int
			for index := range 3 {
				scope.Add(func() error {
					order = append(order, index)
					if index == panicAt {
						panic("synthetic cleanup panic")
					}
					return nil
				})
			}
			err := scope.Close()
			if err == nil || !strings.Contains(err.Error(), "panic during close: synthetic cleanup panic") {
				t.Fatalf("Close() = %v, want the cleanup panic as an error", err)
			}
			if !slices.Equal(order, []int{2, 1, 0}) {
				t.Fatalf("cleanup order = %v, want [2 1 0]", order)
			}
			if !errors.Is(scope.Context().Err(), context.Canceled) {
				t.Fatal("Close did not cancel the scope context")
			}
			if err := scope.Close(); err != nil || len(order) != 3 {
				t.Fatalf("second Close() = %v, cleanup order = %v", err, order)
			}
		})
	}
}

func TestScopeCloseKeepsFailureAndPanicButFiltersBenignErrors(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	failure := errors.New("ordinary cleanup failure")
	var order []int
	for index, result := range []error{failure, net.ErrClosed, context.Canceled} {
		scope.Add(func() error {
			order = append(order, index)
			return result
		})
	}
	scope.Add(func() error {
		order = append(order, 3)
		panic("last registered callback")
	})
	err := scope.Close()
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "last registered callback") {
		t.Fatalf("Close() = %v, want both ordinary failure and cleanup panic", err)
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		t.Fatalf("Close() retained benign errors: %v", err)
	}
	if !slices.Equal(order, []int{3, 2, 1, 0}) {
		t.Fatalf("cleanup order = %v, want [3 2 1 0]", order)
	}
}

func TestScopeCloseDrainsAfterMultipleCallbackPanics(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	completed := false
	scope.Add(func() error {
		completed = true
		return nil
	})
	scope.Add(func() error { panic("first registered panic") })
	scope.Add(func() error { panic("last registered panic") })
	err := scope.Close()
	if err == nil || !strings.Contains(err.Error(), "first registered panic") || !strings.Contains(err.Error(), "last registered panic") {
		t.Fatalf("Close() = %v, want both cleanup panics", err)
	}
	if !completed {
		t.Fatal("earliest callback was abandoned after cleanup panics")
	}
}
