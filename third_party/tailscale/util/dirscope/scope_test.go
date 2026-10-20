// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package dirscope

import (
 "context"
 "errors"
 "sync"
 "testing"
)

func TestSealRequiresActualRelease(t *testing.T) {
 var s Scope
 release, err := s.Begin()
 if err != nil { t.Fatal(err) }
 s.Seal()
 if _, err := s.Begin(); !errors.Is(err, ErrSealed) { t.Fatal(err) }
 ctx, cancel := context.WithCancel(context.Background()); cancel()
 if err := s.Wait(ctx); !errors.Is(err, ErrIncomplete) { t.Fatal(err) }
 select { case <-s.done: t.Fatal("cancellation forged IO completion"); default: }
 release(); release()
 <-s.done
 if err := s.Wait(context.Background()); !errors.Is(err, ErrIncomplete) { t.Fatal("lost first failure", err) }
}
func TestSealRaceAndNilCannotProve(t *testing.T) {
 for range 100 {
  var s Scope
  var wg sync.WaitGroup
  for range 16 { wg.Add(1); go func(){ defer wg.Done(); if end,err:=s.Begin();err==nil {end()} }() }
  s.Seal(); wg.Wait()
  if err:=s.Wait(context.Background());err!=nil {t.Fatal(err)}
 }
 var missing *Scope
 if err:=missing.Wait(context.Background());!errors.Is(err,ErrIncomplete) {t.Fatal(err)}
}
