package runtimegraph

import (
	"reflect"
	"testing"
)

func TestRuntimeCohortsCondenseOnlyCyclesAndOrderDependencies(t *testing.T) {
	nodes := []DependencyNode{
		{Name: "route", Fingerprint: "r", Dependencies: []string{"a", "leaf", "a"}},
		{Name: "a", Fingerprint: "a1", Dependencies: []string{"b", "leaf"}},
		{Name: "b", Fingerprint: "b1", Dependencies: []string{"a"}},
		{Name: "leaf", Fingerprint: "l"},
		{Name: "independent", Fingerprint: "i"},
	}
	cohorts, err := DependencyCohorts(nodes)
	if err != nil {
		t.Fatal(err)
	}
	membership := make(map[string]int)
	for index, cohort := range cohorts {
		for _, member := range cohort.Members {
			membership[member] = index
		}
		seen := make(map[int]bool)
		for _, dependency := range cohort.Dependencies {
			if dependency >= index || seen[dependency] {
				t.Fatalf("not a deduplicated dependency-first DAG: %+v", cohorts)
			}
			seen[dependency] = true
		}
	}
	if len(cohorts) != 4 || membership["a"] != membership["b"] {
		t.Fatalf("cycle not condensed exactly: %+v", cohorts)
	}
	if membership["route"] == membership["a"] || membership["leaf"] == membership["a"] || membership["independent"] == membership["route"] {
		t.Fatal("unrelated resources artificially share ownership")
	}
	if !reflect.DeepEqual(cohorts[membership["a"]].Members, []string{"a", "b"}) {
		t.Fatal("cohort members are not canonical")
	}
	permuted := []DependencyNode{nodes[4], nodes[2], nodes[0], nodes[3], nodes[1]}
	permuted[2].Dependencies = []string{"a", "a", "leaf"}
	permuted[4].Dependencies = []string{"leaf", "b"}
	again, err := DependencyCohorts(permuted)
	if err != nil || !reflect.DeepEqual(cohorts, again) {
		t.Fatalf("input order changes identity: %v\n%+v\n%+v", err, cohorts, again)
	}
	if !reflect.DeepEqual(nodes[1].Dependencies, []string{"b", "leaf"}) {
		t.Fatal("cohort construction mutated caller dependencies")
	}
}

func TestRuntimeCohortsFingerprintIncludesInternalEdgesAndUnambiguousFields(t *testing.T) {
	first := []DependencyNode{{Name: "a", Fingerprint: "ab", Dependencies: []string{"b"}}, {Name: "b", Fingerprint: "c", Dependencies: []string{"a"}}}
	cohorts, err := DependencyCohorts(first)
	if err != nil {
		t.Fatal(err)
	}
	second := []DependencyNode{{Name: "a", Fingerprint: "ab", Dependencies: []string{"a", "b"}}, first[1]}
	changed, err := DependencyCohorts(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(cohorts) != 1 || len(changed) != 1 || cohorts[0].Fingerprint == changed[0].Fingerprint {
		t.Fatal("internal edge shape missing from owner identity")
	}
	third := []DependencyNode{{Name: "a", Fingerprint: "a", Dependencies: []string{"b"}}, {Name: "b", Fingerprint: "bc", Dependencies: []string{"a"}}}
	ambiguous, err := DependencyCohorts(third)
	if err != nil || cohorts[0].Fingerprint == ambiguous[0].Fingerprint {
		t.Fatal("field concatenation aliases distinct resource configurations")
	}
}

func TestRuntimeCohortsRejectIncompleteOrAmbiguousGraph(t *testing.T) {
	for name, nodes := range map[string][]DependencyNode{
		"empty":     {{Name: ""}},
		"duplicate": {{Name: "a"}, {Name: "a"}},
		"missing":   {{Name: "a", Dependencies: []string{"absent"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DependencyCohorts(nodes); err == nil {
				t.Fatal("invalid ownership graph accepted")
			}
		})
	}
}
