package box

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRuntimeCohortsCondenseOnlyCyclesAndOrderDependencies(t *testing.T) {
	nodes := []runtimeDependencyNode{
		{name: "route", fingerprint: "r", dependencies: []string{"a", "leaf", "a"}},
		{name: "a", fingerprint: "a1", dependencies: []string{"b", "leaf"}},
		{name: "b", fingerprint: "b1", dependencies: []string{"a"}},
		{name: "leaf", fingerprint: "l"},
		{name: "independent", fingerprint: "i"},
	}
	cohorts, err := runtimeCohorts(nodes)
	if err != nil {
		t.Fatal(err)
	}
	membership := make(map[string]int)
	for index, cohort := range cohorts {
		for _, member := range cohort.members {
			membership[member] = index
		}
		seen := make(map[int]bool)
		for _, dependency := range cohort.dependencies {
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
	if !reflect.DeepEqual(cohorts[membership["a"]].members, []string{"a", "b"}) {
		t.Fatal("cohort members are not canonical")
	}
	permuted := []runtimeDependencyNode{nodes[4], nodes[2], nodes[0], nodes[3], nodes[1]}
	permuted[2].dependencies = []string{"a", "a", "leaf"}
	permuted[4].dependencies = []string{"leaf", "b"}
	again, err := runtimeCohorts(permuted)
	if err != nil || !reflect.DeepEqual(cohorts, again) {
		t.Fatalf("input order changes identity: %v\n%+v\n%+v", err, cohorts, again)
	}
	if !reflect.DeepEqual(nodes[1].dependencies, []string{"b", "leaf"}) {
		t.Fatal("cohort construction mutated caller dependencies")
	}
}

func TestRuntimeRealmDependencyClosurePreservesOrdinaryDNSOwnershipCycle(t *testing.T) {
	options := runtimeRealmDependencyOptions()
	options.DNS.Servers[0].Options.(*option.RemoteDNSServerOptions).Detour = "carrier-a"
	nodes, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
	if err != nil {
		t.Fatal("ordinary DNS/direct cycle was rejected", err)
	}
	cohorts, err := runtimeCohorts(nodes)
	if err != nil {
		t.Fatal(err)
	}
	membership := make(map[string]int)
	for index, cohort := range cohorts {
		for _, name := range cohort.members {
			membership[name] = index
		}
	}
	if membership["dns-router"] != membership["outbound:carrier-a"] {
		t.Fatal("existing DNS/direct cycle was split")
	}
	realm := membership["outbound:realm"]
	http := membership["http-manager"]
	if realm == http || realm == membership["dns-router"] || !slices.Contains(cohorts[realm].dependencies, http) {
		t.Fatal("Realm did not retain the independent receiving-manager closure", cohorts)
	}
}

func TestRuntimeCohortsFingerprintIncludesInternalEdgesAndUnambiguousFields(t *testing.T) {
	first := []runtimeDependencyNode{{name: "a", fingerprint: "ab", dependencies: []string{"b"}}, {name: "b", fingerprint: "c", dependencies: []string{"a"}}}
	cohorts, err := runtimeCohorts(first)
	if err != nil {
		t.Fatal(err)
	}
	second := []runtimeDependencyNode{{name: "a", fingerprint: "ab", dependencies: []string{"a", "b"}}, first[1]}
	changed, err := runtimeCohorts(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(cohorts) != 1 || len(changed) != 1 || cohorts[0].fingerprint == changed[0].fingerprint {
		t.Fatal("internal edge shape missing from owner identity")
	}
	third := []runtimeDependencyNode{{name: "a", fingerprint: "a", dependencies: []string{"b"}}, {name: "b", fingerprint: "bc", dependencies: []string{"a"}}}
	ambiguous, err := runtimeCohorts(third)
	if err != nil || cohorts[0].fingerprint == ambiguous[0].fingerprint {
		t.Fatal("field concatenation aliases distinct resource configurations")
	}
}

func TestRuntimeCohortsRejectIncompleteOrAmbiguousGraph(t *testing.T) {
	for name, nodes := range map[string][]runtimeDependencyNode{
		"empty":     {{name: ""}},
		"duplicate": {{name: "a"}, {name: "a"}},
		"missing":   {{name: "a", dependencies: []string{"absent"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtimeCohorts(nodes); err == nil {
				t.Fatal("invalid ownership graph accepted")
			}
		})
	}
}
