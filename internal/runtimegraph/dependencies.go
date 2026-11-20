package runtimegraph

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
)

// DependencyNode describes actual constructor-captured dependencies,
// including lazy resolver/detour bindings. Tags identify configuration nodes;
// the allocator later binds their condensation to incarnation resource IDs.
type DependencyNode struct {
	Name         string
	Fingerprint  string
	Dependencies []string
}

// Cohort is an ownership group with dependency indices in the condensation.
type Cohort struct {
	Members      []string
	Dependencies []int
	Fingerprint  string
}

// DependencyCohorts groups only actual ownership cycles. Dependencies are emitted
// before their consumers, so a new owner's outgoing reservations already exist.
func DependencyCohorts(nodes []DependencyNode) ([]Cohort, error) {
	byName := make(map[string]DependencyNode, len(nodes))
	for _, node := range nodes {
		if node.Name == "" {
			return nil, errors.New("empty runtime dependency name")
		}
		if _, exists := byName[node.Name]; exists {
			return nil, errors.New("duplicate runtime dependency name")
		}
		copyNode := node
		copyNode.Dependencies = append([]string(nil), node.Dependencies...)
		sort.Strings(copyNode.Dependencies)
		byName[node.Name] = copyNode
	}
	for _, node := range byName {
		for _, dependency := range node.Dependencies {
			if _, exists := byName[dependency]; !exists {
				return nil, errors.New("missing runtime dependency: " + dependency)
			}
		}
	}
	index, low := map[string]int{}, map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var result []Cohort
	sequence := 0
	var visit func(string)
	visit = func(name string) {
		sequence++
		index[name] = sequence
		low[name] = sequence
		stack = append(stack, name)
		onStack[name] = true
		for _, dependency := range byName[name].Dependencies {
			if index[dependency] == 0 {
				visit(dependency)
				if low[dependency] < low[name] {
					low[name] = low[dependency]
				}
			} else if onStack[dependency] && index[dependency] < low[name] {
				low[name] = index[dependency]
			}
		}
		if low[name] != index[name] {
			return
		}
		var members []string
		for {
			last := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[last] = false
			members = append(members, last)
			if last == name {
				break
			}
		}
		sort.Strings(members)
		result = append(result, Cohort{Members: members})
	}
	var names []string
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if index[name] == 0 {
			visit(name)
		}
	}
	membership := map[string]int{}
	for i, cohort := range result {
		for _, name := range cohort.Members {
			membership[name] = i
		}
	}
	for i := range result {
		seen := map[int]bool{}
		hash := sha256.New()
		for _, name := range result[i].Members {
			HashField(hash, name)
			HashField(hash, byName[name].Fingerprint)
			for _, dependency := range byName[name].Dependencies {
				other := membership[dependency]
				if other != i {
					seen[other] = true
				}
				// Internal edge shape is part of the identity, not just its members.
				HashField(hash, dependency)
			}
		}
		result[i].Fingerprint = hex.EncodeToString(hash.Sum(nil))
		for dependency := range seen {
			result[i].Dependencies = append(result[i].Dependencies, dependency)
		}
		sort.Ints(result[i].Dependencies)
		for _, dependency := range result[i].Dependencies {
			if dependency >= i {
				return nil, errors.New("invalid runtime dependency condensation")
			}
		}
	}
	return result, nil
}

// HashField writes a string preceded by its eight-byte big-endian length.
func HashField(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write([]byte(value))
}
