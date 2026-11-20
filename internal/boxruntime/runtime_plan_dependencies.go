package boxruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
)

// Planning fingerprints the same dependency condensation used by construction.
// This performs no constructor, transport or producer work. Frozen external
// source content is bound separately so a same-path edit changes the receipt.
func runtimePlannedDependencyDigest(ctx context.Context, options option.Options, sourceDigest string) (string, error) {
	nodes, _, err := runtimeConfigNodes(ctx, runtimeResolveGraphDefaults(options))
	if err != nil {
		return "", err
	}
	cohorts, err := runtimegraph.DependencyCohorts(nodes)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	runtimegraph.HashField(hash, "runtime-dependencies-v1")
	runtimegraph.HashField(hash, sourceDigest)
	runtimegraph.HashField(hash, strconv.Itoa(len(cohorts)))
	for _, cohort := range cohorts {
		runtimegraph.HashField(hash, cohort.Fingerprint)
		runtimegraph.HashField(hash, strconv.Itoa(len(cohort.Dependencies)))
		for _, dependency := range cohort.Dependencies {
			runtimegraph.HashField(hash, strconv.Itoa(dependency))
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
