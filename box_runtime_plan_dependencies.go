package box

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/sagernet/sing-box/option"
)

// Planning fingerprints the same dependency condensation used by construction.
// This performs no constructor, transport or producer work. Frozen external
// source content is bound separately so a same-path edit changes the receipt.
func runtimePlannedDependencyDigest(ctx context.Context, options option.Options, sourceDigest string) (string, error) {
	nodes, _, err := runtimeConfigNodes(ctx, runtimeResolveGraphDefaults(options))
	if err != nil { return "", err }
	cohorts, err := runtimeCohorts(nodes)
	if err != nil { return "", err }
	hash := sha256.New()
	runtimeHashField(hash, "runtime-dependencies-v1")
	runtimeHashField(hash, sourceDigest)
	runtimeHashField(hash, strconv.Itoa(len(cohorts)))
	for _, cohort := range cohorts {
		runtimeHashField(hash, cohort.fingerprint)
		runtimeHashField(hash, strconv.Itoa(len(cohort.dependencies)))
		for _, dependency := range cohort.dependencies { runtimeHashField(hash, strconv.Itoa(dependency)) }
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
