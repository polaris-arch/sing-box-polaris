package adapter

import "time"

// TailscaleDirectoryNode is distinct from authentication-store retirement.
// It covers only the pinned producer's directory IO capabilities, not all
// goroutines or global cleanup. Empty identity is never deletion authority.
type TailscaleDirectoryNode struct {
	Tag               string `json:"tag"`
	StateDirectory    string `json:"stateDirectory"`
	DirectoryIdentity string `json:"directoryIdentity"`
	Incarnation       string `json:"incarnation"`
	DirectoryEpoch    string `json:"directoryEpoch"`
	WriterState       string `json:"writerState"`
	CensusVersion     int    `json:"censusVersion"`
	Failure           string `json:"failure"`
	RunNonce          string `json:"-"`
	ConfigDigest      string `json:"-"`
}

type TailscaleDirectoryOwner interface {
	TailscaleDirectoryScope() TailscaleDirectoryNode
	SealTailscaleDirectory()
	RetireTailscaleDirectory(deadline time.Time) TailscaleDirectoryNode
}
