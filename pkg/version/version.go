package version

import (
	"fmt"
	"runtime/debug"
)

const (
	LatestVersion = "v0.0.10"
)

var (
	Version   string
	BuildDate string
	Commit    string
)

func FullString() string {
	ret := fmt.Sprintf("version: %s\n", String())
	return ret
}

func String() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if Version == "" {
			Version = info.Main.Version
		}
	}
	if Version == "" {
		Version = LatestVersion
	}
	return Version
}
