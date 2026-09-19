// Package builtin contains the parsers shipped with the engine. Consumers can
// replace or extend them through manifest.Registry without changing scanner code.
package builtin

import "github.com/itsmangooo/weedout-engine/pkg/manifest"

func Registry() *manifest.Registry {
	return manifest.NewRegistry(
		PackageLockParser{}, PackageJSONParser{}, RequirementsParser{}, GoModParser{},
		CargoLockParser{}, POMParser{}, GradleLockParser{}, SBTLockParser{},
	)
}
