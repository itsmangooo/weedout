package builtin

import (
	"context"
	"testing"

	"github.com/itsmangooo/weedout-engine/pkg/model"
)

func TestBuiltInParsers(t *testing.T) {
	cases := []struct{ name, content, want string }{{"package.json", `{"dependencies":{"lodash":"4.17.20"}}`, "lodash"}, {"package-lock.json", `{"packages":{"":{"dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`, "lodash"}, {"requirements.txt", "Django==4.2.0", "django"}, {"go.mod", "module example\nrequire golang.org/x/text v0.3.7\n", "golang.org/x/text"}, {"Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n", "serde"}, {"pom.xml", "<project><dependencies><dependency><groupId>org.demo</groupId><artifactId>core</artifactId><version>1.2.3</version></dependency></dependencies></project>", "org.demo:core"}, {"gradle.lockfile", "org.demo:core:1.2.3=runtimeClasspath", "org.demo:core"}, {"build.sbt.lock", `{"dependencies":[{"organization":"org.demo","name":"core","version":"1.2.3"}]}`, "org.demo:core"}}
	registry := Registry()
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			result, err := registry.Parse(context.Background(), model.ManifestInput{Path: item.name, Content: item.content})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, dep := range result.Graph.Dependencies {
				if dep.Name == item.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s not parsed: %#v", item.want, result.Graph.Dependencies)
			}
		})
	}
}

func TestCargoLockExcludesWorkspaceAndFindsDirectDependencies(t *testing.T) {
	content := `version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["serde 1.0.100"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	result, err := (CargoLockParser{}).Parse(context.Background(), model.ManifestInput{Path: "Cargo.lock", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Graph.Dependencies) != 1 {
		t.Fatalf("dependencies: %#v", result.Graph.Dependencies)
	}
	dependency := result.Graph.Dependencies[0]
	if dependency.Name != "serde" || dependency.Scope != "runtime_direct" || dependency.Depth != 0 {
		t.Fatalf("dependency: %#v", dependency)
	}
}

func TestPOMRejectsDocumentTypes(t *testing.T) {
	payload := `<!DOCTYPE project [<!ENTITY x "expanded">]><project><artifactId>&x;</artifactId></project>`
	if _, err := (POMParser{}).Parse(context.Background(), model.ManifestInput{Path: "pom.xml", Content: payload}); err == nil {
		t.Fatal("POM document type was accepted")
	}
}
