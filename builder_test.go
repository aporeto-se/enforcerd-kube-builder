package builder

import (
	"fmt"
	"testing"

	"gopkg.in/yaml.v2"
)

func Test1(t *testing.T) {

	daemonSetBuilder := NewEks("/tenant/cloud/cluster", "https://the_api")
	daemonSet := daemonSetBuilder.Build()

	b, _ := yaml.Marshal(daemonSet)
	fmt.Println(string(b))

	if derefString(daemonSet.DaemonSet.Namespace) != "aporeto" {
		t.Fatalf("not expected")
	}

}

func derefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
