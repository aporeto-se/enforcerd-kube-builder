package example

import (
	"github.com/aporeto-se/pkg/core"
	"gopkg.in/yaml.v2"
)

func main() {

	daemonSetBuilder := core.NewEks(namespaceController.GetNamespacePath(), t.config.PrismaAPI)
	daemonSet := daemonSetBuilder.Build()

	b, _ := yaml.Marshal(daemonset.DaemonSet)
	return b

}
