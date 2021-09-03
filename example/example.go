package main

import (
	"fmt"

	core "github.com/aporeto-se/enforcerd-kube-builder/pkg"
	"gopkg.in/yaml.v2"
)

func main() {

	daemonSetBuilder := core.NewEks("/tenant/cloud/cluster", "https://the_api")
	daemonSet := daemonSetBuilder.Build()

	b, _ := yaml.Marshal(daemonSet.DaemonSet)
	fmt.Println(string(b))

}
