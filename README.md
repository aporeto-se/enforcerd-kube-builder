# enforcerd-kube-builder
Generates Kubernetes config for the Prisma (Aporeto) enforcerd Daemon set. This can be converted to YAML or applied directly to the Kubernetes cluster using the Kubernets go-client.


```
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

	// kubeconfig.CoreV1().Namespaces().Apply(ctx, daemonSet.Namespace, k8smetav1.ApplyOptions{
	// 	FieldManager: "cloud-operator",
	// })

	// kubeconfig.RbacV1().ClusterRoleBindings().Apply(ctx, daemonSet.ClusterRoleBinding, k8smetav1.ApplyOptions{
	// 	FieldManager: "cloud-operator",
	// })

	// kubeconfig.CoreV1().ServiceAccounts("aporeto").Apply(ctx, daemonSet.ServiceAccount, k8smetav1.ApplyOptions{
	// 	FieldManager: "cloud-operator",
	// })

	// kubeconfig.AppsV1().DaemonSets("aporeto").Apply(ctx, daemonSet.DaemonSet, k8smetav1.ApplyOptions{
	// 	FieldManager: "cloud-operator",
	// })

}
```
