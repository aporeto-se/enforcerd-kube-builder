# enforcerd-kube-builder
Generates Kubernetes config for the Prisma (Aporeto) enforcerd Daemon set. This can be converted to YAML or applied directly to the Kubernetes cluster using the Kubernets go-client.


```
import core "github.com/aporeto-se/enforcerd-kube-builder/pkg"

daemonSetBuilder := core.NewEks("/tenant/cloud/cluster", "https://the_api")
daemonSet := daemonSetBuilder.Build()
```
