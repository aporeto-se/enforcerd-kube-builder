package builder

import (
	"strconv"

	"github.com/aporeto-se/enforcerd-kube-builder/types"

	k8sappsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8sapcappsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	k8sapccore1 "k8s.io/client-go/applyconfigurations/core/v1"
	k8sapcmetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	k8sapprbacv1 "k8s.io/client-go/applyconfigurations/rbac/v1"
)

const (
	// EnforcerdLogLevelDefault default log level
	EnforcerdLogLevelDefault = "info"
	// EnforcerdLogFormatDefault Log format
	EnforcerdLogFormatDefault = "json"

	// CustomCniBinDir Kubernetes CNI bin location for custom (default)
	CustomCniBinDir = "/opt/cni/bin"
	// CustomConfDir Kubernetes CNI conf location for custom (default)
	CustomConfDir = "/etc/cni/net.d"

	// EksCniBinDir Kubernetes CNI bin location for EKS
	EksCniBinDir = "/opt/cni/bin"
	// EksConfDir Kubernetes CNI conf location for EKS
	EksConfDir = "/etc/cni/net.d"

	// GkeCniBinDir Kubernetes CNI bin location for GKE
	GkeCniBinDir = "/home/kubernetes/bin"
	// GkeConfDir Kubernetes CNI conf location for GKE
	GkeConfDir = "/etc/cni/net.d"

	// AksCniBinDir Kubernetes CNI bin location for AKS
	AksCniBinDir = "/opt/cni/bin"
	// AksConfDir Kubernetes CNI conf location for AKS
	AksConfDir = "/etc/cni/net.d"

	// Ocp4CniBinDir Kubernetes CNI bin location for OC4 (OpenShift)
	Ocp4CniBinDir = "/var/lib/cni/bin"
	// Ocp4ConfDir Kubernetes CNI conf location or OC4 (OpenShift)
	Ocp4ConfDir = "/etc/kubernetes/cni/net.d"

	// TkgiCniBinDir Kubernetes CNI bin location for TKG
	TkgiCniBinDir = "/var/vcap/jobs/kubelet/packages/cni/bin"
	// TkgiConfDir Kubernetes CNI conf location for TKG
	TkgiConfDir = "/etc/cni/net.d"
)

// Builder the Builder
type Builder struct {
	volumes                           []*k8sapccore1.VolumeApplyConfiguration
	volumeMounts                      []*k8sapccore1.VolumeMountApplyConfiguration
	envVars                           []*k8sapccore1.EnvVarApplyConfiguration
	enforcerdNamespace                string
	enforcerdLogLevel                 string
	enforcerdLogFormat                string
	enforcerdAPI                      string
	cniBinDir                         string
	cniConfDir                        string
	args                              []string
	enforcerdTransmitterQueueCount    int32
	enforcerdReceiverQueueCount       int32
	enforcerdFlowReportingInterval    string
	enforcerdAPISkipVerify            bool
	enforcerdActivateKubeSystemPus    bool
	enforcerdActivateOpenShiftPus     bool
	enforcerdKubernetesMonitorWorkers int32
	enforcerdInstallCniPlugin         string
	enforcerdInstallRuncProxy         string
	enforcerdCniChained               bool
	enforcerdCniMultusDefaultNetwork  bool
	enforcerdCniConfFilename          string
	enforcerdCniPrimaryConfFile       string
}

// WithEnforcerdNamespace returns Builder with namespace as specified
func (t *Builder) WithEnforcerdNamespace(enforcerdNamespace string) *Builder {
	t.enforcerdNamespace = enforcerdNamespace
	return t
}

// WithEnforcerdAPI returns Builder with Enforcer API as specified
func (t *Builder) WithEnforcerdAPI(enforcerdAPI string) *Builder {
	t.enforcerdAPI = enforcerdAPI
	return t
}

// WithEnforcerdLogLevelInfo returns Builder with Log Level Info
func (t *Builder) WithEnforcerdLogLevelInfo() *Builder {
	t.enforcerdLogLevel = "info"
	return t
}

// WithEnforcerdLogLevelDebug returns Builder with Log Level Debug
func (t *Builder) WithEnforcerdLogLevelDebug() *Builder {
	t.enforcerdLogLevel = "debug"
	return t
}

// WithCNIBinDir returns Builder with CNI bin dir as specified
func (t *Builder) WithCNIBinDir(cniBinDir string) *Builder {
	t.cniBinDir = cniBinDir
	return t
}

// WithCNIConfDir returns Builder with CNI conf dir as specified
func (t *Builder) WithCNIConfDir(cniConfDir string) *Builder {
	t.cniConfDir = cniConfDir
	return t
}

// WithEnforcerdTransmitterQueueCount returns Builder with Enforcer transmitter queue count as specified
func (t *Builder) WithEnforcerdTransmitterQueueCount(enforcerdTransmitterQueueCount int32) *Builder {
	t.enforcerdTransmitterQueueCount = enforcerdTransmitterQueueCount
	return t
}

// WithEnforcerdReceiverQueueCount returns Builder with Enforcer receiver queue count as specified
func (t *Builder) WithEnforcerdReceiverQueueCount(enforcerdReceiverQueueCount int32) *Builder {
	t.enforcerdReceiverQueueCount = enforcerdReceiverQueueCount
	return t
}

// WithEnforcerdFlowReportingInterval returns Builder with Enforcer flow reporting interval as specified
func (t *Builder) WithEnforcerdFlowReportingInterval(enforcerdFlowReportingInterval string) *Builder {
	t.enforcerdFlowReportingInterval = enforcerdFlowReportingInterval
	return t
}

// WithnforcerdAPISkipVerify returns Builder with Enforcer API skip verify as specified
func (t *Builder) WithnforcerdAPISkipVerify(enforcerdAPISkipVerify bool) *Builder {
	t.enforcerdAPISkipVerify = enforcerdAPISkipVerify
	return t
}

// WithEnforcerdActivateKubeSystemPUS returns Builder with Enforcer activate kube systems processing units as specified
func (t *Builder) WithEnforcerdActivateKubeSystemPUS(enforcerdActivateKubeSystemPus bool) *Builder {
	t.enforcerdActivateKubeSystemPus = enforcerdActivateKubeSystemPus
	return t
}

// WithEnforcerdActivateOpenShiftPUS returns Builder with Enforcer activate Open Shift processing units as specified
func (t *Builder) WithEnforcerdActivateOpenShiftPUS(enforcerdActivateOpenShiftPus bool) *Builder {
	t.enforcerdActivateOpenShiftPus = enforcerdActivateOpenShiftPus
	return t
}

// WithEnforcerdKubernetesMonitorWorkers returns Builder with Enforcer kubernetes monitor workers count as specified
func (t *Builder) WithEnforcerdKubernetesMonitorWorkers(enforcerdKubernetesMonitorWorkers int32) *Builder {
	t.enforcerdKubernetesMonitorWorkers = enforcerdKubernetesMonitorWorkers
	return t
}

// WithEnforcerdInstallCNIPlugin returns Builder with Enforcer CNI plugin as specified
func (t *Builder) WithEnforcerdInstallCNIPlugin(enforcerdInstallCniPlugin string) *Builder {
	t.enforcerdInstallCniPlugin = enforcerdInstallCniPlugin
	return t
}

// WithEnforcerdInstallRuncProxy returns Builder with Enforcer install Runc proxy as specified
func (t *Builder) WithEnforcerdInstallRuncProxy(enforcerdInstallRuncProxy string) *Builder {
	t.enforcerdInstallRuncProxy = enforcerdInstallRuncProxy
	return t
}

// WithEnforcerdCNIChained returns Builder with Enforcer CNI chained as specified
func (t *Builder) WithEnforcerdCNIChained(enforcerdCniChained bool) *Builder {
	t.enforcerdCniChained = enforcerdCniChained
	return t
}

// WithEnforcerdCNIMultusDefaultNetwork returns Builder with Enforcer CNI Multus default network as specified
func (t *Builder) WithEnforcerdCNIMultusDefaultNetwork(enforcerdCniMultusDefaultNetwork bool) *Builder {
	t.enforcerdCniMultusDefaultNetwork = enforcerdCniMultusDefaultNetwork
	return t
}

// WithEnforcerdCNIConfFilename returns Builder with Enforcer CNI conf filename as specified
func (t *Builder) WithEnforcerdCNIConfFilename(enforcerdCniConfFilename string) *Builder {
	t.enforcerdCniConfFilename = enforcerdCniConfFilename
	return t
}

// WithEnforcerdCNIPrimaryConfFile returns Builder with Enforcer CNI primary conf file as specified
func (t *Builder) WithEnforcerdCNIPrimaryConfFile(enforcerdCniPrimaryConfFile string) *Builder {
	t.enforcerdCniPrimaryConfFile = enforcerdCniPrimaryConfFile
	return t
}

func (t *Builder) addVolume(v *k8sapccore1.VolumeApplyConfiguration) *Builder {
	t.volumes = append(t.volumes, v)
	return t
}

func (t *Builder) addVolumeMount(v *k8sapccore1.VolumeMountApplyConfiguration) *Builder {
	t.volumeMounts = append(t.volumeMounts, v)
	return t
}

func (t *Builder) addEnvVar(v *k8sapccore1.EnvVarApplyConfiguration) *Builder {
	t.envVars = append(t.envVars, v)
	return t
}

func newDefault() *Builder {

	return &Builder{
		enforcerdLogLevel:                 EnforcerdLogLevelDefault,
		enforcerdLogFormat:                EnforcerdLogFormatDefault,
		enforcerdTransmitterQueueCount:    2,
		enforcerdReceiverQueueCount:       2,
		enforcerdFlowReportingInterval:    "5m",
		enforcerdAPISkipVerify:            false,
		enforcerdActivateKubeSystemPus:    false,
		enforcerdActivateOpenShiftPus:     false,
		enforcerdKubernetesMonitorWorkers: 4,
		enforcerdInstallCniPlugin:         "",
		enforcerdInstallRuncProxy:         "",
		enforcerdCniChained:               true,
		enforcerdCniMultusDefaultNetwork:  false,
		enforcerdCniConfFilename:          "",
		enforcerdCniPrimaryConfFile:       "",
	}

}

// NewEks returns Builder for AWS EKS
func NewEks(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--tag=clustertype=eks")
	b.cniBinDir = EksCniBinDir
	b.cniConfDir = EksConfDir
	return b
}

// NewGke returns Builder for GCP GKE
func NewGke(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--tag=clustertype=gke")
	b.cniBinDir = GkeCniBinDir
	b.cniConfDir = GkeConfDir
	return b
}

// NewAks returns Builder for Azure AKS
func NewAks(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--tag=clustertype=aks")
	b.cniBinDir = AksCniBinDir
	b.cniConfDir = AksConfDir
	return b
}

// NewOcp4 returns Builder for Open Shift 4
func NewOcp4(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--tag=clustertype=ocp4")
	b.cniBinDir = Ocp4CniBinDir
	b.cniConfDir = Ocp4ConfDir
	return b
}

// NewTkgi returns Builder for TKGI
func NewTkgi(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--default-docker-configpath=/var/vcap/store/docker/docker")
	b.args = append(b.args, "--tag=clustertype=tkgi")
	b.cniBinDir = TkgiCniBinDir
	b.cniConfDir = TkgiConfDir
	return b
}

// NewCustom returns Builder for custom
func NewCustom(enforcerdNamespace, enforcerdAPI string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdAPI = enforcerdAPI
	b.args = append(b.args, "--tag=clustertype=custom")
	b.cniBinDir = CustomCniBinDir
	b.cniConfDir = CustomConfDir
	return b
}

// Build returns Enforcer Kubernetes Daemonset
func (t *Builder) Build() *types.EnforcerdDaemonset {

	t.
		addVolume(k8sapccore1.Volume().WithName("working-dir").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath("/var/lib/prisma-enforcer/enforcerd").WithType(k8scorev1.HostPathDirectoryOrCreate))).
		addVolume(k8sapccore1.Volume().WithName("cni-bin-dir").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath(t.cniBinDir))).
		addVolume(k8sapccore1.Volume().WithName("cni-conf-dir").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath(t.cniConfDir))).
		addVolume(k8sapccore1.Volume().WithName("var-run").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath("/var/run"))).
		addVolume(k8sapccore1.Volume().WithName("run").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath("/run"))).
		addVolume(k8sapccore1.Volume().WithName("var-lib").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath("/var/lib"))).
		addVolume(k8sapccore1.Volume().WithName("cgroups").WithHostPath(k8sapccore1.HostPathVolumeSource().WithPath("/sys/fs/cgroup"))).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("working-dir").WithMountPath("/var/lib/prisma-enforcer/enforcerd")).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("cni-bin-dir").WithMountPath(t.cniBinDir)).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("cni-conf-dir").WithMountPath(t.cniConfDir)).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("cgroups").WithMountPath("/sys/fs/cgroup")).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("var-run").WithMountPath("/var/run").WithMountPropagation(k8scorev1.MountPropagationHostToContainer)).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("run").WithMountPath("/run").WithMountPropagation(k8scorev1.MountPropagationHostToContainer)).
		addVolumeMount(k8sapccore1.VolumeMount().WithName("var-lib").WithMountPath("/var/lib").WithMountPropagation(k8scorev1.MountPropagationHostToContainer)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_NAMESPACE").WithValue(t.enforcerdNamespace)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_API").WithValue(t.enforcerdAPI)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_FORMAT").WithValue(t.enforcerdLogFormat)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_LEVEL").WithValue(t.enforcerdLogLevel)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_WORKING_DIR").WithValue("/var/lib/prisma-enforcer/enforcerd")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_TO_CONSOLE").WithValue("true")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_ENABLE_KUBERNETES").WithValue("true")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_TRANSMITTER_QUEUE_COUNT").WithValue(strconv.Itoa(int(t.enforcerdTransmitterQueueCount)))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_RECEIVER_QUEUE_COUNT").WithValue(strconv.Itoa(int(t.enforcerdReceiverQueueCount)))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_FLOW_REPORTING_INTERVAL").WithValue(t.enforcerdFlowReportingInterval)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_API_SKIP_VERIFY").WithValue(strconv.FormatBool(t.enforcerdAPISkipVerify))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_ACTIVATE_KUBE_SYSTEM_PUS").WithValue(strconv.FormatBool(t.enforcerdActivateKubeSystemPus))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_ACTIVATE_OPENSHIFT_PUS").WithValue(strconv.FormatBool(t.enforcerdActivateOpenShiftPus))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_KUBERNETES_MONITOR_WORKERS").WithValue(strconv.Itoa(int(t.enforcerdKubernetesMonitorWorkers)))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_INSTALL_CNI_PLUGIN").WithValue(t.enforcerdInstallCniPlugin)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_INSTALL_RUNC_PROXY").WithValue(t.enforcerdInstallRuncProxy)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_BIN_DIR").WithValue(t.cniBinDir)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_CONF_DIR").WithValue(t.cniConfDir)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_CHAINED").WithValue(strconv.FormatBool(t.enforcerdCniChained))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_MULTUS_DEFAULT_NETWORK").WithValue(strconv.FormatBool(t.enforcerdCniMultusDefaultNetwork))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_CONF_FILENAME").WithValue((t.enforcerdCniConfFilename))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_CNI_PRIMARY_CONF_FILE").WithValue(t.enforcerdCniPrimaryConfFile)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_KUBENODE").WithValueFrom(k8sapccore1.EnvVarSource().WithFieldRef(k8sapccore1.ObjectFieldSelector().WithFieldPath("spec.nodeName")))).
		addEnvVar(k8sapccore1.EnvVar().WithName("K8S_POD_NAME").WithValueFrom(k8sapccore1.EnvVarSource().WithFieldRef(k8sapccore1.ObjectFieldSelector().WithFieldPath("metadata.name")))).
		addEnvVar(k8sapccore1.EnvVar().WithName("K8S_POD_NAMESPACE").WithValueFrom(k8sapccore1.EnvVarSource().WithFieldRef(k8sapccore1.ObjectFieldSelector().WithFieldPath("metadata.namespace"))))

	labels := map[string]string{
		"app":      "enforcerd",
		"instance": "enforcerd",
		"vendor":   "aporeto",
	}

	annotations := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/enforcerd": "unconfined",
	}

	securityContext := k8sapccore1.SecurityContext().WithRunAsUser(0).WithRunAsGroup(0).WithReadOnlyRootFilesystem(true).
		WithCapabilities(k8sapccore1.Capabilities().WithAdd("KILL").WithAdd("SYS_PTRACE").WithAdd("NET_ADMIN").
			WithAdd("NET_RAW").WithAdd("SYS_RESOURCE").WithAdd("SYS_ADMIN").WithAdd("SYS_MODULE"))

	container := k8sapccore1.Container().WithName("enforcerd").WithImage("gcr.io/prismacloud-cns/enforcerd:v1.1538.1").
		WithImagePullPolicy(k8scorev1.PullIfNotPresent).WithVolumeMounts(t.volumeMounts...).WithArgs(t.args...).
		WithSecurityContext(securityContext).WithCommand("/enforcerd").WithEnv(t.envVars...)

	podSpec := k8sapccore1.PodSpec().WithVolumes(t.volumes...).WithTerminationGracePeriodSeconds(600).
		WithDNSPolicy(k8scorev1.DNSClusterFirstWithHostNet).WithHostNetwork(true).WithHostPID(true).
		WithServiceAccountName("enforcerd").WithContainers(container)

	template := k8sapccore1.PodTemplateSpec().WithLabels(labels).WithAnnotations(annotations).WithSpec(podSpec)

	spec := k8sapcappsv1.DaemonSetSpec().WithSelector(k8sapcmetav1.LabelSelector().WithMatchLabels(labels)).WithTemplate(template).
		WithUpdateStrategy(k8sapcappsv1.DaemonSetUpdateStrategy().WithType(k8sappsv1.RollingUpdateDaemonSetStrategyType)).WithMinReadySeconds(0)

	clusterRole := k8sapprbacv1.ClusterRole("enforcerd")

	clusterRole.Rules = append(clusterRole.Rules, k8sapprbacv1.PolicyRuleApplyConfiguration{
		APIGroups: []string{""},
		Resources: []string{"nodes"},
		Verbs:     []string{"get"},
	})

	clusterRole.Rules = append(clusterRole.Rules, k8sapprbacv1.PolicyRuleApplyConfiguration{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list", "watch"},
	})

	clusterRole.Rules = append(clusterRole.Rules, k8sapprbacv1.PolicyRuleApplyConfiguration{
		APIGroups: []string{""},
		Resources: []string{"events"},
		Verbs:     []string{"create", "patch", "update"},
	})

	clusterRoleBinding := k8sapprbacv1.ClusterRoleBinding("enforcerd").
		WithRoleRef(k8sapprbacv1.RoleRef().WithName("enforcerd").WithAPIGroup("rbac.authorization.k8s.io").WithKind("ClusterRole")).
		WithSubjects(k8sapprbacv1.Subject().WithName("enforcerd").WithKind("ServiceAccount").WithNamespace("aporeto"))

	return &types.EnforcerdDaemonset{
		Namespace:          k8sapccore1.Namespace("aporeto"),
		DaemonSet:          k8sapcappsv1.DaemonSet("enforcerd", "aporeto").WithLabels(labels).WithSpec(spec),
		ClusterRoleBinding: clusterRoleBinding,
		ClusterRole:        clusterRole,
		ServiceAccount:     k8sapccore1.ServiceAccount("enforcerd", "aporeto"),
	}

}
