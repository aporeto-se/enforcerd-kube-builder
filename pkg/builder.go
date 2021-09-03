package core

import (
	"strconv"

	k8sappsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8sapcappsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	k8sapccore1 "k8s.io/client-go/applyconfigurations/core/v1"
	k8sapcmetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	k8sapprbacv1 "k8s.io/client-go/applyconfigurations/rbac/v1"
)

const (
	EnforcerdLogLevelDefault  = "info"
	EnforcerdLogFormatDefault = "json"
	CniBinDirDefault          = "/opt/cni/bin"
	CniConfDirDefault         = "/etc/cni/net.d"
)

type Builder struct {
	volumes                           []*k8sapccore1.VolumeApplyConfiguration
	volumeMounts                      []*k8sapccore1.VolumeMountApplyConfiguration
	envVars                           []*k8sapccore1.EnvVarApplyConfiguration
	enforcerdNamespace                string
	enforcerdLogLevel                 string
	enforcerdLogFormat                string
	enforcerdApi                      string
	cniBinDir                         string
	cniConfDir                        string
	clusterType                       string
	enforcerdTransmitterQueueCount    int32
	enforcerdReceiverQueueCount       int32
	enforcerdFlowReportingInterval    string
	enforcerdApiSkipVerify            bool
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

func (t *Builder) WithEnforcerdNamespace(enforcerdNamespace string) *Builder {
	t.enforcerdNamespace = enforcerdNamespace
	return t
}

func (t *Builder) WithEnforcerdApi(enforcerdApi string) *Builder {
	t.enforcerdApi = enforcerdApi
	return t
}

func (t *Builder) WithEnforcerdLogLevelInfo() *Builder {
	t.enforcerdLogLevel = "info"
	return t
}

func (t *Builder) WithEnforcerdLogLevelDebug() *Builder {
	t.enforcerdLogLevel = "debug"
	return t
}

func (t *Builder) WithCniBinDir(cniBinDir string) *Builder {
	t.cniBinDir = cniBinDir
	return t
}

func (t *Builder) WithCniConfDir(cniConfDir string) *Builder {
	t.cniConfDir = cniConfDir
	return t
}

// func (t *Builder) WithClusterTypeCustom(clusterType string) *Builder {
// 	t.clusterType = clusterType
// 	return t
// }

func (t *Builder) WithEnforcerdTransmitterQueueCount(enforcerdTransmitterQueueCount int32) *Builder {
	t.enforcerdTransmitterQueueCount = enforcerdTransmitterQueueCount
	return t
}

func (t *Builder) WithEnforcerdReceiverQueueCount(enforcerdReceiverQueueCount int32) *Builder {
	t.enforcerdReceiverQueueCount = enforcerdReceiverQueueCount
	return t
}

func (t *Builder) WithEnforcerdFlowReportingInterval(enforcerdFlowReportingInterval string) *Builder {
	t.enforcerdFlowReportingInterval = enforcerdFlowReportingInterval
	return t
}

func (t *Builder) WithnforcerdApiSkipVerify(enforcerdApiSkipVerify bool) *Builder {
	t.enforcerdApiSkipVerify = enforcerdApiSkipVerify
	return t
}

func (t *Builder) WithEnforcerdActivateKubeSystemPus(enforcerdActivateKubeSystemPus bool) *Builder {
	t.enforcerdActivateKubeSystemPus = enforcerdActivateKubeSystemPus
	return t
}

func (t *Builder) WithEnforcerdActivateOpenShiftPus(enforcerdActivateOpenShiftPus bool) *Builder {
	t.enforcerdActivateOpenShiftPus = enforcerdActivateOpenShiftPus
	return t
}

func (t *Builder) WithEnforcerdKubernetesMonitorWorkers(enforcerdKubernetesMonitorWorkers int32) *Builder {
	t.enforcerdKubernetesMonitorWorkers = enforcerdKubernetesMonitorWorkers
	return t
}

func (t *Builder) WithEnforcerdInstallCniPlugin(enforcerdInstallCniPlugin string) *Builder {
	t.enforcerdInstallCniPlugin = enforcerdInstallCniPlugin
	return t
}

func (t *Builder) WithEnforcerdInstallRuncProxy(enforcerdInstallRuncProxy string) *Builder {
	t.enforcerdInstallRuncProxy = enforcerdInstallRuncProxy
	return t
}

func (t *Builder) WithEnforcerdCniChained(enforcerdCniChained bool) *Builder {
	t.enforcerdCniChained = enforcerdCniChained
	return t
}

func (t *Builder) WithEnforcerdCniMultusDefaultNetwork(enforcerdCniMultusDefaultNetwork bool) *Builder {
	t.enforcerdCniMultusDefaultNetwork = enforcerdCniMultusDefaultNetwork
	return t
}

func (t *Builder) WithEnforcerdCniConfFilename(enforcerdCniConfFilename string) *Builder {
	t.enforcerdCniConfFilename = enforcerdCniConfFilename
	return t
}

func (t *Builder) WithEnforcerdCniPrimaryConfFile(enforcerdCniPrimaryConfFile string) *Builder {
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
		cniBinDir:                         CniBinDirDefault,
		cniConfDir:                        CniConfDirDefault,
		enforcerdTransmitterQueueCount:    2,
		enforcerdReceiverQueueCount:       2,
		enforcerdFlowReportingInterval:    "5m",
		enforcerdApiSkipVerify:            false,
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

func NewEks(enforcerdNamespace, enforcerdApi string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdApi = enforcerdApi
	b.clusterType = "eks"
	return b
}

func NewGke(enforcerdNamespace, enforcerdApi string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdApi = enforcerdApi
	b.clusterType = "gke"
	return b
}

func NewAks(enforcerdNamespace, enforcerdApi string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdApi = enforcerdApi
	b.clusterType = "aks"
	return b
}

func NewCustom(enforcerdNamespace, enforcerdApi string) *Builder {
	b := newDefault()
	b.enforcerdNamespace = enforcerdNamespace
	b.enforcerdApi = enforcerdApi
	b.clusterType = "custom"
	return b
}

func (t *Builder) Build() *EnforcerdDaemonset {

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
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_API").WithValue(t.enforcerdApi)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_FORMAT").WithValue(t.enforcerdLogFormat)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_LEVEL").WithValue(t.enforcerdLogLevel)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_WORKING_DIR").WithValue("/var/lib/prisma-enforcer/enforcerd")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_LOG_TO_CONSOLE").WithValue("true")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_ENABLE_KUBERNETES").WithValue("true")).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_TRANSMITTER_QUEUE_COUNT").WithValue(strconv.Itoa(int(t.enforcerdTransmitterQueueCount)))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_RECEIVER_QUEUE_COUNT").WithValue(strconv.Itoa(int(t.enforcerdReceiverQueueCount)))).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_FLOW_REPORTING_INTERVAL").WithValue(t.enforcerdFlowReportingInterval)).
		addEnvVar(k8sapccore1.EnvVar().WithName("ENFORCERD_API_SKIP_VERIFY").WithValue(strconv.FormatBool(t.enforcerdApiSkipVerify))).
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
		WithImagePullPolicy(k8scorev1.PullIfNotPresent).WithVolumeMounts(t.volumeMounts...).WithArgs("--tag=clustertype=" + t.clusterType).
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

	return &EnforcerdDaemonset{
		Namespace:          k8sapccore1.Namespace("aporeto"),
		DaemonSet:          k8sapcappsv1.DaemonSet("enforcerd", "aporeto").WithLabels(labels).WithSpec(spec),
		ClusterRoleBinding: clusterRoleBinding,
		ClusterRole:        clusterRole,
		ServiceAccount:     k8sapccore1.ServiceAccount("enforcerd", "aporeto"),
	}

}
