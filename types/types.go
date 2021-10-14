package types

import (
	k8sapcappsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	k8sapccore1 "k8s.io/client-go/applyconfigurations/core/v1"
	k8sapprbacv1 "k8s.io/client-go/applyconfigurations/rbac/v1"
)

// EnforcerdDaemonset includes everything you need to create a Prisma
// Enforcerd Daemonset on a Kubernetes cluster assuming you do not require
// secrets.
type EnforcerdDaemonset struct {
	Namespace          *k8sapccore1.NamespaceApplyConfiguration
	DaemonSet          *k8sapcappsv1.DaemonSetApplyConfiguration
	ClusterRoleBinding *k8sapprbacv1.ClusterRoleBindingApplyConfiguration
	ClusterRole        *k8sapprbacv1.ClusterRoleApplyConfiguration
	ServiceAccount     *k8sapccore1.ServiceAccountApplyConfiguration
}
