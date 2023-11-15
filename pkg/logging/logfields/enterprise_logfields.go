package logfields

const (
	// GatewayIPs is a list of gateway IPs belonging to a given egress policy
	GatewayIPs = "gatewayIPs"

	// CiliumEgressGatewayPolicyName is the name of a CiliumEgressGatewayPolicy
	IsovalentEgressGatewayPolicyName = "isovalentEgressGatewayPolicyName"

	// K8sGeneration is the metadata.generation of a k8s resource.
	K8sGeneration = "k8sGeneration"
)
