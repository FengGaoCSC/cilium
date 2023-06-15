# hubble-flow-policy-metadata

`hubble-flow-policy-metadata` is an Atlantis plugin which annotates forwarded
flows with the metadata of the applied policy.

More specifically, this plugin extends the Hubble `Flow` protobuf definition with
two additional fields, `egress_allowed_by` and `ingress_allowed_by`, of type
`repeated Policy`:

```protobuf
message Policy {
    // name of the Kubernetes NetworkPolicy, CiliumNetworkPolicy, or CiliumClusterwideNetworkPolicy
    string name = 1;
    // namespace of the Kubernetes NetworkPolicy or CiliumNetworkPolicy
    string namespace = 2;
    // labels of the policy rule, e.g. for use with `cilium policy get`
    repeated string labels = 3;
    // revision of the policy repository at the time the event was observed
    uint64 revision = 4;
}
```

Please refer to the [Cilium Network Policy documentation](https://docs.cilium.io/en/stable/policy/)
and the [Policy Troubleshooting guide](https://docs.cilium.io/en/stable/troubleshooting/#policy-troubleshooting)
for more details on how to interpret these fields.

Every `PolicyVerdictNotification` with `Verdict=Forwarded` is annotated
automatically if this plugin is enabled. No additional configuration is
required.

## Examples

### Using the Hubble CLI for interactive troubleshooting

```console
$ # Deploy the example application
$ kubectl create -f  ../../../examples/minikube/http-sw-app.yaml
service/deathstar created
deployment.apps/deathstar created
pod/tiefighter created
pod/xwing created
$ # Install an ingress CiliumNetworkPolicy for the deathstar
$ kubectl create -f examples/kubernetes/deathstar-api-protection.yaml
ciliumnetworkpolicy.cilium.io/deathstar-api-protection created
$ # Install an allow-all egress policy for the tiefighter
$ kubectl create -f examples/kubernetes/tiefighter-egress-policy.yaml
networkpolicy.networking.k8s.io/tiefighter-egress-policy created
$ # Perform a HTTP request from tiefighter to deathstar
$ kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
Ship landed
$ # Query Hubble via CLI to obtain the policies which allowed the request:
$ # The request returns two policy verdicts for that HTTP request,
$ # one for the tiefighter egress, and one for the deathstar ingress.
$  kubectl exec -n kube-system -t -c hubble-cli ds/hubble-cli -- \
        hubble observe --last 2 --follow --type policy-verdict --verdict FORWARDED \
        --from-label class=tiefighter --to-label class=deathstar \
        -o json | jq '{egress_allowed_by,ingress_allowed_by}'
    --from-label class=tiefighter --to-label class=deathstar \
    -o json | jq '{egress_allowed_by,ingress_allowed_by}'
{
  "egress_allowed_by": [
    {
      "name": "tiefighter-egress-policy",
      "namespace": "default",
      "labels": [
        "k8s:io.cilium.k8s.policy.derived-from=NetworkPolicy",
        "k8s:io.cilium.k8s.policy.name=tiefighter-egress-policy",
        "k8s:io.cilium.k8s.policy.namespace=default",
        "k8s:io.cilium.k8s.policy.uid=62075d2d-1e24-4105-a209-ce25f0b9232d"
      ],
      "revision": "7"
    }
  ],
  "ingress_allowed_by": null
}
{
  "egress_allowed_by": null,
  "ingress_allowed_by": [
    {
      "name": "deathstar-api-protection",
      "namespace": "default",
      "labels": [
        "k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
        "k8s:io.cilium.k8s.policy.name=deathstar-api-protection",
        "k8s:io.cilium.k8s.policy.namespace=default",
        "k8s:io.cilium.k8s.policy.uid=04efc4d2-6d0a-45f2-ae5e-225864ca0c4e"
      ],
      "revision": "7"
    }
  ]
}

$ # Inspect the egress policy via K8s by name
$ kubectl get networkpolicy tiefighter-egress-policy
NAME                       POD-SELECTOR                  AGE
tiefighter-egress-policy   class=tiefighter,org=empire   24m
$ # Inspect the ingress policy via Cilium CLI by one of its labels
$ cilium policy get 'k8s:io.cilium.k8s.policy.uid=04efc4d2-6d0a-45f2-ae5e-225864ca0c4e'
[
  {
    "endpointSelector": {
      "matchLabels": {
        "any:class": "deathstar",
        "any:org": "empire",
        "k8s:io.kubernetes.pod.namespace": "default"
      }
    },
    // ...
  }
]
Revision: 7
```

> **Note:** The `egress_allowed_by` and `ingress_allowed_by` fields are only
> available in the JSON output if you use build of the Hubble CLI which has
> this plugin enabled.

> **Note**: Endpoints will only generate `PolicyVerdictNotification`s for
> egress or ingress flows if the endpoint has policies enforced in the direction
> of traffic. Therefore, in the above example you will not observe
> any events without applying the example policies first.

### Exporting policy verdict events with `hubble-flow-export`

The `hubble-flow-export` can be configured to only export
`PolicyVerdictNotification` events with `Verdict=Forwarded` as follows:

    env:
    - name: CILIUM_EXPORT_FLOW_WHITELIST
      value: |-
        {"event_type":[{"type":5}],"verdict":["FORWARDED"]}

> **Note**: `PolicyVerdictNotification` have the numeric event type
> [`5`](https://github.com/cilium/cilium/blob/450c79ce5e2fbdeb32833df45c04bd529ff6ff4b/pkg/monitor/api/types.go#L49-L51)

## Frequently Asked Questions

### Which policy is applied in the case of overlapping policies?

If two or more policies match a specific flow, all of them will be reported,
since the presence of any of them is sufficient for the flow to be allowed.

### Why do drop verdicts not contain any policy metadata?

A connection may be dropped for policy reasons because there exists no policy
which applies. This whitelist-based approach makes it difficult to exactly
determine which rules did not match the dropped flow. Therefore, the current
version of this plugin only supports annotating forwarded flows.

Please refer to the [Policy Troubleshooting guide](https://docs.cilium.io/en/stable/troubleshooting/#policy-troubleshooting)
for more details on how to find the policies which apply to a specific endpoint.

### Where do the `reserved:io.cilium.policy.derived-from` policy labels come from?

As per Cilium's [default policy enforcement mode](https://docs.cilium.io/en/stable/policy/intro/),
endpoints start without any restrictions on either egress or ingress if no other
policy applies. Therefore, traffic which is allowed by the default policy mode
will have a `reserved:io.cilium.policy.derived-from:allow-any-egress` or
`reserved:io.cilium.policy.derived-from:allow-any-ingress` label in their
respective `egress_allowed_by` or `ingress_allowed_by` fields.

Similarly, endpoints may also allow ingress traffic from localhost if
the [`--allow-localhost`](http://docs.cilium.io/en/stable/policy/language/#access-to-from-local-host)
cilium-agent option is set accordingly. This results in the virtual
`reserved:io.cilium.policy.derived-from=allow-localhost-ingress` policy label.

Endpoints which have a [visibility policy](https://docs.cilium.io/en/stable/policy/visibility/#l7-protocol-visibility) applied will have egress or ingress allowed by the virtual `reserved:io.cilium.policy.derived-from=visibility-annotation`
policy label.

### Why do I see events with `egress_allowed_by` for flows dropped by an ingress policy?

Cilium enforces the policies for ingress and egress separately. This is
relevant for flows between two Cilium endpoints (i.e. flows between two Kubernetes Pods,
as opposed to e.g. flows to the outside world). For such flows, the Cilium will
reach a policy verdict twice, once for egress, and once for ingress.

Therefore, a flow which is allowed by the egress policy of its source endpoint,
but subsequently dropped by the ingress policy of the destination endpoint will
still  cause a `PolicyVerdictNotification` with `Verdict=Forwarded` and a
non-empty `egress_allowed_by` field on node of the source endpoint.
The ingress drop will emit a separate `PolicyVerdictNotification` with
`Verdict=Dropped` on the node of the destination endpoint.
