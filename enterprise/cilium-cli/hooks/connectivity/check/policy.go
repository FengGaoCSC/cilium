//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	"errors"
	"fmt"
	"strings"

	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	enterpriseK8s "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/k8s"
)

// createOrUpdateIEGP creates the IEGP and updates it if it already exists.
func createOrUpdateIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	// Creating, so a resource will definitely be modified.
	_, err := client.CreateIsovalentEgressGatewayPolicy(ctx, iegp, metav1.CreateOptions{})
	if err == nil {
		// Early exit.
		return nil
	}

	if !k8serrors.IsAlreadyExists(err) {
		// A real error happened.
		return err
	}

	// Policy already exists, let's retrieve it.
	policy, err := client.GetIsovalentEgressGatewayPolicy(ctx, iegp.Name, metav1.GetOptions{})
	if err != nil {
		// A real error happened.
		return fmt.Errorf("failed to retrieve isovalent egress gateway policy %s: %w", iegp.Name, err)
	}

	// Overload the field that should stay unchanged.
	policy.ObjectMeta.Labels = iegp.ObjectMeta.Labels
	policy.Spec = iegp.Spec

	// Let's update the policy.
	_, err = client.UpdateIsovalentEgressGatewayPolicy(ctx, policy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update isovalent egress gateway policy %s: %w", iegp.Name, err)
	}

	return nil
}

// deleteIEGP deletes a CiliumEgressGatewayPolicy from the cluster.
func deleteIEGP(ctx context.Context, client *enterpriseK8s.EnterpriseClient, iegp *isovalentv1.IsovalentEgressGatewayPolicy) error {
	if err := client.DeleteIsovalentEgressGatewayPolicy(ctx, iegp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s policy delete failed: %w", client.ClusterName(), iegp.Name, err)
	}

	return nil
}

// addiegps adds one or more CiliumEgressGatewayPolicy resources to the Test.
func (t *EnterpriseTest) addIEGPs(iegps ...*isovalentv1.IsovalentEgressGatewayPolicy) error {
	for _, p := range iegps {
		if p == nil {
			return errors.New("cannot add nil IsovalentEgressGatewayPolicy to test")
		}
		if p.Name == "" {
			return fmt.Errorf("adding IsovalentEgressGatewayPolicy with empty name to test: %v", p)
		}
		if _, ok := t.iegps[p.Name]; ok {
			return fmt.Errorf("IsovalentEgressGatewayPolicy with name %s already in test scope", p.Name)
		}

		t.iegps[p.Name] = p
	}

	return nil
}

// applyPolicies applies all the Test's registered network policies.
func (t *EnterpriseTest) applyPolicies(ctx context.Context) error {
	if len(t.iegps) == 0 {
		return nil
	}

	// Apply all given Cilium Egress Gateway Policies.
	for _, iegp := range t.iegps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumEgressGatewayPolicy '%s' to namespace '%s'..", iegp.Name, iegp.Namespace)
			if err := createOrUpdateIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	// If we return a cleanup closure from this function, cleanup cannot be
	// performed if the user cancels during the policy revision wait time.
	t.WithFinalizer(func() error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deletePolicies(context.TODO()); err != nil {
			t.CiliumLogs(ctx)
			return err
		}

		return nil
	})

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully applied %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *EnterpriseTest) deletePolicies(ctx context.Context) error {
	if len(t.iegps) == 0 {
		return nil
	}

	// Delete all the Test's iegps from all clients.
	for _, iegp := range t.iegps {
		t.Infof("📜 Deleting CiliumEgressGatewayPolicy '%s' from namespace '%s'..", iegp.Name, iegp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteIEGP(ctx, client, iegp); err != nil {
				return fmt.Errorf("deleting CiliumEgressGatewayPolicy: %w", err)
			}
		}
	}

	if len(t.iegps) > 0 {
		t.Debugf("📜 Successfully deleted %d IsovalentEgressGatewayPolicies", len(t.iegps))
	}

	return nil
}

// parseIsovalentEgressGatewayPolicyYAML decodes policy yaml into a slice of
// IsovalentEgressGatewayPolicies.
func parseIsovalentEgressGatewayPolicyYAML(policy string) (iegps []*isovalentv1.IsovalentEgressGatewayPolicy, err error) {
	if policy == "" {
		return nil, nil
	}

	yamls := strings.Split(policy, "\n---")

	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}

		obj, kind, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding policy yaml: %s\nerror: %w", yaml, err)
		}

		switch policy := obj.(type) {
		case *isovalentv1.IsovalentEgressGatewayPolicy:
			iegps = append(iegps, policy)
		default:
			return nil, fmt.Errorf("unknown policy type '%s' in: %s", kind.Kind, yaml)
		}
	}

	return iegps, nil
}
