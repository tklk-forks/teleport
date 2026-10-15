/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package resources_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	resourcesv1 "github.com/gravitational/teleport/integrations/operator/apis/resources/v1"
	"github.com/gravitational/teleport/integrations/operator/controllers/reconcilers"
	"github.com/gravitational/teleport/integrations/operator/controllers/resources"
	"github.com/gravitational/teleport/integrations/operator/controllers/resources/secretlookup"
	"github.com/gravitational/teleport/integrations/operator/controllers/resources/testlib"
)

func newGiteaConnectorSpec() *giteaconnectorv1.GiteaConnectorSpec {
	return giteaconnectorv1.GiteaConnectorSpec_builder{
		ClientId:     "client id",
		ClientSecret: "client secret",
		RedirectUrl:  "https://redirect.example.com/v1/webapi/gitea/callback",
		EndpointUrl:  "https://gitea.example.com",
		TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
			giteaconnectorv1.GiteaTeamRolesMapping_builder{
				Organization: "test",
				Team:         "test",
				Roles:        []string{"test"},
			}.Build(),
		},
	}.Build()
}

type giteaConnectorTestingPrimitives struct {
	setup *testSetup
	reconcilers.Resource153Adapter[*giteaconnectorv1.GiteaConnector]
}

func (g *giteaConnectorTestingPrimitives) Init(setup *testSetup) {
	g.setup = setup
}

func (g *giteaConnectorTestingPrimitives) SetupTeleportFixtures(ctx context.Context) error {
	return nil
}

func (g *giteaConnectorTestingPrimitives) CreateTeleportResource(ctx context.Context, name string) error {
	connector := giteaconnectorv1.GiteaConnector_builder{
		Kind:    types.KindGitea,
		Version: types.V1,
		Metadata: headerv1.Metadata_builder{
			Name: name,
			Labels: map[string]string{
				types.OriginLabel: types.OriginKubernetes,
			},
		}.Build(),
		Spec: newGiteaConnectorSpec(),
	}.Build()
	_, err := g.setup.TeleportClient.GiteaConnectorServiceClient().CreateGiteaConnector(ctx, connector)
	return trace.Wrap(err)
}

func (g *giteaConnectorTestingPrimitives) GetTeleportResource(ctx context.Context, name string) (*giteaconnectorv1.GiteaConnector, error) {
	connector, err := g.setup.TeleportClient.GiteaConnectorServiceClient().GetGiteaConnector(ctx, name, true)
	return connector, trace.Wrap(err)
}

func (g *giteaConnectorTestingPrimitives) DeleteTeleportResource(ctx context.Context, name string) error {
	return trace.Wrap(g.setup.TeleportClient.GiteaConnectorServiceClient().DeleteGiteaConnector(ctx, name))
}

func (g *giteaConnectorTestingPrimitives) CreateKubernetesResource(ctx context.Context, name string) error {
	connector := &resourcesv1.TeleportGiteaConnectorV1{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.Namespace.Name,
		},
		Spec: (*resourcesv1.TeleportGiteaConnectorV1Spec)(newGiteaConnectorSpec()),
	}
	return trace.Wrap(g.setup.K8sClient.Create(ctx, connector))
}

func (g *giteaConnectorTestingPrimitives) DeleteKubernetesResource(ctx context.Context, name string) error {
	connector := &resourcesv1.TeleportGiteaConnectorV1{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.Namespace.Name,
		},
	}
	return trace.Wrap(g.setup.K8sClient.Delete(ctx, connector))
}

func (g *giteaConnectorTestingPrimitives) GetKubernetesResource(ctx context.Context, name string) (*resourcesv1.TeleportGiteaConnectorV1, error) {
	connector := &resourcesv1.TeleportGiteaConnectorV1{}
	obj := kclient.ObjectKey{
		Name:      name,
		Namespace: g.setup.Namespace.Name,
	}
	err := g.setup.K8sClient.Get(ctx, obj, connector)
	return connector, trace.Wrap(err)
}

func (g *giteaConnectorTestingPrimitives) ModifyKubernetesResource(ctx context.Context, name string) error {
	connector, err := g.GetKubernetesResource(ctx, name)
	if err != nil {
		return trace.Wrap(err)
	}
	spec := (*giteaconnectorv1.GiteaConnectorSpec)(connector.Spec)
	spec.GetTeamsToRoles()[0].SetRoles([]string{"foo", "bar"})
	return trace.Wrap(g.setup.K8sClient.Update(ctx, connector))
}

func (g *giteaConnectorTestingPrimitives) CompareTeleportAndKubernetesResource(
	tResource *giteaconnectorv1.GiteaConnector,
	kubeResource *resourcesv1.TeleportGiteaConnectorV1,
) (bool, string) {
	diff := cmp.Diff(
		tResource,
		kubeResource.ToTeleport(),
		testlib.ProtoCompareOptions()...,
	)
	return diff == "", diff
}

func TestGiteaConnectorCreation(t *testing.T) {
	test := &giteaConnectorTestingPrimitives{}
	testlib.ResourceCreationSynchronousTest[*giteaconnectorv1.GiteaConnector, *resourcesv1.TeleportGiteaConnectorV1](t, resources.NewGiteaConnectorV1Reconciler, test)
}

func TestGiteaConnectorDeletion(t *testing.T) {
	test := &giteaConnectorTestingPrimitives{}
	testlib.ResourceDeletionSynchronousTest[*giteaconnectorv1.GiteaConnector, *resourcesv1.TeleportGiteaConnectorV1](t, resources.NewGiteaConnectorV1Reconciler, test)
}

func TestGiteaConnectorDeletionDrift(t *testing.T) {
	test := &giteaConnectorTestingPrimitives{}
	testlib.ResourceDeletionDriftSynchronousTest[*giteaconnectorv1.GiteaConnector, *resourcesv1.TeleportGiteaConnectorV1](t, resources.NewGiteaConnectorV1Reconciler, test)
}

func TestGiteaConnectorUpdate(t *testing.T) {
	test := &giteaConnectorTestingPrimitives{}
	testlib.ResourceUpdateTestSynchronous[*giteaconnectorv1.GiteaConnector, *resourcesv1.TeleportGiteaConnectorV1](t, resources.NewGiteaConnectorV1Reconciler, test)
}

func TestGiteaConnectorSecretLookup(t *testing.T) {
	test := &giteaConnectorTestingPrimitives{}
	setup := testlib.SetupFakeKubeTestEnv(t)
	test.Init(setup)
	ctx := context.Background()

	crName := validRandomResourceName("gitea")
	secretName := validRandomResourceName("gitea-secret")
	secretKey := "client-secret"
	secretValue := validRandomResourceName("secret-value")

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: setup.Namespace.Name,
			Annotations: map[string]string{
				secretlookup.AllowLookupAnnotation: crName,
			},
		},
		// Real kube servers convert stringData into data.
		// The fake client does not, so we must use Data instead.
		Data: map[string][]byte{
			secretKey: []byte(secretValue),
		},
		Type: v1.SecretTypeOpaque,
	}
	kubeClient := setup.K8sClient
	require.NoError(t, kubeClient.Create(ctx, secret))

	spec := proto.CloneOf(newGiteaConnectorSpec())
	spec.SetClientSecret("secret://" + secretName + "/" + secretKey)
	connector := &resourcesv1.TeleportGiteaConnectorV1{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crName,
			Namespace: setup.Namespace.Name,
		},
		Spec: (*resourcesv1.TeleportGiteaConnectorV1Spec)(spec),
	}
	require.NoError(t, kubeClient.Create(ctx, connector))

	reconciler, err := resources.NewGiteaConnectorV1Reconciler(kubeClient, setup.TeleportClient, setup.OperatorMetadata())
	require.NoError(t, err)
	req := reconcile.Request{
		NamespacedName: apimachinerytypes.NamespacedName{
			Namespace: setup.Namespace.Name,
			Name:      crName,
		},
	}
	// First reconciliation sets the finalizer, the second creates the
	// Teleport resource.
	_, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	_, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)

	testlib.FastEventually(t, func() bool {
		got, err := test.GetTeleportResource(ctx, crName)
		if err != nil {
			return false
		}
		return got.GetSpec().GetClientSecret() == secretValue
	})
}
