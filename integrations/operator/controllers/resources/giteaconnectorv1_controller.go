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

package resources

import (
	"context"

	"github.com/gravitational/trace"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gravitational/teleport/api/client"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	resourcesv1 "github.com/gravitational/teleport/integrations/operator/apis/resources/v1"
	"github.com/gravitational/teleport/integrations/operator/controllers"
	"github.com/gravitational/teleport/integrations/operator/controllers/reconcilers"
	"github.com/gravitational/teleport/integrations/operator/controllers/resources/secretlookup"
)

// giteaConnectorClient implements TeleportResourceClient and offers CRUD
// methods needed to reconcile Gitea connectors.
type giteaConnectorClient struct {
	teleportClient *client.Client
	kubeClient     kclient.Client
}

// Get gets the Teleport Gitea connector of a given name.
func (c giteaConnectorClient) Get(ctx context.Context, key reconcilers.ResourceKey) (*giteaconnectorv1.GiteaConnector, error) {
	connector, err := c.teleportClient.GiteaConnectorServiceClient().GetGiteaConnector(ctx, key.Name, false /* with secrets */)
	return connector, trace.Wrap(err)
}

// Create creates a Teleport Gitea connector.
func (c giteaConnectorClient) Create(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) error {
	_, err := c.teleportClient.GiteaConnectorServiceClient().CreateGiteaConnector(ctx, connector)
	return trace.Wrap(err)
}

// Update updates a Teleport Gitea connector.
func (c giteaConnectorClient) Update(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) error {
	_, err := c.teleportClient.GiteaConnectorServiceClient().UpsertGiteaConnector(ctx, connector)
	return trace.Wrap(err)
}

// Delete deletes a Teleport Gitea connector.
func (c giteaConnectorClient) Delete(ctx context.Context, key reconcilers.ResourceKey) error {
	return trace.Wrap(c.teleportClient.GiteaConnectorServiceClient().DeleteGiteaConnector(ctx, key.Name))
}

// Mutate resolves the client secret from a Kubernetes secret when the
// custom resource references one.
func (c giteaConnectorClient) Mutate(ctx context.Context, new, _ *giteaconnectorv1.GiteaConnector, crKey kclient.ObjectKey) error {
	spec := new.GetSpec()
	if spec == nil {
		return nil
	}
	secret := spec.GetClientSecret()
	if secretlookup.IsNeeded(secret) {
		resolvedSecret, err := secretlookup.Try(ctx, c.kubeClient, crKey.Name, crKey.Namespace, secret)
		if err != nil {
			return trace.Wrap(err)
		}
		spec.SetClientSecret(resolvedSecret)
	}
	return nil
}

// NewGiteaConnectorV1Reconciler instantiates a new Kubernetes controller
// reconciling Gitea connector resources.
func NewGiteaConnectorV1Reconciler(client kclient.Client, tClient *client.Client, _ reconcilers.OperatorMetadata) (controllers.Reconciler, error) {
	giteaClient := &giteaConnectorClient{
		teleportClient: tClient,
		kubeClient:     client,
	}
	resourceReconciler, err := reconcilers.NewTeleportResource153Reconciler[
		*giteaconnectorv1.GiteaConnector, *resourcesv1.TeleportGiteaConnectorV1,
	](
		client,
		giteaClient,
		reconcilers.Config{},
	)
	return resourceReconciler, trace.Wrap(err, "building teleport resource reconciler")
}
