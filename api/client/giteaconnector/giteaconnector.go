// Copyright 2025 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package giteaconnector provides a client for managing Gitea auth
// connectors with plain method signatures.
package giteaconnector

import (
	"context"

	"github.com/gravitational/trace"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
)

// Client is a client for the Gitea connector service.
type Client struct {
	grpcClient giteaconnectorv1.GiteaConnectorServiceClient
}

// NewClient creates a new Gitea connector client.
func NewClient(grpcClient giteaconnectorv1.GiteaConnectorServiceClient) *Client {
	return &Client{grpcClient: grpcClient}
}

// GetGiteaConnector returns a Gitea connector by name. The client secret is
// only included when withSecrets is true.
func (c *Client) GetGiteaConnector(ctx context.Context, name string, withSecrets bool) (*giteaconnectorv1.GiteaConnector, error) {
	connector, err := c.grpcClient.GetGiteaConnector(ctx, giteaconnectorv1.GetGiteaConnectorRequest_builder{
		Name:        name,
		WithSecrets: withSecrets,
	}.Build())
	return connector, trace.Wrap(err)
}

// ListGiteaConnectors returns a page of Gitea connectors.
func (c *Client) ListGiteaConnectors(ctx context.Context, pageSize int, pageToken string, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, string, error) {
	resp, err := c.grpcClient.ListGiteaConnectors(ctx, giteaconnectorv1.ListGiteaConnectorsRequest_builder{
		PageSize:    int32(pageSize),
		PageToken:   pageToken,
		WithSecrets: withSecrets,
	}.Build())
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return resp.GetConnectors(), resp.GetNextPageToken(), nil
}

// CreateGiteaConnector creates a new Gitea connector.
func (c *Client) CreateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	created, err := c.grpcClient.CreateGiteaConnector(ctx, giteaconnectorv1.CreateGiteaConnectorRequest_builder{
		Connector: connector,
	}.Build())
	return created, trace.Wrap(err)
}

// UpdateGiteaConnector updates an existing Gitea connector. The update fails
// if the connector's revision does not match the stored one.
func (c *Client) UpdateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	updated, err := c.grpcClient.UpdateGiteaConnector(ctx, giteaconnectorv1.UpdateGiteaConnectorRequest_builder{
		Connector: connector,
	}.Build())
	return updated, trace.Wrap(err)
}

// UpsertGiteaConnector creates or replaces a Gitea connector.
func (c *Client) UpsertGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	upserted, err := c.grpcClient.UpsertGiteaConnector(ctx, giteaconnectorv1.UpsertGiteaConnectorRequest_builder{
		Connector: connector,
	}.Build())
	return upserted, trace.Wrap(err)
}

// DeleteGiteaConnector deletes a Gitea connector by name.
func (c *Client) DeleteGiteaConnector(ctx context.Context, name string) error {
	_, err := c.grpcClient.DeleteGiteaConnector(ctx, giteaconnectorv1.DeleteGiteaConnectorRequest_builder{
		Name: name,
	}.Build())
	return trace.Wrap(err)
}
