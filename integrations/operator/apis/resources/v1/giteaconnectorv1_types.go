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

package v1

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integrations/operator/apis/resources/teleportcr"
)

func init() {
	SchemeBuilder.Register(&TeleportGiteaConnectorV1{}, &TeleportGiteaConnectorV1List{})
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// TeleportGiteaConnectorV1 holds the kubernetes custom resources for
// GiteaConnector
type TeleportGiteaConnectorV1 struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   *TeleportGiteaConnectorV1Spec `json:"spec,omitempty"`
	Status teleportcr.Status             `json:"status"`
}

// TeleportGiteaConnectorV1Spec defines the desired state of TeleportGiteaConnectorV1
type TeleportGiteaConnectorV1Spec giteaconnectorv1.GiteaConnectorSpec

//+kubebuilder:object:root=true

// TeleportGiteaConnectorV1List contains a list of TeleportGiteaConnectorV1
type TeleportGiteaConnectorV1List struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TeleportGiteaConnectorV1 `json:"items"`
}

// ToTeleport returns the [giteaconnectorv1.GiteaConnector] represented by the
// custom resource.
func (c *TeleportGiteaConnectorV1) ToTeleport() *giteaconnectorv1.GiteaConnector {
	return giteaconnectorv1.GiteaConnector_builder{
		Kind:    types.KindGitea,
		Version: types.V1,
		Metadata: headerv1.Metadata_builder{
			Name:        c.Name,
			Description: c.Annotations[teleportcr.DescriptionKey],
			Labels:      c.Labels,
		}.Build(),
		Spec: (*giteaconnectorv1.GiteaConnectorSpec)(c.Spec),
	}.Build()
}

// StatusConditions returns a pointer to Status.Conditions slice. This is used
// by the teleport resource controller to report conditions back to on resource.
func (c *TeleportGiteaConnectorV1) StatusConditions() *[]metav1.Condition {
	return &c.Status.Conditions
}

// UnmarshalJSON delegates unmarshaling of the GiteaConnectorSpec to protojson,
// which is necessary for proto RFD153 resources to be unmarshaled correctly
// from the unstructured object.
func (spec *TeleportGiteaConnectorV1Spec) UnmarshalJSON(data []byte) error {
	return protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}.Unmarshal(data, (*giteaconnectorv1.GiteaConnectorSpec)(spec))
}

// MarshalJSON delegates marshaling of the GiteaConnectorSpec to protojson,
// which is necessary for proto RFD153 resources to be marshaled correctly
// into the unstructured object.
func (spec *TeleportGiteaConnectorV1Spec) MarshalJSON() ([]byte, error) {
	return protojson.MarshalOptions{
		UseProtoNames: true,
	}.Marshal((*giteaconnectorv1.GiteaConnectorSpec)(spec))
}

// DeepCopyInto deep-copies one spec into another.
// Required to satisfy runtime.Object interface.
func (spec *TeleportGiteaConnectorV1Spec) DeepCopyInto(out *TeleportGiteaConnectorV1Spec) {
	proto.Reset((*giteaconnectorv1.GiteaConnectorSpec)(out))
	proto.Merge((*giteaconnectorv1.GiteaConnectorSpec)(out), (*giteaconnectorv1.GiteaConnectorSpec)(spec))
}
