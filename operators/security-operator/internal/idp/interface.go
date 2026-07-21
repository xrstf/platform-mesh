/*
Copyright The Platform Mesh Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package idp

import (
	"context"

	"go.platform-mesh.io/security-operator/internal/idp/dcr"
)

type TenantConfig struct {
	Realm string `json:"realm"`
}

type ListUsersOptions struct {
	Email string `json:"email"`
}

type User struct {
	ID              string       `json:"id,omitempty"`
	Email           string       `json:"email,omitempty"`
	RequiredActions []string     `json:"requiredActions,omitempty"`
	Enabled         bool         `json:"enabled,omitempty"`
	Credentials     []Credential `json:"credentials,omitempty"`
}

type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// Provider defines the interface for an external OIDC provider
type Provider interface {
	// Client Registration (DCR - RFC 7591/7592)
	RegisterClient(ctx context.Context, metadata dcr.ClientMetadata) (dcr.ClientInformation, error)
	GetClient(ctx context.Context, clientID, registrationURI, registrationToken string) (dcr.ClientInformation, error)
	UpdateClient(ctx context.Context, registrationURI, registrationToken string, metadata dcr.ClientMetadata) (dcr.ClientInformation, error)
	DeleteClient(ctx context.Context, clientID, registrationURI, registrationToken string) error

	GetClientByName(ctx context.Context, clientName string) (*clientreg.ClientInformation, error)

	// Realm (org) Management (provider-specific)
	CreateTenant(ctx context.Context, config TenantConfig) (created bool, err error)
	UpdateTenant(ctx context.Context, tenantID string, config TenantConfig) error
	DeleteTenant(ctx context.Context, tenantID string) error
	TenantExists(ctx context.Context, tenantID string) (bool, error)
	EnsureTenant(ctx context.Context, tenantID string, config TenantConfig) error

	// Token Management
	GetInitialAccessToken(ctx context.Context, tenantID string) (string, error)
	RefreshRegistrationToken(ctx context.Context, tenantID, clientID string) (string, error)

	// User Management (SCIM or Userinfo)
	GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error)
	ListUsers(ctx context.Context, tenantID string, opts ListUsersOptions) ([]*User, error)

	// Configuration
	IssuerURL(tenantID string) string
	JWKSURL(tenantID string) string
	AuthorizationEndpoint(tenantID string) string
	TokenEndpoint(tenantID string) string
}
