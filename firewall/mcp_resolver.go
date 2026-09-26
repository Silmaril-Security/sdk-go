// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"fmt"
	"strings"
)

// MCPResolutionStatus describes the result of resolving an MCP dispatch name.
type MCPResolutionStatus string

const (
	// MCPResolutionResolved means exactly one configured MCP tool matched.
	MCPResolutionResolved MCPResolutionStatus = "resolved"
	// MCPResolutionUnresolved means the dispatch name did not match the supplied catalog.
	MCPResolutionUnresolved MCPResolutionStatus = "unresolved"
	// MCPResolutionAmbiguous means a host alias matched multiple configured MCP tools.
	MCPResolutionAmbiguous MCPResolutionStatus = "ambiguous"
)

// MCPResolution is the explicit outcome of resolving an MCP dispatch name.
// Resource is non-nil only when Status is MCPResolutionResolved.
type MCPResolution struct {
	Status   MCPResolutionStatus
	Resource *Resource
}

// MCPResolver resolves host dispatch spellings against a caller-supplied,
// immutable snapshot of configured MCP tool identities. It does not discover
// or scrape configuration.
type MCPResolver struct {
	exact   map[mcpDispatchKey]Resource
	hosts   map[string]struct{}
	aliases map[string][]string
}

type mcpDispatchKey struct {
	host string
	tool string
}

// NewMCPResolver constructs a resolver from concrete configured MCP tool
// identities. Duplicate identities and non-MCP-tool resources are rejected.
func NewMCPResolver(configured []Resource) (*MCPResolver, error) {
	resolver := &MCPResolver{
		exact:   make(map[mcpDispatchKey]Resource, len(configured)),
		hosts:   make(map[string]struct{}, len(configured)),
		aliases: make(map[string][]string, len(configured)),
	}
	for i, resource := range configured {
		if err := resource.Validate(); err != nil {
			return nil, fmt.Errorf("firewall: configured MCP resource %d: %w", i, err)
		}
		if resource.Kind != ResourceKindMCPTool {
			return nil, fmt.Errorf(
				"firewall: configured MCP resource %d has kind %q, want %q",
				i,
				resource.Kind,
				ResourceKindMCPTool,
			)
		}
		key := mcpDispatchKey{host: resource.ParentID, tool: resource.ID}
		if _, exists := resolver.exact[key]; exists {
			return nil, fmt.Errorf(
				"firewall: duplicate configured MCP tool %q under server %q",
				resource.ID,
				resource.ParentID,
			)
		}
		resource.parentPresent = false
		resolver.exact[key] = resource
		resolver.hosts[resource.ParentID] = struct{}{}

		alias := strings.ReplaceAll(resource.ParentID, "-", "_")
		resolver.aliases[alias] = appendUniqueString(
			resolver.aliases[alias],
			resource.ParentID,
		)
	}
	return resolver, nil
}

// Resolve recognizes mcp__<server>__<tool> and MCP:<server>:<tool>. It first
// compares the parsed server and tool to exact configured identities. If no
// exact server matches, it checks the unique host alias formed by replacing
// hyphens in each configured server identity with underscores. Tool identities
// are always exact and case-sensitive.
func (r *MCPResolver) Resolve(dispatchName string) MCPResolution {
	if r == nil {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	host, tool, ok := parseMCPDispatchName(dispatchName)
	if !ok {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	key := mcpDispatchKey{host: host, tool: tool}
	if _, exactHost := r.hosts[host]; exactHost {
		if resource, exists := r.exact[key]; exists {
			return resolvedMCPResource(resource)
		}
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	parents := r.aliases[host]
	switch len(parents) {
	case 0:
		return MCPResolution{Status: MCPResolutionUnresolved}
	case 1:
		resource, exists := r.exact[mcpDispatchKey{host: parents[0], tool: tool}]
		if !exists {
			return MCPResolution{Status: MCPResolutionUnresolved}
		}
		return resolvedMCPResource(resource)
	default:
		return MCPResolution{Status: MCPResolutionAmbiguous}
	}
}

func resolvedMCPResource(resource Resource) MCPResolution {
	return MCPResolution{
		Status:   MCPResolutionResolved,
		Resource: cloneResource(&resource),
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func parseMCPDispatchName(dispatchName string) (host, tool string, ok bool) {
	switch {
	case strings.HasPrefix(dispatchName, "mcp__"):
		parts := strings.SplitN(strings.TrimPrefix(dispatchName, "mcp__"), "__", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", false
		}
		return parts[0], parts[1], true
	case strings.HasPrefix(dispatchName, "MCP:"):
		parts := strings.SplitN(strings.TrimPrefix(dispatchName, "MCP:"), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", false
		}
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}
