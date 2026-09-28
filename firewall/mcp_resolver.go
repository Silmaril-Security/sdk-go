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
	// MCPResolutionAmbiguous means multiple configured identities explain the same dispatch spelling.
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
	tools []Resource
}

// NewMCPResolver constructs a resolver from concrete configured MCP tool
// identities. Duplicate identities and non-MCP-tool resources are rejected.
func NewMCPResolver(configured []Resource) (*MCPResolver, error) {
	resolver := &MCPResolver{tools: make([]Resource, 0, len(configured))}
	seen := make(map[mcpDispatchKey]struct{}, len(configured))
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
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf(
				"firewall: duplicate configured MCP tool %q under server %q",
				resource.ID,
				resource.ParentID,
			)
		}
		seen[key] = struct{}{}
		resource.parentPresent = false
		resolver.tools = append(resolver.tools, resource)
	}
	return resolver, nil
}

// Resolve recognizes mcp__<server>__<tool> and MCP:<server>:<tool>. Server and
// tool identities may themselves contain the dispatch separator. It collects
// every complete configured spelling, including a host alias formed by
// replacing hyphens in a configured server identity with underscores. A server
// contributes an alias spelling only when it contains a hyphen. Identical
// canonical resources are deduplicated. One remaining candidate resolves; more
// than one is ambiguous; none is unresolved. Callers that already hold a typed
// canonical resource use WithResource instead of this raw-name resolver.
func (r *MCPResolver) Resolve(dispatchName string) MCPResolution {
	if r == nil {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	separator, body, ok := mcpDispatchBody(dispatchName)
	if !ok {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	matches := matchingTools(r.tools, body, separator, false)
	matches = append(matches, matchingTools(r.tools, body, separator, true)...)
	unique := dedupeCanonicalResources(matches)
	switch len(unique) {
	case 1:
		return resolvedMCPResource(unique[0])
	case 0:
		return MCPResolution{Status: MCPResolutionUnresolved}
	default:
		return MCPResolution{Status: MCPResolutionAmbiguous}
	}
}

func matchingTools(tools []Resource, body, separator string, alias bool) []Resource {
	matches := make([]Resource, 0, 1)
	for _, tool := range tools {
		host := tool.ParentID
		if alias {
			host = strings.ReplaceAll(host, "-", "_")
			if host == tool.ParentID {
				continue
			}
		}
		if body == host+separator+tool.ID {
			matches = append(matches, tool)
		}
	}
	return matches
}

func dedupeCanonicalResources(matches []Resource) []Resource {
	seen := make(map[mcpDispatchKey]struct{}, len(matches))
	unique := make([]Resource, 0, len(matches))
	for _, match := range matches {
		key := mcpDispatchKey{host: match.ParentID, tool: match.ID}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, match)
	}
	return unique
}

func resolvedMCPResource(resource Resource) MCPResolution {
	return MCPResolution{
		Status:   MCPResolutionResolved,
		Resource: cloneResource(&resource),
	}
}

type mcpDispatchKey struct {
	host string
	tool string
}

func mcpDispatchBody(dispatchName string) (separator, body string, ok bool) {
	switch {
	case strings.HasPrefix(dispatchName, "mcp__") && len(dispatchName) > len("mcp__"):
		return "__", dispatchName[len("mcp__"):], true
	case strings.HasPrefix(dispatchName, "MCP:") && len(dispatchName) > len("MCP:"):
		return ":", dispatchName[len("MCP:"):], true
	default:
		return "", "", false
	}
}
