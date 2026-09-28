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
// tool identities may themselves contain the dispatch separator. Exact
// configured identities are compared first. A unique host alias, formed by
// replacing hyphens in the configured server identity with underscores, is
// used only when no exact interpretation exists. Multiple interpretations or
// alias collisions are ambiguous.
func (r *MCPResolver) Resolve(dispatchName string) MCPResolution {
	if r == nil {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	separator, body, ok := mcpDispatchBody(dispatchName)
	if !ok {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	exact := matchingTools(r.tools, body, separator, false)
	switch len(exact) {
	case 1:
		return resolvedMCPResource(exact[0])
	default:
		if len(exact) > 1 {
			return MCPResolution{Status: MCPResolutionAmbiguous}
		}
	}
	if exactServerPrefix(r.tools, body, separator) {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	aliases := matchingTools(r.tools, body, separator, true)
	switch len(aliases) {
	case 1:
		if aliasHostCollides(r.tools, aliases[0].ParentID) {
			return MCPResolution{Status: MCPResolutionAmbiguous}
		}
		return resolvedMCPResource(aliases[0])
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

func exactServerPrefix(tools []Resource, body, separator string) bool {
	seen := make(map[string]struct{})
	for _, tool := range tools {
		if _, ok := seen[tool.ParentID]; ok {
			continue
		}
		seen[tool.ParentID] = struct{}{}
		if strings.HasPrefix(body, tool.ParentID+separator) {
			return true
		}
	}
	return false
}

func aliasHostCollides(tools []Resource, parentID string) bool {
	alias := strings.ReplaceAll(parentID, "-", "_")
	for _, tool := range tools {
		if tool.ParentID == parentID {
			continue
		}
		if strings.ReplaceAll(tool.ParentID, "-", "_") == alias {
			return true
		}
	}
	return false
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
