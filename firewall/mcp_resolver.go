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

// MCPServerAlias is an additional dispatch host spelling for one canonical
// configured server ID. The alias is explicit catalog data. The resolver also
// derives the hyphen-to-underscore spelling of each configured server ID.
type MCPServerAlias struct {
	ServerID string
	Alias    string
}

// MCPCatalog is a caller-supplied MCP dispatch catalog. Set Tools for a full
// tool catalog, or Servers when only server IDs are known. Aliases add host
// spellings for those configured server IDs. The resolver does not discover
// or scrape configuration.
type MCPCatalog struct {
	Tools   []Resource
	Servers []Resource
	Aliases []MCPServerAlias
}

// MCPResolver resolves host dispatch spellings against a caller-supplied,
// immutable snapshot of configured MCP identities. It does not discover or
// scrape configuration.
type MCPResolver struct {
	tools           []Resource
	servers         []string
	explicitAliases map[string][]string
}

// NewMCPResolver constructs a resolver from concrete configured MCP tool
// identities. Duplicate identities and non-MCP-tool resources are rejected.
func NewMCPResolver(configured []Resource) (*MCPResolver, error) {
	return NewMCPCatalogResolver(MCPCatalog{Tools: configured})
}

// NewMCPCatalogResolver constructs a resolver from a full tool catalog or a
// server-only catalog. A full tool catalog matches complete server/tool
// spellings. A server-only catalog matches every separator-bounded configured
// server ID or alias and uses the entire nonempty remainder as the tool ID.
func NewMCPCatalogResolver(catalog MCPCatalog) (*MCPResolver, error) {
	if len(catalog.Tools) > 0 && len(catalog.Servers) > 0 {
		return nil, fmt.Errorf("firewall: MCP catalog must contain tools or servers, not both")
	}
	resolver := &MCPResolver{explicitAliases: map[string][]string{}}
	known := map[string]struct{}{}
	if len(catalog.Servers) > 0 {
		resolver.servers = make([]string, 0, len(catalog.Servers))
		for i, server := range catalog.Servers {
			if err := server.Validate(); err != nil {
				return nil, fmt.Errorf("firewall: configured MCP server %d: %w", i, err)
			}
			if server.Kind != ResourceKindMCPServer {
				return nil, fmt.Errorf(
					"firewall: configured MCP server %d has kind %q, want %q",
					i,
					server.Kind,
					ResourceKindMCPServer,
				)
			}
			if _, exists := known[server.ID]; exists {
				return nil, fmt.Errorf("firewall: duplicate configured MCP server %q", server.ID)
			}
			known[server.ID] = struct{}{}
			resolver.servers = append(resolver.servers, server.ID)
		}
	} else {
		resolver.tools = make([]Resource, 0, len(catalog.Tools))
		seenTools := map[mcpDispatchKey]struct{}{}
		for i, resource := range catalog.Tools {
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
			if _, exists := seenTools[key]; exists {
				return nil, fmt.Errorf(
					"firewall: duplicate configured MCP tool %q under server %q",
					resource.ID,
					resource.ParentID,
				)
			}
			seenTools[key] = struct{}{}
			known[resource.ParentID] = struct{}{}
			resource.parentPresent = false
			resolver.tools = append(resolver.tools, resource)
		}
	}
	for i, alias := range catalog.Aliases {
		if _, ok := known[alias.ServerID]; !ok {
			return nil, fmt.Errorf("firewall: MCP alias %d server %q is not configured", i, alias.ServerID)
		}
		if err := validateExactIdentity(alias.Alias, "MCP alias"); err != nil {
			return nil, fmt.Errorf("firewall: MCP alias %d: %w", i, err)
		}
		if alias.Alias == alias.ServerID {
			return nil, fmt.Errorf("firewall: MCP alias %d repeats configured server %q", i, alias.ServerID)
		}
		resolver.explicitAliases[alias.ServerID] = append(resolver.explicitAliases[alias.ServerID], alias.Alias)
	}
	return resolver, nil
}

// Resolve recognizes mcp__<server>__<tool> and MCP:<server>:<tool>. Server and
// tool identities may themselves contain the dispatch separator. A full tool
// catalog enumerates complete server/tool spellings. A server-only catalog
// takes every separator-bounded configured server ID or alias prefix and uses
// the entire nonempty remainder, including further separators, as the tool ID.
// Exact and alias spellings are equal candidates. Identical canonical resources
// are deduplicated. One remaining candidate resolves; more than one is
// ambiguous; none is unresolved. Callers that already hold a typed canonical
// resource use WithResource instead of this raw-name resolver.
func (r *MCPResolver) Resolve(dispatchName string) MCPResolution {
	if r == nil {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	separator, body, ok := mcpDispatchBody(dispatchName)
	if !ok {
		return MCPResolution{Status: MCPResolutionUnresolved}
	}
	var matches []Resource
	if len(r.servers) > 0 {
		matches = r.serverCandidates(body, separator)
	} else {
		matches = r.toolCandidates(body, separator)
	}
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

func (r *MCPResolver) toolCandidates(body, separator string) []Resource {
	matches := make([]Resource, 0, 1)
	for _, tool := range r.tools {
		for _, host := range r.hostSpellings(tool.ParentID) {
			if body == host+separator+tool.ID {
				matches = append(matches, tool)
				break
			}
		}
	}
	return matches
}

func (r *MCPResolver) serverCandidates(body, separator string) []Resource {
	matches := make([]Resource, 0, 1)
	for _, serverID := range r.servers {
		for _, host := range r.hostSpellings(serverID) {
			prefix := host + separator
			if !strings.HasPrefix(body, prefix) {
				continue
			}
			toolID := body[len(prefix):]
			if toolID == "" {
				continue
			}
			matches = append(matches, Resource{
				Kind:     ResourceKindMCPTool,
				ID:       toolID,
				ParentID: serverID,
			})
		}
	}
	return matches
}

func (r *MCPResolver) hostSpellings(serverID string) []string {
	hosts := []string{serverID}
	seen := map[string]struct{}{serverID: {}}
	add := func(host string) {
		if host == "" {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	add(strings.ReplaceAll(serverID, "-", "_"))
	for _, alias := range r.explicitAliases[serverID] {
		add(alias)
	}
	return hosts
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
