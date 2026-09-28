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

// MCPCatalog is a caller-supplied MCP dispatch catalog. Tools alone form a full
// tool catalog whose parents are implicit. Servers alone form a server-only
// catalog. Servers and Tools together anchor that full tool catalog to the
// listed servers and ignore tool rows whose parent is not listed. Aliases add
// host spellings only for those configured server IDs. The resolver does not
// discover or scrape configuration.
type MCPCatalog struct {
	Tools   []Resource
	Servers []Resource
	Aliases []MCPServerAlias
}

// mcpCatalogMode selects how a constructed catalog interprets dispatch names.
// It is fixed at construction so a server list cannot by itself override a
// full tool catalog.
type mcpCatalogMode uint8

const (
	// mcpCatalogImplicitTools matches complete spellings. Each tool parent is
	// a configured server even when no server row was supplied.
	mcpCatalogImplicitTools mcpCatalogMode = iota
	// mcpCatalogServersOnly derives the tool ID from a separator-bounded prefix.
	mcpCatalogServersOnly
	// mcpCatalogAnchoredTools matches complete spellings for tools whose parent
	// is one of the explicit configured servers.
	mcpCatalogAnchoredTools
)

// MCPResolver resolves host dispatch spellings against a caller-supplied,
// immutable snapshot of configured MCP identities. It does not discover or
// scrape configuration.
type MCPResolver struct {
	mode            mcpCatalogMode
	tools           []Resource
	servers         []string
	explicitAliases map[string][]string
}

// NewMCPResolver constructs a resolver from concrete configured MCP tool
// identities. Duplicate identities and non-MCP-tool resources are rejected.
func NewMCPResolver(configured []Resource) (*MCPResolver, error) {
	return NewMCPCatalogResolver(MCPCatalog{Tools: configured})
}

// NewMCPCatalogResolver constructs a resolver from one of three catalog shapes.
// Tools alone, including NewMCPResolver, match complete spellings and treat
// every tool parent as configured. Servers alone match every separator-bounded
// configured server ID or alias and use the remainder as the tool ID when that
// remainder is a valid resource ID. Servers and Tools together keep the full
// tool-catalog match, but only for tools whose parent is one of the listed
// servers; other tool rows are ignored and are not configured parents.
// Configured IDs are validated at construction. Aliases bind only to those
// configured servers.
func NewMCPCatalogResolver(catalog MCPCatalog) (*MCPResolver, error) {
	resolver := &MCPResolver{explicitAliases: map[string][]string{}}
	configured := map[string]struct{}{}
	var err error
	switch {
	case len(catalog.Servers) > 0 && len(catalog.Tools) > 0:
		resolver.mode = mcpCatalogAnchoredTools
		resolver.servers, configured, err = configuredMCPServers(catalog.Servers)
		if err != nil {
			return nil, err
		}
		resolver.tools, configured, err = configuredMCPTools(catalog.Tools, configured, true)
	case len(catalog.Servers) > 0:
		resolver.mode = mcpCatalogServersOnly
		resolver.servers, configured, err = configuredMCPServers(catalog.Servers)
	default:
		resolver.mode = mcpCatalogImplicitTools
		resolver.tools, configured, err = configuredMCPTools(catalog.Tools, nil, false)
	}
	if err != nil {
		return nil, err
	}
	for i, alias := range catalog.Aliases {
		if _, ok := configured[alias.ServerID]; !ok {
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

func configuredMCPServers(servers []Resource) ([]string, map[string]struct{}, error) {
	ids := make([]string, 0, len(servers))
	known := make(map[string]struct{}, len(servers))
	for i, server := range servers {
		if err := server.Validate(); err != nil {
			return nil, nil, fmt.Errorf("firewall: configured MCP server %d: %w", i, err)
		}
		if server.Kind != ResourceKindMCPServer {
			return nil, nil, fmt.Errorf(
				"firewall: configured MCP server %d has kind %q, want %q",
				i,
				server.Kind,
				ResourceKindMCPServer,
			)
		}
		if _, exists := known[server.ID]; exists {
			return nil, nil, fmt.Errorf("firewall: duplicate configured MCP server %q", server.ID)
		}
		known[server.ID] = struct{}{}
		ids = append(ids, server.ID)
	}
	return ids, known, nil
}

func configuredMCPTools(tools []Resource, configured map[string]struct{}, anchored bool) ([]Resource, map[string]struct{}, error) {
	if configured == nil {
		configured = map[string]struct{}{}
	}
	accepted := make([]Resource, 0, len(tools))
	seen := map[mcpDispatchKey]struct{}{}
	for i, resource := range tools {
		if err := resource.Validate(); err != nil {
			return nil, nil, fmt.Errorf("firewall: configured MCP resource %d: %w", i, err)
		}
		if resource.Kind != ResourceKindMCPTool {
			return nil, nil, fmt.Errorf(
				"firewall: configured MCP resource %d has kind %q, want %q",
				i,
				resource.Kind,
				ResourceKindMCPTool,
			)
		}
		if anchored {
			if _, ok := configured[resource.ParentID]; !ok {
				continue
			}
		}
		key := mcpDispatchKey{host: resource.ParentID, tool: resource.ID}
		if _, exists := seen[key]; exists {
			return nil, nil, fmt.Errorf(
				"firewall: duplicate configured MCP tool %q under server %q",
				resource.ID,
				resource.ParentID,
			)
		}
		seen[key] = struct{}{}
		if !anchored {
			configured[resource.ParentID] = struct{}{}
		}
		resource.parentPresent = false
		accepted = append(accepted, resource)
	}
	return accepted, configured, nil
}

// Resolve recognizes mcp__<server>__<tool> and MCP:<server>:<tool>. Server and
// tool identities may themselves contain the dispatch separator. A full tool
// catalog enumerates complete server/tool spellings. A server-only catalog
// takes every separator-bounded configured server ID or alias prefix and uses
// the remainder, including further separators, as the tool ID when that
// remainder passes resource ID validation.
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
	if r.mode == mcpCatalogServersOnly {
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
			candidate := Resource{
				Kind:     ResourceKindMCPTool,
				ID:       toolID,
				ParentID: serverID,
			}
			if err := candidate.Validate(); err != nil {
				continue
			}
			matches = append(matches, candidate)
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
