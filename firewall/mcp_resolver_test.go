// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import "testing"

func TestMCPResolverExactAndUniqueAlias(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search_papers", ParentID: "arxiv-mcp-server"},
		{Kind: ResourceKindMCPTool, ID: "create_issue", ParentID: "github"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		dispatch string
		parent   string
		tool     string
	}{
		{
			name:     "double underscore exact",
			dispatch: "mcp__arxiv-mcp-server__search_papers",
			parent:   "arxiv-mcp-server",
			tool:     "search_papers",
		},
		{
			name:     "double underscore alias",
			dispatch: "mcp__arxiv_mcp_server__search_papers",
			parent:   "arxiv-mcp-server",
			tool:     "search_papers",
		},
		{
			name:     "colon exact",
			dispatch: "MCP:github:create_issue",
			parent:   "github",
			tool:     "create_issue",
		},
		{
			name:     "colon alias",
			dispatch: "MCP:arxiv_mcp_server:search_papers",
			parent:   "arxiv-mcp-server",
			tool:     "search_papers",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution := resolver.Resolve(tc.dispatch)
			if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
				t.Fatalf("resolution = %+v", resolution)
			}
			if resolution.Resource.Kind != ResourceKindMCPTool ||
				resolution.Resource.ParentID != tc.parent ||
				resolution.Resource.ID != tc.tool {
				t.Fatalf("resource = %+v", resolution.Resource)
			}
		})
	}
}

func TestMCPResolverExactConfiguredIdentityPrecedesAlias(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server-name"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server_name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolution := resolver.Resolve("mcp__server_name__search")
	if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
		t.Fatalf("resolution = %+v", resolution)
	}
	if resolution.Resource.ParentID != "server_name" {
		t.Fatalf("parent = %q, want exact configured server_name", resolution.Resource.ParentID)
	}
}

func TestMCPResolverReportsAmbiguousAlias(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server-name_x"},
		{Kind: ResourceKindMCPTool, ID: "create", ParentID: "server_name-x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__server_name_x__search",
		"MCP:server_name_x:search",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
}

func TestMCPResolverReportsUnresolvedWithoutGuessing(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search-papers", ParentID: "arxiv-mcp-server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"search-papers",
		"mcp__arxiv_mcp_server__search_papers",
		"mcp__ARXIV_MCP_SERVER__search-papers",
		"mcp__unknown__search-papers",
		"mcp____search-papers",
		"MCP:arxiv_mcp_server:",
		"mcp:arxiv_mcp_server:search-papers",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionUnresolved || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}

	var nilResolver *MCPResolver
	if resolution := nilResolver.Resolve("MCP:server:tool"); resolution.Status != MCPResolutionUnresolved {
		t.Fatalf("nil resolver = %+v", resolution)
	}
}

func TestMCPResolverReturnsIndependentResourceCopy(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := resolver.Resolve("MCP:server:search")
	if first.Resource == nil {
		t.Fatal("first resolution missing resource")
	}
	first.Resource.ID = "mutated"
	second := resolver.Resolve("MCP:server:search")
	if second.Resource == nil || second.Resource.ID != "search" {
		t.Fatalf("second resource = %+v", second.Resource)
	}
}

func TestNewMCPResolverValidatesConfiguredCatalog(t *testing.T) {
	cases := []struct {
		name       string
		configured []Resource
	}{
		{
			name:       "non mcp tool",
			configured: []Resource{{Kind: ResourceKindTool, ID: "shell"}},
		},
		{
			name:       "invalid mcp tool",
			configured: []Resource{{Kind: ResourceKindMCPTool, ID: "search"}},
		},
		{
			name: "duplicate",
			configured: []Resource{
				{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server"},
				{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewMCPResolver(tc.configured); err == nil {
				t.Fatal("expected catalog validation error")
			}
		})
	}
}
