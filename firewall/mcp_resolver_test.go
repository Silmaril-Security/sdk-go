// Copyright (c) 2024-2026 Silmaril Security Inc. All rights reserved.

package firewall

import (
	"strings"
	"testing"
)

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

func TestMCPResolverExactAndAliasSpellingsCollide(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "git_hub"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "git-hub"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__git_hub__search",
		"MCP:git_hub:search",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
	hyphenated := resolver.Resolve("mcp__git-hub__search")
	if hyphenated.Status != MCPResolutionResolved || hyphenated.Resource == nil || hyphenated.Resource.ParentID != "git-hub" {
		t.Fatalf("hyphenated exact resolution = %+v", hyphenated)
	}
}

func TestMCPResolverDistinctToolsDoNotCollideOnSharedAliasHost(t *testing.T) {
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
		if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
		if resolution.Resource.ParentID != "server-name_x" || resolution.Resource.ID != "search" {
			t.Fatalf("%q resource = %+v", dispatch, resolution.Resource)
		}
	}
}

func TestMCPResolverCompleteAliasSpellingsStayAmbiguous(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "foo-bar-baz"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "foo_bar-baz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__foo_bar_baz__search",
		"MCP:foo_bar_baz:search",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
}

func TestMCPResolverServerWithoutHyphenStaysExactOnly(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server_name"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server-name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	shared := resolver.Resolve("mcp__server_name__search")
	if shared.Status != MCPResolutionAmbiguous || shared.Resource != nil {
		t.Fatalf("shared exact and alias resolution = %+v", shared)
	}
	hyphenDispatch := resolver.Resolve("mcp__server-name__search")
	if hyphenDispatch.Status != MCPResolutionResolved || hyphenDispatch.Resource == nil || hyphenDispatch.Resource.ParentID != "server-name" {
		t.Fatalf("hyphenated exact resolution = %+v", hyphenDispatch)
	}

	exactOnly, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server_name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__server-name__search",
		"MCP:server-name:search",
	} {
		resolution := exactOnly.Resolve(dispatch)
		if resolution.Status != MCPResolutionUnresolved || resolution.Resource != nil {
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

func TestMCPResolverMatchesConfiguredIDsContainingSeparators(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod:west"},
		{Kind: ResourceKindMCPTool, ID: "west__search", ParentID: "staging"},
		{Kind: ResourceKindMCPTool, ID: "west:search", ParentID: "staging"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		dispatch string
		parent   string
		tool     string
	}{
		{dispatch: "mcp__prod__west__search", parent: "prod__west", tool: "search"},
		{dispatch: "MCP:prod:west:search", parent: "prod:west", tool: "search"},
		{dispatch: "mcp__staging__west__search", parent: "staging", tool: "west__search"},
		{dispatch: "MCP:staging:west:search", parent: "staging", tool: "west:search"},
	}
	for _, tc := range cases {
		t.Run(tc.dispatch, func(t *testing.T) {
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

func TestMCPResolverSeparatorExactAndAliasSpellingsCollide(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west-1"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west_1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolution := resolver.Resolve("mcp__prod__west_1__search")
	if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
		t.Fatalf("resolution = %+v", resolution)
	}
	aliasOnly, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	alias := aliasOnly.Resolve("mcp__prod__west_1__search")
	if alias.Status != MCPResolutionResolved || alias.Resource == nil || alias.Resource.ParentID != "prod__west-1" {
		t.Fatalf("alias resolution = %+v", alias)
	}
}

func TestMCPResolverAmbiguousOverlappingSeparatorInterpretations(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west"},
		{Kind: ResourceKindMCPTool, ID: "west__search", ParentID: "prod"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod:west"},
		{Kind: ResourceKindMCPTool, ID: "west:search", ParentID: "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__prod__west__search",
		"MCP:prod:west:search",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
}

func TestMCPResolverDuplicateToolNamesRemainParentSpecific(t *testing.T) {
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "alpha"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "beta"},
		{Kind: ResourceKindMCPTool, ID: "search", ParentID: "prod__west"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"mcp__alpha__search":      "alpha",
		"mcp__beta__search":       "beta",
		"MCP:alpha:search":        "alpha",
		"MCP:prod__west:search":   "prod__west",
		"mcp__prod__west__search": "prod__west",
	}
	for dispatch, parent := range cases {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
		if resolution.Resource.ParentID != parent || resolution.Resource.ID != "search" {
			t.Fatalf("%q resource = %+v", dispatch, resolution.Resource)
		}
	}
}

func TestMCPResolverLongSeparatorNamesStayUnresolvedOrExact(t *testing.T) {
	parent := strings.Repeat("region__", 32) + "tail"
	tool := strings.Repeat("search__", 16) + "end"
	resolver, err := NewMCPResolver([]Resource{
		{Kind: ResourceKindMCPTool, ID: tool, ParentID: parent},
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch := "mcp__" + parent + "__" + tool
	first := resolver.Resolve(dispatch)
	second := resolver.Resolve(dispatch)
	if first.Status != MCPResolutionResolved || second.Status != MCPResolutionResolved {
		t.Fatalf("resolutions = %+v %+v", first, second)
	}
	if first.Resource == nil || second.Resource == nil ||
		first.Resource.ParentID != parent || second.Resource.ID != tool ||
		first.Resource.ParentID != second.Resource.ParentID ||
		first.Resource.ID != second.Resource.ID {
		t.Fatalf("resources = %+v %+v", first.Resource, second.Resource)
	}
	unknown := resolver.Resolve(dispatch + "__extra")
	if unknown.Status != MCPResolutionUnresolved || unknown.Resource != nil {
		t.Fatalf("unknown = %+v", unknown)
	}
}

func TestMCPServerCatalogResolvesNestedToolID(t *testing.T) {
	resolver, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{
			{Kind: ResourceKindMCPServer, ID: "prod__west"},
			{Kind: ResourceKindMCPServer, ID: "prod:west"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		dispatch string
		parent   string
		tool     string
	}{
		{dispatch: "mcp__prod__west__search__papers", parent: "prod__west", tool: "search__papers"},
		{dispatch: "MCP:prod:west:search:papers", parent: "prod:west", tool: "search:papers"},
	}
	for _, tc := range cases {
		resolution := resolver.Resolve(tc.dispatch)
		if resolution.Status != MCPResolutionResolved || resolution.Resource == nil {
			t.Fatalf("%q resolution = %+v", tc.dispatch, resolution)
		}
		if resolution.Resource.Kind != ResourceKindMCPTool ||
			resolution.Resource.ParentID != tc.parent ||
			resolution.Resource.ID != tc.tool {
			t.Fatalf("%q resource = %+v", tc.dispatch, resolution.Resource)
		}
		if err := resolution.Resource.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMCPServerCatalogRejectsInvalidToolSuffix(t *testing.T) {
	resolver, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{{Kind: ResourceKindMCPServer, ID: "server"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__server__   ",
		"mcp__server__\t",
		"MCP:server:   ",
		"mcp__server__",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionUnresolved || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
	nested := resolver.Resolve("mcp__server__search__papers")
	if nested.Status != MCPResolutionResolved || nested.Resource == nil ||
		nested.Resource.ParentID != "server" || nested.Resource.ID != "search__papers" {
		t.Fatalf("separator tool id = %+v", nested)
	}
	if err := nested.Resource.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMCPServerCatalogOverlappingIDsAreAmbiguous(t *testing.T) {
	resolver, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{
			{Kind: ResourceKindMCPServer, ID: "prod"},
			{Kind: ResourceKindMCPServer, ID: "prod__west"},
			{Kind: ResourceKindMCPServer, ID: "prod:west"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dispatch := range []string{
		"mcp__prod__west__search",
		"MCP:prod:west:search",
	} {
		resolution := resolver.Resolve(dispatch)
		if resolution.Status != MCPResolutionAmbiguous || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
	unique := resolver.Resolve("mcp__prod__list")
	if unique.Status != MCPResolutionResolved || unique.Resource == nil ||
		unique.Resource.ParentID != "prod" || unique.Resource.ID != "list" {
		t.Fatalf("unique server resolution = %+v", unique)
	}
}

func TestMCPServerCatalogExactAliasCollisionAndExplicitAlias(t *testing.T) {
	resolver, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{
			{Kind: ResourceKindMCPServer, ID: "git_hub"},
			{Kind: ResourceKindMCPServer, ID: "git-hub"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	collision := resolver.Resolve("mcp__git_hub__search")
	if collision.Status != MCPResolutionAmbiguous || collision.Resource != nil {
		t.Fatalf("collision = %+v", collision)
	}
	aliasOnly, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{{Kind: ResourceKindMCPServer, ID: "git-hub"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved := aliasOnly.Resolve("MCP:git_hub:search")
	if resolved.Status != MCPResolutionResolved || resolved.Resource == nil ||
		resolved.Resource.ParentID != "git-hub" || resolved.Resource.ID != "search" {
		t.Fatalf("alias resolution = %+v", resolved)
	}

	explicit, err := NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{{Kind: ResourceKindMCPServer, ID: "github"}},
		Aliases: []MCPServerAlias{{ServerID: "github", Alias: "gh"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gh := explicit.Resolve("mcp__gh__search__issues")
	if gh.Status != MCPResolutionResolved || gh.Resource == nil ||
		gh.Resource.ParentID != "github" || gh.Resource.ID != "search__issues" {
		t.Fatalf("explicit alias = %+v", gh)
	}
	for _, dispatch := range []string{"mcp__github__", "mcp__github", "search"} {
		if resolution := explicit.Resolve(dispatch); resolution.Status != MCPResolutionUnresolved || resolution.Resource != nil {
			t.Fatalf("%q resolution = %+v", dispatch, resolution)
		}
	}
}

func TestNewMCPCatalogResolverRejectsMixedOrUnknownAliases(t *testing.T) {
	_, err := NewMCPCatalogResolver(MCPCatalog{
		Tools:   []Resource{{Kind: ResourceKindMCPTool, ID: "search", ParentID: "server"}},
		Servers: []Resource{{Kind: ResourceKindMCPServer, ID: "server"}},
	})
	if err == nil {
		t.Fatal("expected mixed catalog error")
	}
	_, err = NewMCPCatalogResolver(MCPCatalog{
		Servers: []Resource{{Kind: ResourceKindMCPServer, ID: "server"}},
		Aliases: []MCPServerAlias{{ServerID: "other", Alias: "alias"}},
	})
	if err == nil {
		t.Fatal("expected unknown alias server error")
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
			name:       "whitespace tool id",
			configured: []Resource{{Kind: ResourceKindMCPTool, ID: "   ", ParentID: "server"}},
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
