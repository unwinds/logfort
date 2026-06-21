// Package webui embeds the compiled frontend assets.
package webui

import "embed"

//go:embed dist
var FS embed.FS
