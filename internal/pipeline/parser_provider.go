package pipeline

import (
	"log"
	"sync"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
)

// ParserProvider supplies a hot-reloadable parser to the ingester.
//
// It keeps the last successfully compiled parser so an invalid edit never
// stops ingestion: the error is logged and the previous parser keeps working.
type ParserProvider struct {
	file *config.File[parser.Config]

	mu      sync.RWMutex
	parser  *parser.Parser
	lastErr string
}

// NewParserProvider binds a provider to a parser config file and compiles the
// current contents.
func NewParserProvider(file *config.File[parser.Config]) *ParserProvider {
	p := &ParserProvider{file: file}
	if cfg, ok := file.Current(); ok {
		compiled, err := parser.NewParser(&cfg)
		if err != nil {
			p.lastErr = err.Error()
			log.Printf("parser: initial config invalid, using built-in rules: %v", err)
		} else {
			p.parser = compiled
		}
	}
	if p.parser == nil {
		p.parser, _ = parser.NewParser(nil)
	}
	return p
}

// Reload re-reads the config when its mtime changed and recompiles.
func (p *ParserProvider) Reload() {
	changed, err := p.file.Reload()
	if err != nil {
		if msg := err.Error(); msg != p.lastErr {
			p.lastErr = msg
			log.Printf("parser: config reload failed, keeping previous config: %v", err)
		}
		return
	}
	if !changed {
		return
	}
	cfg, ok := p.file.Current()
	if !ok {
		return
	}
	compiled, err := parser.NewParser(&cfg)
	if err != nil {
		p.lastErr = err.Error()
		log.Printf("parser: config invalid, keeping previous config: %v", err)
		return
	}
	p.mu.Lock()
	p.parser = compiled
	p.lastErr = ""
	p.mu.Unlock()
	log.Printf("parser: config reloaded (%d devices)", len(cfg.Devices))
}

// Parse delegates to the current parser.
func (p *ParserProvider) Parse(line string) *parser.Entry {
	p.mu.RLock()
	current := p.parser
	p.mu.RUnlock()
	return current.Parse(line)
}
