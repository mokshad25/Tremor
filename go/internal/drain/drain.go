// Package drain is a Go port of the Drain log-template miner as implemented
// by drain3 0.9.x (drain3/drain.py), which TREMOR's Python version uses.
//
// Drain (He et al., ICWS 2017) puts each message into a fixed-depth prefix
// tree: the first level splits by token count, the next levels by the
// message's leading tokens, and each leaf holds a short list of clusters.
// Within a leaf, a message joins the most similar cluster if the share of
// identical tokens reaches SimTh; otherwise it starts a new cluster.
// Tokens where a cluster's messages disagree become the wildcard <*>.
//
// The port is behaviour-for-behaviour, including drain3's quirks: tokens
// containing a digit go down the wildcard branch when the tree is built,
// the max_children overflow rules, tie-breaking on equal similarity (more
// wildcards wins, then first-inserted), and the LRU cluster cache in which
// candidate scans do not refresh recency but a match does. The comparison
// test replays 130k real messages through both and requires identical
// cluster ids and final templates.
package drain

import (
	"container/list"
	"strings"
	"unicode"
)

// Config mirrors drain3's Drain parameters.
type Config struct {
	Depth       int     // tree depth including root and length levels; >= 3
	SimTh       float64 // minimum similarity to join a cluster
	MaxChildren int     // max children of an internal node
	MaxClusters int     // LRU capacity; 0 = unlimited
	ParamStr    string  // wildcard token
	// ParametrizeNumericTokens routes tokens containing a digit down the
	// wildcard branch when inserting into the tree.
	ParametrizeNumericTokens bool
}

// TremorConfig is the configuration TREMOR uses (app/core/templates.py).
func TremorConfig() Config {
	return Config{Depth: 4, SimTh: 0.4, MaxChildren: 100, MaxClusters: 1000, ParamStr: "<*>", ParametrizeNumericTokens: true}
}

// Cluster is one mined template.
type Cluster struct {
	ID     int
	Tokens []string
	Size   int
}

// Template is the template text, tokens joined by single spaces.
func (c *Cluster) Template() string { return strings.Join(c.Tokens, " ") }

// Change reports what Add did.
type Change uint8

const (
	ChangeNone            Change = iota // matched an existing cluster unchanged
	ChangeCreated                       // started a new cluster
	ChangeTemplateChanged               // matched and generalised the template
)

type node struct {
	children   map[string]*node
	clusterIDs []int
}

func newNode() *node { return &node{children: map[string]*node{}} }

// Drain is not safe for concurrent use; TREMOR gives each service its own
// instance, owned by that service's shard goroutine.
type Drain struct {
	cfg          Config
	maxNodeDepth int
	byLen        map[int]*node // first tree level: token count

	clusters map[int]*list.Element // id -> element in lru (Value is *Cluster)
	lru      *list.List            // front = least recently used
	counter  int
}

// New returns an empty Drain. It panics on Depth < 3, like drain3.
func New(cfg Config) *Drain {
	if cfg.Depth < 3 {
		panic("drain: depth must be at least 3")
	}
	if cfg.ParamStr == "" {
		cfg.ParamStr = "<*>"
	}
	return &Drain{
		cfg:          cfg,
		maxNodeDepth: cfg.Depth - 2,
		byLen:        map[int]*node{},
		clusters:     map[int]*list.Element{},
		lru:          list.New(),
	}
}

// Len is the number of live clusters.
func (d *Drain) Len() int { return len(d.clusters) }

// Created is the number of clusters ever created (the last id handed out).
func (d *Drain) Created() int { return d.counter }

// Clusters returns the live clusters, least recently used first.
func (d *Drain) Clusters() []*Cluster {
	out := make([]*Cluster, 0, d.lru.Len())
	for e := d.lru.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(*Cluster))
	}
	return out
}

// Get returns a live cluster without refreshing its recency.
func (d *Drain) Get(id int) *Cluster {
	if e, ok := d.clusters[id]; ok {
		return e.Value.(*Cluster)
	}
	return nil
}

// touch marks id as most recently used (cachetools LRUCache.__getitem__).
func (d *Drain) touch(id int) {
	if e, ok := d.clusters[id]; ok {
		d.lru.MoveToBack(e)
	}
}

// insert stores a new cluster, evicting the least recently used one if the
// cache is full (cachetools LRUCache.__setitem__).
func (d *Drain) insert(c *Cluster) {
	if d.cfg.MaxClusters > 0 && len(d.clusters) >= d.cfg.MaxClusters {
		oldest := d.lru.Front()
		delete(d.clusters, oldest.Value.(*Cluster).ID)
		d.lru.Remove(oldest)
	}
	d.clusters[c.ID] = d.lru.PushBack(c)
}

func tokenize(content string) []string { return strings.Fields(content) }

func hasNumbers(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// Add mines one (already masked) message.
func (d *Drain) Add(content string) (*Cluster, Change) {
	tokens := tokenize(content)
	match := d.treeSearch(tokens)
	if match == nil {
		d.counter++
		c := &Cluster{ID: d.counter, Tokens: tokens, Size: 1}
		d.insert(c)
		d.addToTree(c)
		return c, ChangeCreated
	}
	change := ChangeNone
	if tmpl, changed := d.createTemplate(tokens, match.Tokens); changed {
		match.Tokens = tmpl
		change = ChangeTemplateChanged
	}
	match.Size++
	d.touch(match.ID)
	return match, change
}

func (d *Drain) treeSearch(tokens []string) *Cluster {
	n := len(tokens)
	cur, ok := d.byLen[n]
	if !ok {
		return nil
	}
	if n == 0 {
		return d.Get(cur.clusterIDs[0])
	}
	depth := 1
	for _, tok := range tokens {
		if depth >= d.maxNodeDepth || depth == n {
			break
		}
		next, ok := cur.children[tok]
		if !ok {
			next, ok = cur.children[d.cfg.ParamStr]
		}
		if !ok {
			return nil
		}
		cur = next
		depth++
	}
	return d.fastMatch(cur.clusterIDs, tokens)
}

func (d *Drain) addToTree(c *Cluster) {
	n := len(c.Tokens)
	cur, ok := d.byLen[n]
	if !ok {
		cur = newNode()
		d.byLen[n] = cur
	}
	if n == 0 {
		cur.clusterIDs = []int{c.ID}
		return
	}
	depth := 1
	param := d.cfg.ParamStr
	for _, tok := range c.Tokens {
		if depth >= d.maxNodeDepth || depth >= n {
			// Leaf: drop ids of evicted clusters, then append this one.
			kept := cur.clusterIDs[:0:0]
			for _, id := range cur.clusterIDs {
				if _, live := d.clusters[id]; live {
					kept = append(kept, id)
				}
			}
			cur.clusterIDs = append(kept, c.ID)
			return
		}
		if next, ok := cur.children[tok]; ok {
			cur = next
		} else if d.cfg.ParametrizeNumericTokens && hasNumbers(tok) {
			cur = d.child(cur, param)
		} else if _, hasParam := cur.children[param]; hasParam {
			if len(cur.children) < d.cfg.MaxChildren {
				cur = d.newChild(cur, tok)
			} else {
				cur = cur.children[param]
			}
		} else {
			switch {
			case len(cur.children)+1 < d.cfg.MaxChildren:
				cur = d.newChild(cur, tok)
			case len(cur.children)+1 == d.cfg.MaxChildren:
				cur = d.newChild(cur, param)
			default:
				// Unreachable: a node only reaches MaxChildren entries once it
				// has a wildcard child. drain3 would raise KeyError here.
				cur = d.child(cur, param)
			}
		}
		depth++
	}
}

func (d *Drain) child(n *node, key string) *node {
	if c, ok := n.children[key]; ok {
		return c
	}
	return d.newChild(n, key)
}

func (d *Drain) newChild(n *node, key string) *node {
	c := newNode()
	n.children[key] = c
	return c
}

// seqDistance is drain3's get_seq_distance with include_params=false.
func (d *Drain) seqDistance(tmpl, tokens []string) (sim float64, params int) {
	if len(tmpl) == 0 {
		return 1, 0
	}
	same := 0
	for i, t := range tmpl {
		if t == d.cfg.ParamStr {
			params++
			continue
		}
		if t == tokens[i] {
			same++
		}
	}
	return float64(same) / float64(len(tmpl)), params
}

func (d *Drain) fastMatch(ids []int, tokens []string) *Cluster {
	maxSim, maxParams := -1.0, -1
	var best *Cluster
	for _, id := range ids {
		c := d.Get(id) // no recency update while scanning candidates
		if c == nil {
			continue
		}
		sim, params := d.seqDistance(c.Tokens, tokens)
		if sim > maxSim || (sim == maxSim && params > maxParams) {
			maxSim, maxParams, best = sim, params, c
		}
	}
	if maxSim >= d.cfg.SimTh {
		return best
	}
	return nil
}

// createTemplate generalises tmpl with tokens: positions that differ become
// the wildcard. It reports whether anything changed.
func (d *Drain) createTemplate(tokens, tmpl []string) ([]string, bool) {
	var out []string
	for i := range tmpl {
		if tokens[i] != tmpl[i] && tmpl[i] != d.cfg.ParamStr {
			if out == nil {
				out = append([]string(nil), tmpl...)
			}
			out[i] = d.cfg.ParamStr
		}
	}
	if out == nil {
		return tmpl, false
	}
	return out, true
}
