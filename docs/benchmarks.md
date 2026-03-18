# Performance Benchmarks

OpenPawz ships a dedicated benchmark crate (`openpawz-bench`) powered by
[Criterion.rs](https://bheisler.github.io/criterion.rs/book/) that measures
every performance-critical path in the engine — from SQLite session ops and
memory search to HNSW vector indexing, injection scanning, and cryptographic
operations.

## Why Benchmark?

| Goal | What It Catches |
|------|-----------------|
| **Regression detection** | A refactor silently doubles BM25 search time |
| **Capacity planning** | How fast can we insert 2 000 HNSW vectors? |
| **Optimization targeting** | Know *which* function is the bottleneck before optimizing |
| **Comparing algorithms** | HNSW search vs brute-force at 1 000 vectors |
| **CI gating** | Fail a PR if a critical path regresses beyond a threshold |

## Benchmark Suites

The crate contains **8 bench files** covering **140+ individual benchmarks**:

### session_bench

Sessions, messages, tasks, and agent file I/O.

| Benchmark | What It Measures |
|-----------|-----------------|
| `session/create` | Create a new chat session (SQLite INSERT) |
| `session/list/{10,100,500}` | List sessions at varying DB sizes |
| `message/add` | Add a message with HMAC chain verification |
| `message/get/{50,200,1000}` | Fetch messages at varying depths |
| `task/create` | Create a scheduled task |
| `task/list_200` | List 200 tasks with full deserialization |
| `agent/file_set` | Write an agent file (SOUL, instructions) |
| `agent/file_get` | Read an agent file by key |

### platform_bench

Config, flows, squads, canvas, projects, and telemetry.

| Benchmark | What It Measures |
|-----------|-----------------|
| `config/set` | Upsert a key/value config pair |
| `config/get` | Retrieve a config value by key |
| `config/get_miss` | Lookup a nonexistent key (miss path) |
| `flow/save` | Create or update a flow graph |
| `flow/get` | Fetch a single flow by ID |
| `flow/list/{10,50,200}` | List flows at varying DB sizes |
| `flow/run_create` | Record a flow execution run |
| `flow/run_list_100` | Fetch 100 run records |
| `squad/create` | Create a squad with 4 members |
| `squad/list_20` | List 20 squads with nested members |
| `squad/agents_share` | Check if two agents share a squad |
| `squad/agent_in_squad` | Scope check: agent ∈ squad |
| `canvas/upsert` | Insert or update a canvas component |
| `canvas/list_by_session/{5,20,100}` | Fetch canvas components at scale |
| `canvas/patch` | Partial update (title + data) |
| `project/create` | Create a project with 3 agents |
| `project/list_20` | List 20 projects with nested agents |
| `project/set_agents_5` | Atomically replace 5 agent assignments |
| `project/agents_share` | Check if two agents share a project |
| `project/agent_in_project` | Scope check: agent ∈ project |
| `project/get_agent_model` | Lookup agent model override |
| `telemetry/record` | Insert a telemetry metric row |
| `telemetry/daily_summary` | Aggregate daily metrics (100 rows) |
| `telemetry/model_breakdown` | Per-model cost breakdown (200 rows) |
| `telemetry/range_30d` | Aggregate 30-day range (300 rows) |

### memory_bench

Memory store, BM25 search, knowledge graph, episodic and semantic memory
subsystems, content overlap, and fact extraction.

| Benchmark | What It Measures |
|-----------|-----------------|
| `memory/store` | Insert a memory record |
| `memory/search_keyword` | Keyword (LIKE) search |
| `memory/search_bm25` | BM25 ranked full-text search |
| `memory/list/{20,100,500}` | List memories at scale |
| `memory/stats` | Aggregate memory statistics |
| `memory/content_overlap/{identical,similar,disjoint,long}` | Jaccard overlap for dedup |
| `graph/relate` | Create an edge between two memory nodes |
| `graph/apply_decay` | Time-decay pass over the graph |
| `graph/garbage_collect` | Remove orphaned nodes |
| `graph/memory_stats` | Graph statistics |
| `graph/store_procedural` | Insert procedural (how-to) memory |
| `graph/spreading_activation` | Spreading activation over the graph |
| `graph/community_detection` | Louvain-style community detection |
| `episodic/store` | Insert an episodic memory |
| `episodic/get` | Fetch a single episodic memory |
| `episodic/batch_get/{10,50,200}` | Batch fetch at varying sizes |
| `episodic/search_bm25/{20,100,500}` | BM25 over episodic memories |
| `episodic/search_vector` | Vector similarity search (cosine) |
| `semantic/store` | Insert a semantic memory |
| `semantic/search_bm25` | BM25 over semantic memories |
| `memory/extract_facts/{preference,context,instruction}` | Fact extraction by type |
| `episodic/gc_candidates/{50,200,1000}` | Identify GC candidates at scale |

### engram_bench

HNSW vector index, reranking, hybrid search, abstraction tree, tokenizer,
sensory buffer, working memory, affect system, intent classification, entity
extraction, temporal scoring, recall tuning, gated search, and model
capabilities.

| Benchmark | What It Measures |
|-----------|-----------------|
| `hnsw/insert/{100,500,2000}` | Build an HNSW index at varying sizes |
| `hnsw/search/{100,1000,5000}` | ANN search at varying index sizes |
| `hnsw/vs_brute_force_1k` | Compare HNSW vs linear scan at 1 000 vectors |
| `reranking/rrf` | Reciprocal Rank Fusion |
| `reranking/mmr` | Maximal Marginal Relevance |
| `hybrid/resolve_weight` | Resolve hybrid search weight |
| `hybrid/weighted_rrf_fuse` | Weighted RRF fusion |
| `abstraction/build_tree` | Build a hierarchical abstraction tree |
| `abstraction/pack_with_fallback` | Token-budget packing |
| `abstraction/select_level` | Select abstraction level |
| `tokenizer/count_tokens/{Cl100kBase,O200kBase,Heuristic}` | Token counting by encoding |
| `tokenizer/truncate_to_budget` | Truncate text to a token budget |
| `sensory/push` | Push to the sensory buffer |
| `sensory/format_for_context` | Format sensory buffer for LLM context |
| `working_mem/insert_recall` | Working memory insert + recall |
| `working_mem/decay_priorities` | Priority decay pass |
| `working_mem/format_for_context` | Format working memory for context |
| `intent/classify/{factual,procedural,causal,exploratory,episodic}` | Intent classification |
| `intent/weights` | Intent weight computation |
| `entity/extract/{short,medium,long}` | Named entity extraction |
| `metadata/infer` / `metadata/infer_full` | Metadata inference |
| `metadata/detect_lang/{rust,python,typescript}` | Programming language detection |
| `temporal/recency_score/{1h,24h,7d,30d}` | Recency scoring at different ages |
| `temporal/cluster` | Temporal clustering |
| `recall_tuner/observe_and_tune` | Adaptive recall tuning |
| `quality/compute_ndcg` / `quality/average_relevancy` | Retrieval quality metrics |
| `gate/decision/{skip_greeting,retrieve_factual,...}` | Gated search decisions |
| `model_caps/resolve/{gpt5,claude,gemini,llama,unknown}` | Model capability resolution |
| `model_caps/normalize_name` | Normalize model name strings |

### cognitive_bench

Proposition decomposition, memory fusion, SCC certificates, and tool metadata
extensions.

| Benchmark | What It Measures |
|-----------|-----------------|
| `proposition/decompose_simple` | Decompose a single sentence into propositions |
| `proposition/decompose_compound` | Decompose a multi-sentence compound text |
| `proposition/decompose_long` | Decompose a 20-sentence corpus |
| `fusion/run/{10,50}` | Memory fusion cycle at varying corpus sizes |
| `scc/capability_hash/{3,50}` | SHA-256 capability hash at varying set sizes |
| `scc/memory_hash` | SHA-256 hash of audit chain tip |
| `scc/latest_certificate` | Fetch most recent SCC |
| `scc/list_certificates_50` | Fetch 50 certificate chain entries |
| `tool_meta/mutability/{known_safe,known_write,unknown}` | Tool mutability classification |
| `tool_meta/worker_allowed/{read_file,execute_command,custom}` | Worker tool allowlist check |
| `tool_meta/orchestrator_safe/{read_file,execute_command,coinbase}` | Orchestrator auto-approve check |
| `tool_meta/auto_approved` | List all auto-approvable tools |
| `tool_meta/domain_str/{5 tools}` | Tool domain string lookup |

### security_bench

Injection scanning, PII detection, encryption, constrained decoding, key
derivation, differential privacy, and score quantization.

| Benchmark | What It Measures |
|-----------|-----------------|
| `injection/scan/{1KB,10KB,100KB}` | Injection scan at varying input sizes |
| `injection/scan_clean` | Scan a clean (no-injection) input |
| `injection/is_likely` | Quick heuristic injection check |
| `pii/detect/{no_pii,has_pii}` | PII detection (emails, SSNs, cards) |
| `encryption/encrypt` | AES-256-GCM encrypt |
| `encryption/decrypt` | AES-256-GCM decrypt |
| `constrained/detect/{openai,anthropic,google,ollama}` | Provider constraint detection |
| `constrained/normalize_tool_required` | Tool `required` array normalization |
| `constrained/apply_openai_strict` | Apply OpenAI strict mode |
| `crypto/derive_agent_key` | Argon2-based key derivation |
| `crypto/prepare_for_storage/{cleartext,sensitive,confidential}` | Tiered storage preparation |
| `crypto/dp_noise/{eps_0.1,eps_1.0,eps_10.0}` | Differential privacy noise |
| `crypto/quantize_score` | Score quantization (oracle resistance) |

### audit_bench

Tamper-evident audit log and Software Composition Certificates.

| Benchmark | What It Measures |
|-----------|-----------------|
| `audit/append` | Append an HMAC-chained audit entry |
| `audit/verify_chain/{100,1000,5000}` | Verify chain integrity at scale |
| `audit/query_recent_50` | Query 50 recent audit entries |
| `audit/stats` | Aggregate audit statistics |
| `scc/issue_certificate` | Issue a capability certificate |
| `scc/verify_chain/{10,50,200}` | Verify SCC chain at scale |

### reasoning_bench

Affect scoring, emotional context, pricing, task complexity, and tool metadata.

| Benchmark | What It Measures |
|-----------|-----------------|
| `affect/score/{positive,negative,neutral,mixed}` | Score emotional affect of text |
| `affect/modulated_encoding` | Affect-modulated memory encoding |
| `affect/congruent_boost` | Mood-congruent retrieval boost |
| `affect/to_emotional_context` | Convert affect to emotional context |
| `pricing/model_price/{gpt-5.3,claude-opus-4-6,claude-sonnet-4,gemini-3.1-pro,...}` | Look up model pricing |
| `pricing/estimate_cost_usd` | Estimate token cost |
| `pricing/classify_complexity/{simple,complex}` | Classify task complexity tier |
| `tool_meta/get/{execute_command,read_file,...}` | Retrieve tool metadata |
| `tool_meta/tools_in_tier/{safe,reversible,external}` | List tools by safety tier |
| `tool_meta/domain_lookup` | Resolve tool domain |

## Latest Results (March 2026, Apple M-series)

Results from `cargo bench -p openpawz-bench -- --quick` on an Apple M-series Mac.

### Session & Platform Operations

| Benchmark | Median |
|-----------|--------|
| `session/create` | 5.0 µs |
| `session/list/10` | 11.1 µs |
| `session/list/100` | 63.1 µs |
| `session/list/500` | 332.9 µs |
| `message/add` | 8.4 µs |
| `message/get/50` | 53.0 µs |
| `message/get/200` | 190.4 µs |
| `message/get/1000` | 947.9 µs |
| `task/create` | 7.5 µs |
| `task/list_200` | 298.9 µs |
| `agent/file_set` | 4.1 µs |
| `agent/file_get` | 2.5 µs |
| `config/set` | 2.4 µs |
| `config/get` | 1.6 µs |
| `config/get_miss` | 1.2 µs |
| `flow/save` | 8.4 µs |
| `flow/get` | 3.5 µs |
| `flow/list/10` | 11.0 µs |
| `flow/list/50` | 45.5 µs |
| `flow/list/200` | 167.1 µs |
| `flow/run_create` | 7.3 µs |
| `flow/run_list_100` | 72.1 µs |
| `squad/create` | 22.7 µs |
| `squad/list_20` | 70.4 µs |
| `squad/agents_share` | 3.5 µs |
| `squad/agent_in_squad` | 2.1 µs |
| `canvas/upsert` | 10.1 µs |
| `canvas/list_by_session/5` | 9.8 µs |
| `canvas/list_by_session/20` | 25.6 µs |
| `canvas/list_by_session/100` | 102.2 µs |
| `canvas/patch` | 3.5 µs |
| `project/create` | 6.2 µs |
| `project/list_20` | 87.0 µs |
| `project/set_agents_5` | 21.8 µs |
| `project/agents_share` | 4.3 µs |
| `project/agent_in_project` | 1.9 µs |
| `project/get_agent_model` | 2.0 µs |
| `telemetry/record` | 6.9 µs |
| `telemetry/daily_summary` | 25.1 µs |
| `telemetry/model_breakdown` | 62.5 µs |
| `telemetry/range_30d` | 81.4 µs |

### Memory & Knowledge Graph

| Benchmark | Median |
|-----------|--------|
| `memory/store` | 21.4 µs |
| `memory/search_keyword` | 12.9 µs |
| `memory/search_bm25` | 31.1 µs |
| `memory/list/20` | 16.3 µs |
| `memory/list/100` | 66.8 µs |
| `memory/list/500` | 365.2 µs |
| `memory/stats` | 10.9 µs |
| `memory/content_overlap/identical` | 1.1 µs |
| `memory/content_overlap/similar` | 1.1 µs |
| `memory/content_overlap/disjoint` | 1.2 µs |
| `memory/content_overlap/long` | 14.3 µs |
| `graph/relate` | 14.4 µs |
| `graph/apply_decay` | 3.8 µs |
| `graph/garbage_collect` | 4.1 µs |
| `graph/memory_stats` | 3.5 µs |
| `graph/store_procedural` | 10.7 µs |
| `episodic/store` | 36.1 µs |
| `episodic/get` | 9.4 µs |
| `episodic/batch_get/10` | 31.3 µs |
| `episodic/batch_get/50` | 108.8 µs |
| `episodic/batch_get/200` | 416.9 µs |
| `episodic/search_bm25/20` | 32.9 µs |
| `episodic/search_vector` | 36.5 µs |
| `semantic/store` | 26.1 µs |
| `semantic/search_bm25` | 20.2 µs |

### Engram (Cognitive Pipeline)

| Benchmark | Median |
|-----------|--------|
| `hnsw/insert/100` | 29.3 ms |
| `hnsw/insert/500` | 271.5 ms |
| `hnsw/insert/2000` | 1.89 s |
| `hnsw/search/100` | 37.1 µs |
| `hnsw/search/1000` | 380.6 µs |
| `hnsw/search/5000` | 733.2 µs |
| `reranking/rrf` | 6.2 µs |
| `reranking/mmr` | 63.8 µs |
| `hybrid/resolve_weight` | 436 ns |
| `abstraction/build_tree` | 8.7 µs |
| `sensory/push` | 253 ns |
| `affect/score_affect` | 6.3 µs |
| `intent/weights` | 5.0 µs |
| `metadata/infer` | 14.3 µs |
| `metadata/infer_full` | 16.3 µs |
| `temporal/cluster` | 3.0 µs |
| `quality/compute_ndcg` | 177 ns |
| `proposition/decompose_simple` | 1.4 µs |
| `proposition/decompose_compound` | 6.0 µs |
| `proposition/decompose_long` | 30.8 µs |
| `fusion/run/10` | 12.6 µs |
| `fusion/run/50` | 11.2 µs |

### Security & Cryptography

| Benchmark | Median |
|-----------|--------|
| `injection/scan/1KB` | 137.8 µs |
| `injection/scan/10KB` | 739.6 µs |
| `injection/scan/100KB` | 6.63 ms |
| `injection/scan_clean` | 205.1 µs |
| `injection/is_likely` | 82.9 µs |
| `encryption/encrypt` | 3.8 µs |
| `encryption/decrypt` | 3.0 µs |
| `crypto/derive_agent_key` | 1.6 µs |
| `crypto/quantize_score` | 3.5 ns |

### Audit & SCC

| Benchmark | Median |
|-----------|--------|
| `audit/append` | 16.4 µs |
| `audit/verify_chain/100` | 397.9 µs |
| `audit/verify_chain/1000` | 3.92 ms |
| `audit/verify_chain/5000` | 19.98 ms |
| `audit/query_recent_50` | 43.4 µs |
| `audit/stats` | 15.0 µs |
| `scc/issue_certificate` | 14.5 µs |
| `scc/capability_hash/3` | 553 ns |
| `scc/capability_hash/50` | 6.3 µs |
| `scc/memory_hash` | 1.5 µs |
| `scc/latest_certificate` | 3.7 µs |
| `scc/list_certificates_50` | 37.5 µs |

### Reasoning & Tool Metadata

| Benchmark | Median |
|-----------|--------|
| `affect/score/{positive,negative,neutral,mixed}` | 6.0–6.5 µs |
| `affect/modulated_encoding` | 1.3 ns |
| `affect/congruent_boost` | 2.1 ns |
| `affect/to_emotional_context` | 1.8 µs |
| `pricing/model_price` | 10–25 ns |
| `pricing/estimate_cost_usd` | 14.7 ns |
| `pricing/classify_complexity` | 23–24 ns |
| `tool_meta/get` | 12–17 ns |
| `tool_meta/tools_in_tier` | 228–265 ns |
| `tool_meta/domain_lookup` | 60 ns |
| `tool_meta/mutability` | 26–214 ns |
| `tool_meta/worker_allowed` | 16–24 ns |
| `tool_meta/orchestrator_safe` | 14–30 ns |
| `tool_meta/auto_approved` | 429 ns |
| `tool_meta/domain_str` | 18–31 ns |

## Running Benchmarks

All commands assume you're in the `src-tauri/` directory.

### Quick Timing (Built-in)

Runs a fast, self-contained timing loop — no Criterion overhead. Good for a
quick sanity check:

```bash
openpawz bench quick                  # 100 iterations (default)
openpawz bench quick --iterations 500 # 500 iterations
openpawz bench quick --output json    # Machine-readable output
```

### Full Criterion Suite

Runs the statistically rigorous Criterion suite with 100 samples per benchmark:

```bash
openpawz bench full                           # Run all 8 suites
openpawz bench full --bench session_bench     # Just session benchmarks
openpawz bench full --bench engram_bench hnsw # Filter to HNSW within engram
```

Or run directly with cargo:

```bash
cargo bench -p openpawz-bench                           # All suites
cargo bench -p openpawz-bench --bench memory_bench      # One suite
cargo bench -p openpawz-bench --bench engram_bench -- hnsw  # Filter
```

### Generate a Report

Parse Criterion's saved results and produce a Markdown report:

```bash
openpawz bench report                            # → benchmarks-report.md
openpawz bench report -o perf-report.md          # Custom output path
openpawz bench report --run-first                # Run benchmarks, then report
openpawz bench report --run-first --bench session_bench  # Run one suite first
openpawz bench report --output json              # Print JSON to stdout
```

The report includes:

- **Summary table** — count, fastest, and slowest per category
- **Detailed tables** — mean, median, and std dev for every benchmark
- **Top 10 slowest** — optimization targets at a glance
- **Top 10 fastest** — sanity check for sub-microsecond operations

### HTML Reports

Criterion automatically generates interactive HTML reports with charts:

```
target/criterion/report/index.html   # Overview
target/criterion/<bench>/report/     # Per-benchmark detail
```

Open them in a browser:

```bash
open target/criterion/report/index.html   # macOS
xdg-open target/criterion/report/index.html  # Linux
```

## Understanding Results

Each Criterion benchmark reports three timing values:

| Value | Meaning |
|-------|---------|
| **Mean** | Average across all samples |
| **Median** | 50th percentile — less sensitive to outliers |
| **Std Dev** | Spread — high values indicate noisy measurements |

### What's Normal?

| Operation Type | Expected Range |
|---------------|---------------|
| In-memory lookups (tokenizer, affect, intent, pricing, tool_meta) | < 10 µs |
| Config key/value get/set | 1–3 µs |
| Single SQLite reads (session get, flow get, canvas get) | 2–10 µs |
| Single SQLite writes (session create, flow save) | 5–25 µs |
| Batch SQLite reads (list 100–500 rows) | 40–400 µs |
| BM25 / keyword search | 15–60 µs |
| Message add (single insert) | 8–12 µs |
| HNSW search (1 000 vectors) | 300–400 µs |
| HNSW insert (2 000 vectors) | 1–3 s |
| Community detection (graph) | 100–300 µs |
| AES-256-GCM encrypt/decrypt | 3–4 µs |
| Argon2 key derivation | 1–2 µs |
| Injection scan (1 KB) | 130–150 µs |
| Injection scan (100 KB) | 6–7 ms |
| Content overlap (short) | 1–1.5 µs |
| Proposition decomposition (compound) | 5–7 µs |
| Telemetry range aggregate (30 days) | 80–100 µs |
| SCC capability hash (3 caps) | 500–600 ns |

### The "Gnuplot not found" Message

```
Gnuplot not found, using plotters backend
```

This is **harmless**. Criterion prefers gnuplot for HTML chart rendering but
falls back to plotters (a pure-Rust alternative) automatically. The benchmark
numbers are identical. To silence it:

```bash
brew install gnuplot   # macOS
sudo apt install gnuplot  # Debian/Ubuntu
```

## Tips

- **Consistent environment**: Close browsers and heavy apps before benchmarking.
  Criterion takes 100 samples, so transient load can cause outliers.
- **Warm the cache**: Run the suite twice. The first run populates OS file
  caches; the second gives more stable numbers.
- **Filter for speed**: Use `openpawz bench full --bench session_bench` to run
  just one suite when iterating on a specific module.
- **Regression tracking**: Save reports periodically
  (`openpawz bench report -o bench-2026-03-17.md`) and diff them to catch
  regressions.
- **CI integration**: Compare the `--output json` format programmatically
  against a baseline.
