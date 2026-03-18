use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use openpawz_bench::*;
use openpawz_core::engine::engram::memory_fusion;
use openpawz_core::engine::engram::proposition;
use openpawz_core::engine::scc;
use openpawz_core::engine::tool_metadata;
use std::hint::black_box;

// ── Proposition decomposition ────────────────────────────────────────────

fn bench_decompose_simple(c: &mut Criterion) {
    let text = "Rust uses ownership for memory safety.";
    c.bench_function("proposition/decompose_simple", |b| {
        b.iter(|| black_box(proposition::decompose(black_box(text))));
    });
}

fn bench_decompose_compound(c: &mut Criterion) {
    let text = "Rust uses ownership for memory safety and it prevents data races at compile time. \
        The borrow checker enforces these rules, and lifetimes annotate reference scopes. \
        Additionally, smart pointers like Box and Rc provide heap allocation patterns.";
    c.bench_function("proposition/decompose_compound", |b| {
        b.iter(|| black_box(proposition::decompose(black_box(text))));
    });
}

fn bench_decompose_long(c: &mut Criterion) {
    let text = MEMORY_CORPUS.join(". ");
    c.bench_function("proposition/decompose_long", |b| {
        b.iter(|| black_box(proposition::decompose(black_box(&text))));
    });
}

// ── Memory fusion ────────────────────────────────────────────────────────

fn bench_fusion_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("fusion/run");
    for &count in &[10, 50] {
        let store = fresh_store();
        for i in 0..count {
            let emb = random_vec_bytes(384);
            store
                .store_memory(
                    &format!("fus-{}", i),
                    MEMORY_CORPUS[i % MEMORY_CORPUS.len()],
                    "fact",
                    5,
                    Some(&emb),
                    Some("bench-agent"),
                )
                .unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(count), &store, |b, store| {
            b.iter(|| black_box(memory_fusion::run_fusion(store).unwrap()));
        });
    }
    group.finish();
}

// ── SCC extended ─────────────────────────────────────────────────────────

fn bench_compute_capability_hash(c: &mut Criterion) {
    let caps_small = vec![
        "read_file".into(),
        "execute_command".into(),
        "write_file".into(),
    ];
    let caps_large: Vec<String> = (0..50).map(|i| format!("tool_{}", i)).collect();
    let mut group = c.benchmark_group("scc/capability_hash");
    group.bench_with_input(BenchmarkId::new("count", 3), &caps_small, |b, caps| {
        b.iter(|| black_box(scc::compute_capability_hash(black_box(caps))));
    });
    group.bench_with_input(BenchmarkId::new("count", 50), &caps_large, |b, caps| {
        b.iter(|| black_box(scc::compute_capability_hash(black_box(caps))));
    });
    group.finish();
}

fn bench_compute_memory_hash(c: &mut Criterion) {
    let store = fresh_store();
    // Seed some audit entries for the hash to read
    for i in 0..50 {
        openpawz_core::engine::audit::append(
            &store,
            openpawz_core::engine::audit::AuditCategory::Memory,
            "store",
            "agent",
            "sess",
            &format!("sub-{}", i),
            None,
            true,
        )
        .unwrap();
    }
    c.bench_function("scc/memory_hash", |b| {
        b.iter(|| black_box(scc::compute_memory_hash(black_box(&store))));
    });
}

fn bench_scc_latest_certificate(c: &mut Criterion) {
    let store = fresh_store();
    let caps = vec!["tool_a".into(), "tool_b".into()];
    for _ in 0..20 {
        scc::issue_certificate(&store, "model", &caps).unwrap();
    }
    c.bench_function("scc/latest_certificate", |b| {
        b.iter(|| black_box(scc::latest_certificate(black_box(&store)).unwrap()));
    });
}

fn bench_scc_list_certificates(c: &mut Criterion) {
    let store = fresh_store();
    let caps = vec!["tool_a".into(), "tool_b".into()];
    for _ in 0..50 {
        scc::issue_certificate(&store, "model", &caps).unwrap();
    }
    c.bench_function("scc/list_certificates_50", |b| {
        b.iter(|| black_box(scc::list_certificates(black_box(&store), 50).unwrap()));
    });
}

// ── Tool metadata extended ───────────────────────────────────────────────

fn bench_tool_mutability(c: &mut Criterion) {
    let tools = &[
        ("read_file", "known_safe"),
        ("execute_command", "known_write"),
        ("custom_mcp_tool", "unknown_fallback"),
    ];
    let mut group = c.benchmark_group("tool_meta/mutability");
    for (tool, label) in tools {
        group.bench_with_input(BenchmarkId::new("tool", *label), tool, |b, tool| {
            b.iter(|| black_box(tool_metadata::mutability(black_box(tool))));
        });
    }
    group.finish();
}

fn bench_tool_worker_allowed(c: &mut Criterion) {
    let tools = &["read_file", "execute_command", "custom_mcp_tool"];
    let mut group = c.benchmark_group("tool_meta/worker_allowed");
    for tool in tools {
        group.bench_with_input(BenchmarkId::new("tool", *tool), tool, |b, tool| {
            b.iter(|| black_box(tool_metadata::worker_allowed(black_box(tool))));
        });
    }
    group.finish();
}

fn bench_tool_orchestrator_safe(c: &mut Criterion) {
    let tools = &["read_file", "execute_command", "coinbase_get_balance"];
    let mut group = c.benchmark_group("tool_meta/orchestrator_safe");
    for tool in tools {
        group.bench_with_input(BenchmarkId::new("tool", *tool), tool, |b, tool| {
            b.iter(|| black_box(tool_metadata::orchestrator_safe(black_box(tool))));
        });
    }
    group.finish();
}

fn bench_auto_approved_tools(c: &mut Criterion) {
    c.bench_function("tool_meta/auto_approved", |b| {
        b.iter(|| black_box(tool_metadata::auto_approved_tools()));
    });
}

fn bench_tool_domain_str(c: &mut Criterion) {
    let tools = &[
        "execute_command",
        "store_memory",
        "coinbase_get_balance",
        "read_file",
        "upsert_canvas_component",
    ];
    let mut group = c.benchmark_group("tool_meta/domain_str");
    for tool in tools {
        group.bench_with_input(BenchmarkId::new("tool", *tool), tool, |b, tool| {
            b.iter(|| black_box(tool_metadata::domain_str(black_box(tool))));
        });
    }
    group.finish();
}

criterion_group!(
    proposition_group,
    bench_decompose_simple,
    bench_decompose_compound,
    bench_decompose_long,
);
criterion_group!(fusion_group, bench_fusion_small);
criterion_group!(
    scc_extended,
    bench_compute_capability_hash,
    bench_compute_memory_hash,
    bench_scc_latest_certificate,
    bench_scc_list_certificates,
);
criterion_group!(
    tool_meta_extended,
    bench_tool_mutability,
    bench_tool_worker_allowed,
    bench_tool_orchestrator_safe,
    bench_auto_approved_tools,
    bench_tool_domain_str,
);
criterion_main!(
    proposition_group,
    fusion_group,
    scc_extended,
    tool_meta_extended
);
