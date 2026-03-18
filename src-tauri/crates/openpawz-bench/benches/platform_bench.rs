use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use openpawz_bench::*;
use openpawz_core::atoms::types::{Flow, FlowRun, Project, ProjectAgent, Squad, SquadMember};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

static CONFIG_CTR: AtomicU64 = AtomicU64::new(0);
static FLOW_CTR: AtomicU64 = AtomicU64::new(0);
static SQUAD_CTR: AtomicU64 = AtomicU64::new(0);
static CANVAS_CTR: AtomicU64 = AtomicU64::new(0);
static PROJECT_CTR: AtomicU64 = AtomicU64::new(0);
static TEL_CTR: AtomicU64 = AtomicU64::new(0);

// ── Config key/value store ───────────────────────────────────────────────

fn bench_config_set(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("config/set", |b| {
        b.iter(|| {
            let i = CONFIG_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .set_config(
                    &format!("key-{}", i % 50),
                    black_box("bench-value-with-some-realistic-length"),
                )
                .unwrap();
        });
    });
}

fn bench_config_get(c: &mut Criterion) {
    let store = fresh_store();
    for i in 0..50 {
        store
            .set_config(&format!("key-{}", i), &format!("value-{}", i))
            .unwrap();
    }
    c.bench_function("config/get", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i = (i + 1) % 50;
            black_box(store.get_config(black_box(&format!("key-{}", i))).unwrap());
        });
    });
}

fn bench_config_get_miss(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("config/get_miss", |b| {
        b.iter(|| black_box(store.get_config(black_box("nonexistent-key")).unwrap()));
    });
}

// ── Flow CRUD ────────────────────────────────────────────────────────────

fn make_flow(id: &str) -> Flow {
    let ts = now();
    Flow {
        id: id.into(),
        name: "Benchmark Flow".into(),
        description: Some("A flow created during benchmarking".into()),
        folder: None,
        graph_json: r#"{"nodes":[{"id":"n1","type":"trigger"},{"id":"n2","type":"action"}],"edges":[{"from":"n1","to":"n2"}]}"#.into(),
        created_at: ts.clone(),
        updated_at: ts,
    }
}

fn make_flow_run(id: &str, flow_id: &str) -> FlowRun {
    FlowRun {
        id: id.into(),
        flow_id: flow_id.into(),
        status: "success".into(),
        duration_ms: Some(1234),
        events_json: Some(r#"[{"type":"start"},{"type":"complete"}]"#.into()),
        error: None,
        started_at: now(),
        finished_at: Some(now()),
    }
}

fn bench_flow_save(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("flow/save", |b| {
        b.iter(|| {
            let i = FLOW_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .save_flow(black_box(&make_flow(&format!("fl-{}", i))))
                .unwrap();
        });
    });
}

fn bench_flow_get(c: &mut Criterion) {
    let store = fresh_store();
    for i in 0..50 {
        store.save_flow(&make_flow(&format!("fg-{}", i))).unwrap();
    }
    c.bench_function("flow/get", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i = (i + 1) % 50;
            black_box(store.get_flow(black_box(&format!("fg-{}", i))).unwrap());
        });
    });
}

fn bench_flow_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("flow/list");
    for &count in &[10, 50, 200] {
        let store = fresh_store();
        for i in 0..count {
            store.save_flow(&make_flow(&format!("fll-{}", i))).unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(count), &store, |b, store| {
            b.iter(|| black_box(store.list_flows().unwrap().len()));
        });
    }
    group.finish();
}

static FLOW_RUN_CTR: AtomicU64 = AtomicU64::new(0);

fn bench_flow_run_create(c: &mut Criterion) {
    let store = fresh_store();
    store.save_flow(&make_flow("fr-flow")).unwrap();
    c.bench_function("flow/run_create", |b| {
        b.iter(|| {
            let i = FLOW_RUN_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .create_flow_run(black_box(&make_flow_run(&format!("fr-{}", i), "fr-flow")))
                .unwrap();
        });
    });
}

fn bench_flow_run_list(c: &mut Criterion) {
    let store = fresh_store();
    store.save_flow(&make_flow("frl-flow")).unwrap();
    for i in 0..100 {
        store
            .create_flow_run(&make_flow_run(&format!("frl-{}", i), "frl-flow"))
            .unwrap();
    }
    c.bench_function("flow/run_list_100", |b| {
        b.iter(|| {
            black_box(
                store
                    .list_flow_runs(black_box("frl-flow"), 100)
                    .unwrap()
                    .len(),
            )
        });
    });
}

// ── Squad operations ─────────────────────────────────────────────────────

fn make_squad(id: &str, member_count: usize) -> Squad {
    let ts = now();
    Squad {
        id: id.into(),
        name: "Benchmark Squad".into(),
        goal: "Run fast".into(),
        status: "active".into(),
        members: (0..member_count)
            .map(|i| SquadMember {
                agent_id: format!("agent-{}", i),
                role: if i == 0 {
                    "coordinator".into()
                } else {
                    "member".into()
                },
            })
            .collect(),
        created_at: ts.clone(),
        updated_at: ts,
    }
}

fn bench_squad_create(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("squad/create", |b| {
        b.iter(|| {
            let i = SQUAD_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .create_squad(black_box(&make_squad(&format!("sq-{}", i), 4)))
                .unwrap();
        });
    });
}

fn bench_squad_list(c: &mut Criterion) {
    let store = fresh_store();
    for i in 0..20 {
        store
            .create_squad(&make_squad(&format!("sql-{}", i), 3))
            .unwrap();
    }
    c.bench_function("squad/list_20", |b| {
        b.iter(|| black_box(store.list_squads().unwrap().len()));
    });
}

fn bench_agents_share_squad(c: &mut Criterion) {
    let store = fresh_store();
    store.create_squad(&make_squad("shared-sq", 5)).unwrap();
    c.bench_function("squad/agents_share", |b| {
        b.iter(|| black_box(store.agents_share_squad(black_box("agent-0"), black_box("agent-3"))));
    });
}

fn bench_agent_in_squad(c: &mut Criterion) {
    let store = fresh_store();
    store.create_squad(&make_squad("scope-sq", 5)).unwrap();
    c.bench_function("squad/agent_in_squad", |b| {
        b.iter(|| black_box(store.agent_in_squad(black_box("agent-2"), black_box("scope-sq"))));
    });
}

// ── Canvas operations ────────────────────────────────────────────────────

fn bench_canvas_upsert(c: &mut Criterion) {
    let store = fresh_store();
    store
        .create_session("canvas-sess", "model", None, None)
        .unwrap();
    c.bench_function("canvas/upsert", |b| {
        b.iter(|| {
            let i = CANVAS_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .upsert_canvas_component(
                    &format!("cc-{}", i),
                    Some("canvas-sess"),
                    None,
                    "bench-agent",
                    "code_block",
                    "Benchmark Canvas",
                    r#"{"language":"rust","code":"fn main() {}"}"#,
                    Some(r#"{"x":0,"y":0,"w":400,"h":300}"#),
                )
                .unwrap();
        });
    });
}

fn bench_canvas_list_by_session(c: &mut Criterion) {
    let mut group = c.benchmark_group("canvas/list_by_session");
    for &count in &[5, 20, 100] {
        let store = fresh_store();
        store
            .create_session("cls-sess", "model", None, None)
            .unwrap();
        for i in 0..count {
            store
                .upsert_canvas_component(
                    &format!("cls-{}", i),
                    Some("cls-sess"),
                    None,
                    "agent",
                    "chart",
                    &format!("Chart {}", i),
                    "{}",
                    None,
                )
                .unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(count), &store, |b, store| {
            b.iter(|| {
                black_box(
                    store
                        .list_canvas_by_session(black_box("cls-sess"))
                        .unwrap()
                        .len(),
                )
            });
        });
    }
    group.finish();
}

fn bench_canvas_patch(c: &mut Criterion) {
    let store = fresh_store();
    store
        .create_session("cp-sess", "model", None, None)
        .unwrap();
    store
        .upsert_canvas_component(
            "cp-1",
            Some("cp-sess"),
            None,
            "agent",
            "text",
            "Patch Target",
            "original data",
            None,
        )
        .unwrap();
    c.bench_function("canvas/patch", |b| {
        b.iter(|| {
            black_box(
                store
                    .patch_canvas_component(
                        black_box("cp-1"),
                        Some("Updated Title"),
                        Some("updated data"),
                        None,
                    )
                    .unwrap(),
            )
        });
    });
}

// ── Project operations ───────────────────────────────────────────────────

fn make_project(id: &str, agent_count: usize) -> Project {
    let ts = now();
    Project {
        id: id.into(),
        title: "Benchmark Project".into(),
        goal: "Maximize throughput".into(),
        status: "running".into(),
        boss_agent: "boss-agent".into(),
        agents: (0..agent_count)
            .map(|i| ProjectAgent {
                agent_id: format!("pa-{}", i),
                role: if i == 0 {
                    "boss".into()
                } else {
                    "worker".into()
                },
                specialty: "general".into(),
                status: "idle".into(),
                current_task: None,
                model: None,
                system_prompt: None,
                capabilities: vec!["read_file".into(), "execute_command".into()],
            })
            .collect(),
        created_at: ts.clone(),
        updated_at: ts,
    }
}

fn bench_project_create(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("project/create", |b| {
        b.iter(|| {
            let i = PROJECT_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .create_project(black_box(&make_project(&format!("proj-{}", i), 3)))
                .unwrap();
        });
    });
}

fn bench_project_list(c: &mut Criterion) {
    let store = fresh_store();
    for i in 0..20 {
        store
            .create_project(&make_project(&format!("pl-{}", i), 3))
            .unwrap();
    }
    c.bench_function("project/list_20", |b| {
        b.iter(|| black_box(store.list_projects().unwrap().len()));
    });
}

fn bench_project_set_agents(c: &mut Criterion) {
    let store = fresh_store();
    store.create_project(&make_project("psa-proj", 0)).unwrap();
    let agents: Vec<ProjectAgent> = (0..5)
        .map(|i| ProjectAgent {
            agent_id: format!("psa-agent-{}", i),
            role: "worker".into(),
            specialty: "coder".into(),
            status: "idle".into(),
            current_task: None,
            model: None,
            system_prompt: None,
            capabilities: vec![],
        })
        .collect();
    c.bench_function("project/set_agents_5", |b| {
        b.iter(|| {
            store
                .set_project_agents(black_box("psa-proj"), black_box(&agents))
                .unwrap()
        });
    });
}

fn bench_agents_share_project(c: &mut Criterion) {
    let store = fresh_store();
    store.create_project(&make_project("asp-proj", 5)).unwrap();
    c.bench_function("project/agents_share", |b| {
        b.iter(|| black_box(store.agents_share_project(black_box("pa-0"), black_box("pa-3"))));
    });
}

fn bench_agent_in_project(c: &mut Criterion) {
    let store = fresh_store();
    store.create_project(&make_project("aip-proj", 5)).unwrap();
    c.bench_function("project/agent_in_project", |b| {
        b.iter(|| black_box(store.agent_in_project(black_box("pa-2"), black_box("aip-proj"))));
    });
}

fn bench_get_agent_model(c: &mut Criterion) {
    let store = fresh_store();
    let mut proj = make_project("gam-proj", 3);
    proj.agents[0].model = Some("gpt-5.3".into());
    store.create_project(&proj).unwrap();
    c.bench_function("project/get_agent_model", |b| {
        b.iter(|| black_box(store.get_agent_model(black_box("pa-0"))));
    });
}

// ── Telemetry ────────────────────────────────────────────────────────────

fn bench_telemetry_record(c: &mut Criterion) {
    let store = fresh_store();
    c.bench_function("telemetry/record", |b| {
        b.iter(|| {
            let i = TEL_CTR.fetch_add(1, Ordering::Relaxed);
            store
                .record_metric(
                    "2026-03-17",
                    &format!("tl-sess-{}", i % 10),
                    "gpt-5.3",
                    2000,
                    500,
                    0.015,
                    3,
                    450,
                    1200,
                    1650,
                    2,
                )
                .unwrap();
        });
    });
}

fn bench_telemetry_daily(c: &mut Criterion) {
    let store = fresh_store();
    for i in 0..100 {
        store
            .record_metric(
                "2026-03-17",
                &format!("td-sess-{}", i),
                if i % 2 == 0 {
                    "gpt-5.3"
                } else {
                    "claude-sonnet-4"
                },
                1500 + (i * 10) as u64,
                400 + (i * 5) as u64,
                0.01 + (i as f64 * 0.001),
                2,
                300,
                1000,
                1300,
                1,
            )
            .unwrap();
    }
    c.bench_function("telemetry/daily_summary", |b| {
        b.iter(|| black_box(store.get_daily_metrics(black_box("2026-03-17")).unwrap()));
    });
}

fn bench_telemetry_model_breakdown(c: &mut Criterion) {
    let store = fresh_store();
    let models = &[
        "gpt-5.3",
        "claude-opus-4-6",
        "claude-sonnet-4",
        "gemini-3.1-pro",
        "gemini-3-flash",
        "deepseek-reasoner",
    ];
    for i in 0..200 {
        store
            .record_metric(
                "2026-03-17",
                &format!("tmb-sess-{}", i),
                models[i % models.len()],
                2000,
                500,
                0.02,
                2,
                300,
                1000,
                1300,
                1,
            )
            .unwrap();
    }
    c.bench_function("telemetry/model_breakdown", |b| {
        b.iter(|| black_box(store.get_model_breakdown(black_box("2026-03-17")).unwrap()));
    });
}

fn bench_telemetry_range(c: &mut Criterion) {
    let store = fresh_store();
    for day in 1..=30 {
        for i in 0..10 {
            store
                .record_metric(
                    &format!("2026-03-{:02}", day),
                    &format!("tr-sess-{}", i),
                    "gpt-5.3",
                    1500,
                    400,
                    0.01,
                    2,
                    300,
                    1000,
                    1300,
                    1,
                )
                .unwrap();
        }
    }
    c.bench_function("telemetry/range_30d", |b| {
        b.iter(|| {
            black_box(
                store
                    .get_metrics_range(black_box("2026-03-01"), black_box("2026-03-30"))
                    .unwrap(),
            )
        });
    });
}

criterion_group!(
    config_ops,
    bench_config_set,
    bench_config_get,
    bench_config_get_miss
);
criterion_group!(
    flow_ops,
    bench_flow_save,
    bench_flow_get,
    bench_flow_list,
    bench_flow_run_create,
    bench_flow_run_list,
);
criterion_group!(
    squad_ops,
    bench_squad_create,
    bench_squad_list,
    bench_agents_share_squad,
    bench_agent_in_squad,
);
criterion_group!(
    canvas_ops,
    bench_canvas_upsert,
    bench_canvas_list_by_session,
    bench_canvas_patch,
);
criterion_group!(
    project_ops,
    bench_project_create,
    bench_project_list,
    bench_project_set_agents,
    bench_agents_share_project,
    bench_agent_in_project,
    bench_get_agent_model,
);
criterion_group!(
    telemetry_ops,
    bench_telemetry_record,
    bench_telemetry_daily,
    bench_telemetry_model_breakdown,
    bench_telemetry_range,
);
criterion_main!(
    config_ops,
    flow_ops,
    squad_ops,
    canvas_ops,
    project_ops,
    telemetry_ops
);
