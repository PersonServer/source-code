//! psd — a self-hostable AAuth Person Server daemon.
//!
//! Subcommands:
//!   psd serve [--config PATH]        run the HTTP server
//!   psd keygen [--keys PATH] [--rotate] [--prune-days N]
//!   psd person add --name NAME       create a person + print a one-time enrolment link
//!   psd person list
//!   psd invite --person ID [--ttl S] print a new enrolment link for an existing person
//!   psd agents list | revoke ISS SUB
//!   psd pending list | approve ID [--person ID] | deny ID
//!                                    decide a waiting request from the operator's shell
//!   psd example-config               print an example config to stdout
//!   psd version

mod app;
mod audit;
mod config;
mod consent;
mod federation;
mod handlers;
mod httpc;
mod issue;
mod jwks_cache;
mod keys;
mod markdown;
mod metadata;
mod notify;
mod passkey;
mod pending;
mod problem;
mod reqctx;
mod restoken;
mod revocation;
mod router;
mod server;
mod store;
mod ui;
mod upstream;

#[cfg(test)]
mod tests;

use tokio::net::TcpListener;

use app::App;
use config::Config;
use keys::KeySet;

/// The draft revisions this build tracks. AAuth is an evolving IETF
/// Internet-Draft family, not a released standard: wire formats change
/// between revisions. Pin a commit and re-read the Document History before
/// upgrading.
const TRACKED_DRAFTS: [&str; 2] = [
    "draft-hardt-oauth-aauth-protocol-11",
    "draft-hardt-httpbis-signature-key-08",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = match cmd {
        "serve" => run_serve(&args),
        "keygen" => run_keygen(&args),
        "person" => run_person(&args),
        "invite" => run_invite(&args),
        "agents" => run_agents(&args),
        "pending" => run_pending(&args),
        "example-config" => {
            print!("{}", config::EXAMPLE_CONFIG);
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!(
                "psd {} (tracking AAuth Internet-Drafts: {})",
                env!("CARGO_PKG_VERSION"),
                TRACKED_DRAFTS.join(", ")
            );
            Ok(())
        }
        _ => {
            print_help();
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    eprintln!(
        "psd {} — AAuth Person Server\n\n\
         USAGE:\n\
         \x20 psd serve [--config psd.json]\n\
         \x20 psd keygen [--keys psd-keys.json] [--rotate] [--prune-days N]\n\
         \x20 psd person add --name \"Alice\" [--config psd.json] [--ttl 900]\n\
         \x20 psd person list [--config psd.json]\n\
         \x20 psd invite --person ID [--config psd.json] [--ttl 900]\n\
         \x20 psd agents list [--config psd.json]\n\
         \x20 psd agents revoke ISS SUB [--config psd.json]\n\
         \x20 psd pending list [--config psd.json]\n\
         \x20 psd pending approve ID [--person ID] [--config psd.json]\n\
         \x20 psd pending deny ID [--config psd.json]\n\
         \x20 psd example-config > psd.json\n\
         \x20 psd version\n\n\
         Environment overrides: PSD_ISSUER, PSD_LISTEN, PSD_KEYS_FILE, PSD_DB_PATH,\n\
         PSD_TELEMETRY_ENABLED, OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME.",
        env!("CARGO_PKG_VERSION")
    );
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--keys").unwrap_or("psd-keys.json");
    let rotate = has_flag(args, "--rotate");
    let prune = flag(args, "--prune-days")
        .map(|d| d.parse::<u64>().map(|days| days * 86400))
        .transpose()
        .map_err(|_| "invalid --prune-days")?;
    let msg = keys::keygen(path, rotate, prune)?;
    println!("{msg}");
    Ok(())
}

fn open_store(args: &[String]) -> Result<(Config, store::Store), String> {
    let config_path = flag(args, "--config").unwrap_or("psd.json");
    let cfg = Config::load(config_path)?;
    let st = store::Store::open(&cfg.storage.path).map_err(|e| e.to_string())?;
    if cfg.storage.path == ":memory:" {
        return Err(
            "storage.path is :memory:; a CLI command against an in-memory database has \
                    nothing to act on"
                .into(),
        );
    }
    Ok((cfg, st))
}

fn enrolment_url(cfg: &Config, token: &str) -> String {
    format!("{}/enrol/{token}", cfg.issuer)
}

fn ttl_flag(args: &[String], default: u64) -> Result<u64, String> {
    flag(args, "--ttl")
        .map(|s| s.parse::<u64>().map_err(|_| "invalid --ttl".to_string()))
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn run_person(args: &[String]) -> Result<(), String> {
    match args.get(2).map(|s| s.as_str()) {
        Some("add") => {
            let name = flag(args, "--name").ok_or("--name is required")?;
            if name.trim().is_empty() || name.len() > 128 {
                return Err("--name must be 1..=128 characters".into());
            }
            let ttl = ttl_flag(args, 900)?;
            let (cfg, st) = open_store(args)?;
            let person = st.create_person(name.trim()).map_err(|e| e.to_string())?;
            let token = st
                .create_enrolment(&person.id, ttl)
                .map_err(|e| e.to_string())?;
            println!("{}", enrolment_url(&cfg, &token));
            eprintln!(
                "created person {} ({}); open the link above within {ttl}s to register a passkey \
                 (single use)",
                person.id, person.display_name
            );
            if crate::passkey::Passkeys::new(&cfg.issuer).is_err() {
                eprintln!(
                    "WARNING: issuer host is an IP address; browsers will refuse to create a \
                     passkey there. Use a hostname issuer (e.g. http://localhost:8430)."
                );
            }
            Ok(())
        }
        Some("list") => {
            let (_cfg, st) = open_store(args)?;
            for p in st.list_persons().map_err(|e| e.to_string())? {
                let creds = st
                    .credentials_for_person(&p.id)
                    .map_err(|e| e.to_string())?
                    .len();
                println!(
                    "{}\t{}\t{} passkey(s)\tcreated {}",
                    p.id,
                    p.display_name,
                    creds,
                    ui::format_utc(p.created_at)
                );
            }
            Ok(())
        }
        _ => Err("usage: psd person add --name NAME | psd person list".into()),
    }
}

fn run_invite(args: &[String]) -> Result<(), String> {
    let person_id =
        flag(args, "--person").ok_or("--person ID is required (see `psd person list`)")?;
    let ttl = ttl_flag(args, 900)?;
    let (cfg, st) = open_store(args)?;
    let person = st
        .get_person(person_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no person with id {person_id}"))?;
    let token = st
        .create_enrolment(&person.id, ttl)
        .map_err(|e| e.to_string())?;
    println!("{}", enrolment_url(&cfg, &token));
    eprintln!(
        "enrolment link for {} ({}); valid {ttl}s, single use",
        person.id, person.display_name
    );
    Ok(())
}

fn run_agents(args: &[String]) -> Result<(), String> {
    match args.get(2).map(|s| s.as_str()) {
        Some("list") => {
            let (_cfg, st) = open_store(args)?;
            for p in st.list_persons().map_err(|e| e.to_string())? {
                for b in st.bindings_for_person(&p.id).map_err(|e| e.to_string())? {
                    println!(
                        "{}\t{}\t{}\t{}\tperson {}\tsince {}",
                        b.status,
                        b.agent_iss,
                        b.agent_sub,
                        b.ap_name.as_deref().unwrap_or("-"),
                        p.id,
                        ui::format_utc(b.bound_at)
                    );
                }
            }
            Ok(())
        }
        Some("revoke") => {
            let (iss, sub) = match (args.get(3), args.get(4)) {
                (Some(i), Some(s)) if !i.starts_with("--") && !s.starts_with("--") => (i, s),
                _ => return Err("usage: psd agents revoke ISS SUB".into()),
            };
            let (cfg, st) = open_store(args)?;
            let binding = st
                .binding(iss, sub)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no binding for ({iss}, {sub})"))?;
            if st.revoke_binding(iss, sub).map_err(|e| e.to_string())? {
                st.revoke_consents_for_agent(&binding.person_id, iss, sub)
                    .map_err(|e| e.to_string())?;
                st.audit(
                    Some(&binding.person_id),
                    "operator",
                    "binding_revoked",
                    Some(sub),
                    &serde_json::json!({ "agent_iss": iss, "agent_sub": sub, "via": "cli" }),
                )
                .map_err(|e| e.to_string())?;
                println!(
                    "revoked binding of {sub} at {iss} (was person {})",
                    binding.person_id
                );
                // SHOULD: revoke outstanding auth tokens at their resources.
                let keys = KeySet::load(&cfg.keys_file)?;
                let audit = audit::Audit::new(cfg.audit_log_file.as_deref())?;
                let app = App::build(cfg, keys, audit, st)?;
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let sweep = rt.block_on(async {
                    let _ = rustls::crypto::ring::default_provider().install_default();
                    revocation::revoke_auth_tokens_for_agent(
                        &app,
                        iss,
                        sub,
                        "binding_revoked_by_operator",
                    )
                    .await
                });
                println!(
                    "auth tokens: {} live, {} resources notified, {} not reachable",
                    sweep.tokens, sweep.notified, sweep.failed
                );
            } else {
                println!("binding of {sub} at {iss} was already revoked");
            }
            Ok(())
        }
        _ => Err("usage: psd agents list | psd agents revoke ISS SUB".into()),
    }
}

/// `psd pending …` — the operator decides a waiting request from the shell.
/// The operator holds the database and the keys, so this grants nothing a
/// dashboard session could not; it exists for headless deployments and for
/// shape A, where the operator is the person.
fn run_pending(args: &[String]) -> Result<(), String> {
    let (cfg, st) = open_store(args)?;
    match args.get(2).map(|s| s.as_str()) {
        Some("list") => {
            let persons = st.list_persons().map_err(|e| e.to_string())?;
            let mut any = false;
            for p in persons.iter() {
                for pr in st.pending_for_person(&p.id).map_err(|e| e.to_string())? {
                    any = true;
                    print_pending(&pr, Some(&p.display_name));
                }
            }
            // Unclaimed requests are not tied to a person yet; list them by
            // scanning recent audit is roundabout — use a direct query.
            for pr in st.unclaimed_pending().map_err(|e| e.to_string())? {
                any = true;
                print_pending(&pr, None);
            }
            if !any {
                eprintln!("no pending requests");
            }
            Ok(())
        }
        Some(action @ ("approve" | "deny")) => {
            let id = args
                .get(3)
                .filter(|s| !s.starts_with("--"))
                .ok_or_else(|| format!("usage: psd pending {action} ID [--person ID]"))?;
            let pr = st
                .pending(id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no pending request {id}"))?;
            if !pr.is_open() {
                return Err(format!(
                    "pending request {id} is {} — nothing to decide",
                    pr.state
                ));
            }
            // Which person decides: --person, the claimed person, or the only one.
            let person_id = match (flag(args, "--person"), &pr.person_id) {
                (Some(p), Some(claimed)) if p != claimed => {
                    return Err(format!(
                        "pending request {id} is claimed by person {claimed}, not {p}"
                    ))
                }
                (Some(p), _) => p.to_string(),
                (None, Some(claimed)) => claimed.clone(),
                (None, None) => {
                    let persons = st.list_persons().map_err(|e| e.to_string())?;
                    match persons.as_slice() {
                        [only] => only.id.clone(),
                        [] => return Err("no person exists yet (psd person add)".into()),
                        _ => {
                            return Err(
                                "several persons exist; say which one decides with --person ID"
                                    .into(),
                            )
                        }
                    }
                }
            };
            if st
                .get_person(&person_id)
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Err(format!("no person with id {person_id}"));
            }
            let keys = KeySet::load(&cfg.keys_file)?;
            let audit = audit::Audit::new(cfg.audit_log_file.as_deref())?;
            let app = App::build(cfg, keys, audit, st)?;
            let pr = app
                .store
                .claim_pending(id, &person_id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| {
                    format!("pending request {id} could not be claimed for {person_id} (expired, or claimed by someone else)")
                })?;
            if action == "deny" {
                consent::deny(&app, &person_id, &pr, "cli")?;
                println!("denied {id}");
                return Ok(());
            }
            match consent::approve(&app, &person_id, &pr, "cli")? {
                consent::ApproveOutcome::Approved { jti, exp } => {
                    println!(
                        "approved {id}: person token {jti} issued (exp {}), waiting for the agent's poll",
                        ui::format_utc(exp)
                    );
                    Ok(())
                }
                consent::ApproveOutcome::BoundElsewhere { owner } => Err(format!(
                    "refused: agent is actively bound to person {owner}; revoke that binding first"
                )),
                consent::ApproveOutcome::Expired => Err("too late: the request expired".into()),
            }
        }
        _ => Err("usage: psd pending list | approve ID [--person ID] | deny ID".into()),
    }
}

fn print_pending(pr: &store::Pending, person: Option<&str>) {
    println!(
        "{}\t{}\t{}\t{}\t{}\tresource {}\tasked {}\texpires {}",
        pr.id,
        pr.state,
        pr.kind,
        pr.agent_sub,
        person.unwrap_or("(unclaimed)"),
        pr.payload
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("-"),
        ui::format_utc(pr.created_at),
        ui::format_utc(pr.expires_at)
    );
}

fn run_serve(args: &[String]) -> Result<(), String> {
    let config_path = flag(args, "--config").unwrap_or("psd.json");
    let cfg = Config::load(config_path)?;
    let keys = KeySet::load(&cfg.keys_file)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(serve(cfg, keys))
}

async fn serve(cfg: Config, keys: KeySet) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listen = cfg.listen.clone();
    let issuer = cfg.issuer.clone();
    let insecure = cfg.insecure_dev_mode;
    let db_path = cfg.storage.path.clone();

    let app = App::new(cfg, keys)?;

    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("cannot bind {listen}: {e}"))?;

    app.audit.emit(
        "server_started",
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "issuer": issuer,
            "tracked_drafts": TRACKED_DRAFTS,
        }),
    );
    eprintln!("psd {} listening on {listen}", env!("CARGO_PKG_VERSION"));
    eprintln!("  issuer:   {issuer}");
    eprintln!("  storage:  sqlite {db_path}");
    eprintln!(
        "  ui:       {} · templates {}",
        if app.passkeys.is_some() {
            "passkeys enabled"
        } else {
            "passkeys UNAVAILABLE (issuer host is an IP address; use a hostname)"
        },
        if app.templates.overridden.is_empty() {
            "built-in".to_string()
        } else {
            format!("overridden: {}", app.templates.overridden.join(", "))
        }
    );
    eprintln!("  drafts:   {}", TRACKED_DRAFTS.join(", "));
    eprintln!(
        "  note:     AAuth is an IETF Internet-Draft; wire formats may change between revisions"
    );
    if insecure {
        eprintln!("  WARNING:  insecure_dev_mode is ON — do not use in production");
    }

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\nshutting down");
    };
    server::run(listener, app, shutdown).await;
    Ok(())
}
