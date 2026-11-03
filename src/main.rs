//! n4acl — a small TUI editor for NFSv4 ACLs on illumos ZFS.
#![cfg_attr(not(any(target_os = "illumos", n4acl_check_illumos)), allow(dead_code))]

mod ace;
mod apply;
mod ids;
mod model;
mod sys;
mod ui;

use ids::{IdDb, Source};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
n4acl — NFSv4/ZFS ACL editor for illumos

usage: n4acl [options] PATH
       n4acl --restore BACKUP

id context (how names are shown and resolved):
  -z ZONE             use ZONE's /etc/passwd and /etc/group (via its zonepath)
  -p PASSWD -g GROUP  use these files
  -G                  global zone (default unless the path is inside a zone)
  -n                  numeric ids only, never resolve names

non-interactive:
  --dump              print the ACL in chmod A= syntax (numeric with -n)
  --explain           explain every entry in plain language and run checks
  --test WHO          effective access for WHO = name | uid | uid:gid,gid…
  --restore FILE      re-apply ACLs saved in a backup file

  -h, --help          this text
";

struct Opts {
    path: Option<PathBuf>,
    source: Option<Source>,
    zone: Option<String>,
    passwd: Option<PathBuf>,
    group: Option<PathBuf>,
    dump: bool,
    explain: bool,
    test: Option<String>,
    restore: Option<PathBuf>,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts { path: None, source: None, zone: None, passwd: None, group: None, dump: false, explain: false, test: None, restore: None };
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        let s = a.to_string_lossy().into_owned();
        let mut val = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match s.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-z" => o.zone = Some(val("-z")?.to_string_lossy().into_owned()),
            "-p" => o.passwd = Some(val("-p")?.into()),
            "-g" => o.group = Some(val("-g")?.into()),
            "-G" => o.source = Some(Source::Global),
            "-n" => o.source = Some(Source::Numeric),
            "--dump" => o.dump = true,
            "--explain" => o.explain = true,
            "--test" => o.test = Some(val("--test")?.to_string_lossy().into_owned()),
            "--restore" => o.restore = Some(val("--restore")?.into()),
            "--" => o.path = args.next().map(PathBuf::from),
            _ if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option {s}")),
            _ if o.path.is_none() => o.path = Some(a.into()),
            _ => return Err("only one path is supported".into()),
        }
    }
    Ok(o)
}

fn id_source(o: &Opts, t: &ui::Target) -> Result<Source, String> {
    if let Some(z) = &o.zone {
        let zone = sys::zones().into_iter().find(|x| &x.name == z).ok_or_else(|| format!("no such zone: {z}"))?;
        return Ok(Source::Zone { name: zone.name.clone(), root: zone.root() });
    }
    match (&o.passwd, &o.group) {
        (Some(p), Some(g)) => return Ok(Source::Files { passwd: p.clone(), group: g.clone() }),
        (Some(_), None) | (None, Some(_)) => return Err("-p and -g must be used together".into()),
        _ => {}
    }
    if let Some(s) = &o.source {
        return Ok(s.clone());
    }
    if sys::current_zone() != "global" {
        return Ok(Source::Global); // inside a zone, its own name service is right
    }
    Ok(match sys::guess_zone(&t.mount.real_path, t.mount.dataset.as_deref(), t.props.zoned) {
        Some(z) => Source::Zone { name: z.name.clone(), root: z.root() },
        None => Source::Global,
    })
}

fn main() -> ExitCode {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("n4acl: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if let Some(f) = &o.restore {
        return match apply::restore(f) {
            Ok((n, errs)) => {
                println!("restored {n} ACL(s)");
                for (p, e) in &errs {
                    eprintln!("{}: {e}", p.display());
                }
                if errs.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
            }
            Err(e) => {
                eprintln!("n4acl: {}: {e}", f.display());
                ExitCode::FAILURE
            }
        };
    }
    let Some(path) = o.path.clone() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let target = match ui::Target::load(path.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("n4acl: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let src = match id_source(&o, &target) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("n4acl: {e}");
            return ExitCode::from(2);
        }
    };
    let numeric = matches!(src, Source::Numeric);
    let ids = IdDb::load(src);
    let acl = match sys::get_acl(&path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("n4acl: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    if o.dump || o.explain || o.test.is_some() {
        if o.dump {
            for a in &acl {
                println!("{}", ace::ace_text(a, &ids, numeric));
            }
        }
        let global = (!ids.is_global()).then(|| IdDb::load(Source::Global));
        if o.explain {
            for (i, a) in acl.iter().enumerate() {
                println!("#{} {}", i + 1, ace::ace_text(a, &ids, numeric));
                for l in ace::explain(a, target.is_dir, &ids, global.as_ref()) {
                    println!("   {l}");
                }
            }
            let cx = model::Ctx {
                is_dir: target.is_dir,
                ids: &ids,
                global: global.as_ref(),
                aclmode: target.props.aclmode.as_deref(),
                aclinherit: target.props.aclinherit.as_deref(),
            };
            for l in model::lint(&acl, &cx) {
                println!("{} {}", if l.sev == model::Severity::Warn { "warning:" } else { "note:" }, l.msg);
            }
        }
        if let Some(who) = &o.test {
            let (u, g) = who.split_once(':').map(|(a, b)| (a, Some(b))).unwrap_or((who.as_str(), None));
            let uid = match ace::resolve_user(u, &ids) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("n4acl: {e}");
                    return ExitCode::from(2);
                }
            };
            let gids = match g {
                Some(g) => {
                    let mut v = Vec::new();
                    for x in g.split(',').filter(|s| !s.is_empty()) {
                        match ace::resolve_group(x, &ids) {
                            Ok(id) => v.push(id),
                            Err(e) => {
                                eprintln!("n4acl: {e}");
                                return ExitCode::from(2);
                            }
                        }
                    }
                    v
                }
                None => ids.user_groups(uid),
            };
            println!("uid {uid} groups {gids:?}");
            for (p, d) in model::evaluate(&acl, &model::Subject { uid, gids }, target.uid, target.gid) {
                let s = match d {
                    model::Decision::Allowed(i) => format!("allow  (#{})", i + 1),
                    model::Decision::Denied(i) => format!("DENY   (#{})", i + 1),
                    model::Decision::OwnerImplicit => "allow  (owner, implicit)".into(),
                    model::Decision::NoMatch => "DENY   (no match)".into(),
                };
                println!("  {} {:<17} {s}", p.ch, p.name);
            }
        }
        return ExitCode::SUCCESS;
    }

    match ui::run(ui::App::new(target, ids, acl)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("n4acl: {e}");
            ExitCode::FAILURE
        }
    }
}
