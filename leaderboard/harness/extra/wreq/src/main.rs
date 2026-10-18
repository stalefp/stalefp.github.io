// wreq_bench <outdir> <Profile>...  e.g. wreq_bench out Chrome149 Firefox151
// One GET per profile to the TLS echo endpoint; saves the raw echo JSON as wreq_<Profile>.json.
// wreq_bench --probe wreq <Profile> <browser> <url> <n> <headers-json>
// Behaviour probe (leaderboard/harness/probe.py): n GETs on ONE client with the given headers in the given order
// (orig_headers, client default headers off), certificate check off for the local capture cert. Prints {ok, done, error}.
use wreq_util::{Emulation, Platform, Profile};

fn profile(name: &str) -> Option<Profile> {
    match name {
        "Chrome149" => Some(Profile::Chrome149),
        "Firefox151" => Some(Profile::Firefox151),
        _ => None,
    }
}

/// Minimal parser for the probe's headers argument: a JSON array of [name, value] string pairs (no serde in the lockfile).
fn parse_pairs(s: &str) -> Vec<(String, String)> {
    let mut strs = Vec::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '"' { continue; }
        let mut cur = String::new();
        while let Some(c) = it.next() {
            match c {
                '"' => break,
                '\\' => match it.next() {
                    Some('n') => cur.push('\n'), Some('t') => cur.push('\t'),
                    Some('u') => { let h: String = it.by_ref().take(4).collect(); if let Some(ch) = u32::from_str_radix(&h, 16).ok().and_then(char::from_u32) { cur.push(ch) } }
                    Some(o) => cur.push(o), None => {}
                },
                o => cur.push(o),
            }
        }
        strs.push(cur);
    }
    strs.chunks(2).filter(|p| p.len() == 2).map(|p| (p[0].clone(), p[1].clone())).collect()
}

fn esc(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ") }

async fn probe(args: &[String]) {
    // args: wreq <Profile> <browser> <url> <n> <headers-json>
    let (name, url, n) = (&args[1], &args[3], args[4].parse::<usize>().unwrap_or(8));
    let hdrs = parse_pairs(&args[5]);
    let mut done = 0;
    let res: Result<(), String> = async {
        let p = profile(name).ok_or(format!("unknown profile {name}"))?;
        let em = Emulation::builder().profile(p).platform(Platform::Linux).build();
        let client = wreq::Client::builder().emulation(em).tls_cert_verification(false).build().map_err(|e| e.to_string())?;
        for i in 0..n {
            let mut orig = wreq::header::OrigHeaderMap::new();
            let mut rb = client.get(format!("{url}&i={i}")).default_headers(false);
            for (k, v) in &hdrs { orig.insert(k.clone()); rb = rb.header(k.as_str(), v.as_str()); }
            rb.orig_headers(orig).send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?;
            done += 1;
        }
        Ok(())
    }.await;
    match res {
        Ok(()) => println!("{{\"ok\": true, \"done\": {done}}}"),
        Err(e) => println!("{{\"ok\": {}, \"done\": {done}, \"error\": \"{}\"}}", done > 0, esc(&e)),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--probe") { probe(&args[2..]).await; return; }
    let out = &args[1];
    std::fs::create_dir_all(out).unwrap();
    let mut failed = false;
    for name in &args[2..] {
        let Some(p) = profile(name) else { eprintln!("{name}: unknown profile"); failed = true; continue };
        let em = Emulation::builder().profile(p).platform(Platform::Linux).build();
        let res = async { wreq::get("https://tls.peet.ws/api/all").emulation(em).send().await?.text().await }.await;
        match res {
            Ok(body) => { std::fs::write(format!("{out}/wreq_{name}.json"), &body).unwrap(); println!("wreq {name}: ok"); }
            Err(e) => { eprintln!("wreq {name}: {e}"); failed = true; }
        }
    }
    if failed { std::process::exit(1); }
}
