// wreq_bench <outdir> <Profile>...  e.g. wreq_bench out Chrome149 Firefox151
// One GET per profile to the TLS echo endpoint; saves the raw echo JSON as wreq_<Profile>.json.
use wreq_util::{Emulation, Platform, Profile};

fn profile(name: &str) -> Option<Profile> {
    match name {
        "Chrome149" => Some(Profile::Chrome149),
        "Firefox151" => Some(Profile::Firefox151),
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
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
