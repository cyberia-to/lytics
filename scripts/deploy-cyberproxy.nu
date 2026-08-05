# Build lytics-ingest (linux x86_64 via zig) and deploy to cyberproxy.
# Serves at https://cyberstates.net/lytics/
#
# Prereqs: rustup stable, cargo-zigbuild, zig, ssh cyberproxy
#
#   nu scripts/deploy-cyberproxy.nu

def main [] {
  let root = ($env.PWD | path expand)
  let rs = $"($root)/rs"
  if not ($"($rs)/Cargo.toml" | path exists) {
    error make {msg: "run from lytics repo root"}
  }

  let path = $"($env.HOME)/.rustup/toolchains/stable-aarch64-apple-darwin/bin:($env.HOME)/.cargo/bin:($env.PATH | str join ':')"
  let target = "x86_64-unknown-linux-gnu"
  let bin = $"($rs)/target/($target)/release/lytics-ingest"

  print "→ zigbuild lytics-ingest ($target)"
  with-env { PATH: $path } {
    cd $rs
    ^cargo zigbuild -p lytics-ingest --release --target $target
  }

  print "→ stage + rsync to cyberproxy:/home/cyber/lytics/"
  let stage = "/tmp/lytics-deploy"
  rm -rf $stage
  mkdir $"($stage)/bin" $"($stage)/data" $"($stage)/static/tracker"

  cp $bin $"($stage)/bin/lytics-ingest"
  cp $"($root)/data/dbip-city-lite.mmdb" $"($stage)/data/"
  ^cp -R $"($rs)/ingest/static/tracker/." $"($stage)/static/tracker/"

  ^ssh cyberproxy "mkdir -p /home/cyber/lytics/{bin,data/store,static/tracker}"
  ^rsync -az $"($stage)/bin/lytics-ingest" cyberproxy:/home/cyber/lytics/bin/
  ^rsync -az $"($stage)/static/tracker/" cyberproxy:/home/cyber/lytics/static/tracker/
  ^rsync -az $"($stage)/data/dbip-city-lite.mmdb" cyberproxy:/home/cyber/lytics/data/

  print "→ restart lytics.service"
  ^ssh cyberproxy "chmod +x /home/cyber/lytics/bin/lytics-ingest; sudo systemctl restart lytics; sleep 1; sudo systemctl is-active lytics"

  print ""
  print "live: https://cyberstates.net/lytics/"
  print "api:  https://cyberstates.net/lytics/api/report/overview"
}
