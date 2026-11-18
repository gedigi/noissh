# Packaging & deployment contrib

Supplementary files for deploying noissh. Nothing here is built by `cargo`; copy
what you need.

## systemd unit (`noisshd.service`)

Runs the standalone server daemon on UDP port 51820 with sensible sandboxing.

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/noisshd /usr/local/bin/noisshd
   ```

2. Create a dedicated unprivileged user (the daemon serves *this* user's login
   shell, so pick the account you actually want reachable — never root):

   ```sh
   sudo useradd --system --create-home --shell /bin/bash noissh
   ```

3. Install and enable the unit:

   ```sh
   sudo install -m 0644 contrib/noisshd.service /etc/systemd/system/noisshd.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now noisshd
   ```

4. Authorize client keys by adding their public key lines to
   `~noissh/.config/noissh/authorized_keys` (one `noissh-x25519 <base64>` per
   line). A client prints its line with `noissh-keygen`. The daemon picks up
   changes to this file within a couple of seconds (no restart needed), and
   removing a key ends that key's sessions. Keep the file and its directory
   writable by their owner only (`chmod go-w`): the daemon refuses them
   otherwise.

5. Open UDP 51820 in your firewall. Check status / logs:

   ```sh
   systemctl status noisshd
   journalctl -u noisshd -f
   ```

Adjust `User=`, `ExecStart=` path, and the `--listen` address/port in the unit
to taste. If you install the binary elsewhere, update `ExecStart=` accordingly.

## Homebrew (placeholder)

A formula is not published yet. Planned outline:

```ruby
# Formula/noissh.rb (TODO)
class Noissh < Formula
  desc "Resilient remote shell over QUIC and Noise"
  homepage "https://github.com/gedigi/noissh"
  # url "https://github.com/gedigi/noissh/archive/refs/tags/vX.Y.Z.tar.gz"
  # sha256 "..."
  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end
end
```

TODO: tagged release tarball + sha256, a tap (`gedigi/homebrew-tap`), and a
`brew services` plist mirroring the systemd unit for macOS.

## Debian package

The release workflow builds `.deb` packages for x86_64 and aarch64 Linux with
`cargo-deb` (metadata in the root `Cargo.toml`, `[package.metadata.deb]`) and
attaches them to each GitHub release. They install the three binaries and the
man pages; they do not install this systemd unit or create a user.
