//! The files under `deploy/`, which are what the machines of the test network
//! run.
//!
//! The two scripts cannot be run for real here: they want root, a package
//! manager, systemd and a firewall. What goes wrong in them is what they
//! decide, and that can be run. So each script is run whole, as it ships,
//! against a machine made of stand-ins: every system path is moved under a
//! scratch directory, every command that would touch the machine is a small
//! script that writes down what it was asked, and the build is a stand-in that
//! answers `--check` the way the program does. What a run leaves behind (the
//! unit it wrote, the directories it moved, the commands it gave) is then
//! read.
//!
//! The units themselves are read as text, for the numbers and directives an
//! operator relies on and systemd acts on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

const NODE_UNIT: &str = include_str!("../../../deploy/cairnd.service");
const EXPLORER_UNIT: &str = include_str!("../../../deploy/cairn-explorer.service");

/// A directive's value in a unit, the first time it is set.
fn directive<'a>(unit: &'a str, name: &str) -> Option<&'a str> {
    unit.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
        .map(str::trim)
}

fn seconds(value: &str) -> u64 {
    value
        .trim_end_matches('s')
        .parse()
        .unwrap_or_else(|_| panic!("`{value}` is not a number of seconds"))
}

/// A machine whose resolver is slow to come up after a reboot still comes up,
/// and a unit that cannot start still stops trying.
///
/// The node refuses to start when a seed the operator named does not resolve,
/// and the unit gave it five starts five seconds apart: twenty five seconds.
/// A seed machine whose resolver answered later than that after a reboot
/// stayed down until somebody started it by hand, under a README that said it
/// comes back on its own. Nothing read the two numbers together, so a unit
/// that gave up after twenty five seconds passed.
#[test]
fn a_unit_keeps_trying_for_as_long_as_a_resolver_takes_to_come_up() {
    for (name, unit) in [
        ("cairnd.service", NODE_UNIT),
        ("cairn-explorer.service", EXPLORER_UNIT),
    ] {
        let apart = seconds(directive(unit, "RestartSec").expect("a restart delay"));
        let starts: u64 = directive(unit, "StartLimitBurst")
            .expect("a limit on starts")
            .parse()
            .unwrap();
        let within = seconds(directive(unit, "StartLimitIntervalSec").expect("an interval"));
        let trying = apart * (starts - 1);
        assert!(
            trying >= 60,
            "{name} gives up after {trying} seconds of starts, which a resolver slow to \
             answer after a reboot outlasts: the machine then stays down until somebody \
             starts it by hand"
        );
        assert!(
            within > trying,
            "{name} counts starts over {within} seconds and spends {trying} making them, so \
             the limit is never reached and a node that cannot start restarts for ever"
        );
        let after = directive(unit, "After").unwrap_or_default();
        assert!(
            after.contains("nss-lookup.target"),
            "{name} is not ordered after the resolver it will ask for its seeds"
        );
    }
}

/// The node needs one directory and two sockets, and the unit takes away what
/// it does not need.
///
/// Nothing held the sandbox, so directives could go missing from it and every
/// test here stayed green. These were missing and cost nothing: no capability
/// at all, no set-user-id files, no clock or hostname changes, other
/// processes out of sight, only the system calls a service makes, and chain
/// files that are not world-readable on a shared machine.
#[test]
fn the_units_take_away_everything_a_node_does_not_use() {
    let wanted = [
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("RestrictSUIDSGID", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("ProtectProc", "invisible"),
        ("SystemCallFilter", "@system-service"),
        ("SystemCallErrorNumber", "EPERM"),
        ("UMask", "0027"),
    ];
    for (name, unit) in [
        ("cairnd.service", NODE_UNIT),
        ("cairn-explorer.service", EXPLORER_UNIT),
    ] {
        for (directive_name, value) in wanted {
            assert_eq!(
                directive(unit, directive_name),
                Some(value),
                "{name} does not set {directive_name}={value}"
            );
        }
        assert!(
            directive(unit, "LimitNOFILE").is_some(),
            "{name} does not say how many files the node may open, which is the \
             directive the node's own message about connections sends an operator to"
        );
    }
}

#[cfg(unix)]
mod scripts {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    /// One of the two scripts, and what differs between them.
    struct Script {
        text: &'static str,
        /// The unit it writes, under `/etc/systemd/system`.
        unit: &'static str,
        /// The same unit as it ships, which the script writes its line into.
        shipped: &'static str,
        /// The program it builds and installs.
        program: &'static str,
        /// Where the chain is kept when nothing says otherwise.
        data: &'static str,
        port: &'static str,
    }

    const INSTALL: Script = Script {
        text: include_str!("../../../deploy/install.sh"),
        unit: "cairnd.service",
        shipped: include_str!("../../../deploy/cairnd.service"),
        program: "cairnd",
        data: "/var/lib/cairn",
        port: "9944",
    };

    const EXPLORER: Script = Script {
        text: include_str!("../../../deploy/explorer.sh"),
        unit: "cairn-explorer.service",
        shipped: include_str!("../../../deploy/cairn-explorer.service"),
        program: "cairn-explorer",
        data: "/var/lib/cairn-explorer",
        port: "9945",
    };

    /// The system paths the scripts write to, every one of which is moved
    /// under the scratch directory before a script is run.
    const SYSTEM: [&str; 3] = ["/usr/local/", "/etc/", "/var/lib/"];

    /// The shells a script is run under: whatever `sh` is here, and `dash`
    /// where it is installed and is not already `sh`, since it is the `sh` of
    /// the machines these scripts are for.
    fn shells() -> Vec<&'static str> {
        let mut shells = vec!["sh"];
        let sh_is_dash = fs::canonicalize("/bin/sh")
            .is_ok_and(|shell| shell.to_string_lossy().ends_with("dash"));
        if Path::new("/bin/dash").exists() && !sh_is_dash {
            shells.push("/bin/dash");
        }
        shells
    }

    fn write_executable(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The commands a script would change the machine with, each a few lines
    /// that write down what they were asked under `$CAIRN_MACHINE`.
    ///
    /// Written once and shared by every run rather than made for each one:
    /// some systems look a new executable over the first time it runs, which
    /// costs most of a second, and a run calls a dozen of them.
    fn stand_ins() -> &'static Path {
        static MADE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        MADE.get_or_init(|| {
            let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("deploy-stand-ins");
            let stand_in = |name: &str, body: &str| {
                let text = format!("#!/bin/sh\n{body}\n");
                let path = directory.join(name);
                if fs::read_to_string(&path).ok().as_deref() == Some(text.as_str()) {
                    return;
                }
                // Beside and then into place, so a run in another process
                // never executes a file half written.
                let beside = directory.join(format!(".{name}.{}", std::process::id()));
                write_executable(&beside, &text);
                fs::rename(&beside, &path).unwrap();
            };
            stand_in("id", r#"[ "${1:-}" = "-u" ] && echo 0; exit 0"#);
            for quiet in [
                "apt-get", "curl", "cc", "useradd", "chown", "sleep", "gpg", "caddy",
            ] {
                stand_in(quiet, "exit 0");
            }
            stand_in(
                "git",
                r#"[ "$1" = "-C" ] && shift 2
case "$1" in
    rev-parse) echo 0123456789abcdef ;;
    symbolic-ref) echo main ;;
    log) echo 2026-09-26 ;;
esac
exit 0"#,
            );
            stand_in(
                "cargo",
                r#"for last; do :; done
mkdir -p target/release
ln -sf "$CAIRN_MACHINE/built" "target/release/$last""#,
            );
            stand_in(
                "systemctl",
                r#"echo "$*" >> "$CAIRN_MACHINE/systemctl.log"
case "$1" in
    is-active) [ ! -f "$CAIRN_MACHINE/stopped" ] ;;
    show) echo "today" ;;
esac"#,
            );
            stand_in(
                "ufw",
                r#"echo "$*" >> "$CAIRN_MACHINE/ufw.log"
case "${2%/tcp}" in
    "" | *[!0-9]*) echo "ERROR: Bad port" >&2; exit 1 ;;
esac"#,
            );
            // The program, built and installed. Which build it is stands in a
            // file under the machine: the one a machine was left running is a
            // link the test made, and a copy is the one the script installed.
            // It answers `--check` the way the program does: exit 2 for a line
            // it will not read, 1 for one it read and could not start with,
            // and otherwise its name and its network on the first two lines.
            let build = r#"case "$0" in
    */usr/local/bin/*) if [ -L "$0" ]; then which=running; else which=built; fi ;;
    *) which=built ;;
esac
. "$CAIRN_MACHINE/$which.conf"
program=${0##*/}
echo "$which $*" >> "$CAIRN_MACHINE/asked.log"
data=cairn-data
network=testnet
listen=0.0.0.0:1
named=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check | --archive) shift ;;
        --data) data=$2; shift 2 ;;
        --network) network=$2; named=1; shift 2 ;;
        --listen) listen=$2; shift 2 ;;
        *) shift 2 ;;
    esac
done
if [ -f "$data/cairn.conf" ] && grep -q refused "$data/cairn.conf"; then
    echo "$program: unknown setting in $data/cairn.conf" >&2
    exit 2
fi
if [ "$network" = testnet ]; then
    network=$testnet_is
fi
case " $knows " in
    *" $network "*) ;;
    *) echo "$program: unknown network $network" >&2; exit 2 ;;
esac
if [ -n "$named" ] && [ -f "$CAIRN_MACHINE/fails-with-a-name" ]; then
    echo "$program: could not start" >&2
    exit 1
fi
case "${listen##*:}" in
    "" | *[!0-9]*) echo "$program: $listen is not an address" >&2; exit 1 ;;
esac
echo "$program 0.0.0"
echo "network      $network (0x00000000)""#;
            // Twice, so that the build a machine is running and the one an
            // update makes are two files, as they are on a machine: `install`
            // refuses to copy a file onto itself.
            stand_in("build", build);
            stand_in("running-build", build);
            directory
        })
    }

    /// A machine for one run of one script.
    struct Machine {
        root: PathBuf,
        script: &'static Script,
        shell: &'static str,
    }

    impl Machine {
        fn new(script: &'static Script, name: &str, shell: &'static str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "cairn-deploy-{}-{}-{name}-{}",
                std::process::id(),
                script.program,
                shell.rsplit('/').next().unwrap_or(shell),
            ));
            let _ = fs::remove_dir_all(&root);
            let machine = Self {
                root,
                script,
                shell,
            };
            machine.stand_ins();
            machine
        }

        fn at(&self, path: &str) -> PathBuf {
            self.root.join(path.trim_start_matches('/'))
        }

        fn path(&self, path: &str) -> String {
            self.at(path).display().to_string()
        }

        fn stand_ins(&self) {
            fs::create_dir_all(self.at("/usr/local/src/cairn/.git")).unwrap();
            fs::create_dir_all(self.at("/etc/systemd/system")).unwrap();
            fs::create_dir_all(self.at("/etc/caddy")).unwrap();
            fs::create_dir_all(self.at("home")).unwrap();
            fs::create_dir_all(self.at("work")).unwrap();
            let shipped = self
                .at("/usr/local/src/cairn/deploy")
                .join(self.script.unit);
            fs::create_dir_all(shipped.parent().unwrap()).unwrap();
            fs::write(shipped, self.script.shipped).unwrap();
        }

        /// The build that is installed and running before the update, which
        /// knows the networks in `knows` and takes `testnet` to mean
        /// `testnet_is`.
        fn running(&self, knows: &str, testnet_is: &str) {
            let program = self.at(&format!("/usr/local/bin/{}", self.script.program));
            fs::create_dir_all(program.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(stand_ins().join("running-build"), program).unwrap();
            self.knows("running", knows, testnet_is);
        }

        /// The build the update makes.
        fn building(&self, knows: &str, testnet_is: &str) {
            std::os::unix::fs::symlink(stand_ins().join("build"), self.at("built")).unwrap();
            self.knows("built", knows, testnet_is);
        }

        fn knows(&self, which: &str, knows: &str, testnet_is: &str) {
            fs::write(
                self.root.join(format!("{which}.conf")),
                format!("knows=\"{knows}\"\ntestnet_is={testnet_is}\n"),
            )
            .unwrap();
        }

        /// A unit already installed, whose command line is `arguments`.
        fn installed(&self, arguments: &str) {
            let program = self.path(&format!("/usr/local/bin/{}", self.script.program));
            fs::write(
                self.unit_path(),
                format!("[Service]\nExecStart={program} {arguments}\n"),
            )
            .unwrap();
        }

        fn unit_path(&self) -> PathBuf {
            self.at("/etc/systemd/system").join(self.script.unit)
        }

        fn unit(&self) -> String {
            fs::read_to_string(self.unit_path()).unwrap_or_default()
        }

        fn exec_start(&self) -> String {
            self.unit()
                .lines()
                .find(|line| line.starts_with("ExecStart="))
                .unwrap_or_default()
                .to_owned()
        }

        fn log(&self, name: &str) -> String {
            fs::read_to_string(self.root.join(name)).unwrap_or_default()
        }

        /// The script as it ships, with every system path it names moved
        /// under this machine. Refused outright if one is left, so that no run
        /// of a script can reach the machine the tests are running on.
        fn script_text(&self) -> String {
            let mut text = self.script.text.to_owned();
            for prefix in SYSTEM {
                text = text.replace(prefix, &format!("{}{prefix}", self.root.display()));
            }
            let mut left = text.clone();
            for prefix in SYSTEM {
                left = left.replace(&format!("{}{prefix}", self.root.display()), "");
            }
            for prefix in SYSTEM {
                assert!(
                    !left.contains(prefix),
                    "a path under {prefix} was not moved, so this run is not made"
                );
            }
            text
        }

        fn run(&self, settings: &[(&str, &str)]) -> Output {
            let script = self.root.join("script.sh");
            fs::write(&script, self.script_text()).unwrap();
            let path = format!(
                "{}:{}",
                stand_ins().display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let mut command = Command::new(self.shell);
            command
                .arg(&script)
                .current_dir(self.at("work"))
                .env("PATH", path)
                .env("HOME", self.at("home"))
                .env("CAIRN_MACHINE", &self.root);
            for name in [
                "NETWORK",
                "PORT",
                "SEED",
                "MINE",
                "HTTP",
                "DOMAIN",
                "REPO",
                "CAIRN_INSTALLER_REEXEC",
            ] {
                command.env_remove(name);
            }
            for (name, value) in settings {
                command.env(name, value);
            }
            command.output().expect("the shell runs")
        }
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn said(output: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    /// An update keeps every argument the unit's command line had, and a
    /// setting it is told changes that setting and nothing else.
    ///
    /// Both scripts wrote the line again from the handful of settings they
    /// carry, and said only what they had kept. An operator who had written
    /// `--keep all` got a gigabyte back, and the next round of upkeep deleted
    /// the blocks being kept; `--data` went back to the default directory and
    /// the node started a chain from nothing beside the one it had; `--listen`
    /// on one interface opened on all of them; `--archive` stopped.
    #[test]
    fn an_update_carries_every_argument_the_unit_had() {
        for shell in shells() {
            for script in [&INSTALL, &EXPLORER] {
                let machine = Machine::new(script, "carries", shell);
                machine.running("testnet-6 devnet", "testnet-6");
                machine.building("testnet-6 devnet", "testnet-6");
                let chain = machine.path("/mnt/chain");
                // What each program takes: the explorer keeps everything and
                // archives without being told, and has no status line.
                let own: &[&str] = if script.program == "cairnd" {
                    &["--status 30", "--keep all", "--archive"]
                } else {
                    &["--keep 8GB"]
                };
                let mut by_hand = vec![
                    format!("--data {chain}"),
                    format!("--listen 203.0.113.5:{}", script.port),
                ];
                by_hand.extend(own.iter().map(|argument| (*argument).to_owned()));
                by_hand.push("--seed 198.51.100.7:9944".to_owned());
                machine.installed(&format!("--network testnet-6 {}", by_hand.join(" ")));

                let output = machine.run(&[]);
                assert!(output.status.success(), "{}", said(&output));
                let line = machine.exec_start();
                for argument in &by_hand {
                    assert!(
                        format!("{line} ").contains(&format!(" {argument} ")),
                        "{} dropped `{argument}` from the line it wrote: {line}",
                        script.unit
                    );
                }
                assert!(
                    machine
                        .unit()
                        .contains(&format!("\nReadWritePaths={chain}\n")),
                    "{} keeps the chain in {chain} and may only write the default directory",
                    script.unit
                );

                // A setting named changes what it names, and the address it
                // stands beside stays.
                let output = machine.run(&[("PORT", "9955")]);
                assert!(output.status.success(), "{}", said(&output));
                let line = machine.exec_start();
                assert!(
                    line.contains(" --listen 203.0.113.5:9955 ") && line.contains(own[0]),
                    "{} changed more than the port it was told: {line}",
                    script.unit
                );
            }
        }
    }

    /// A line the script cannot carry word for word is refused, and nothing is
    /// done.
    ///
    /// The line is split the way the shell splits it, and systemd reads
    /// quotes, variables and specifiers of its own. A line carrying one of
    /// those would be written back as something else, which is the loss this
    /// carrying exists to prevent.
    #[test]
    fn a_line_the_script_cannot_carry_is_refused_before_anything_is_done() {
        for script in [&INSTALL, &EXPLORER] {
            let machine = Machine::new(script, "quoted", "sh");
            machine.running("testnet-6", "testnet-6");
            machine.building("testnet-6", "testnet-6");
            machine.installed("--network testnet-6 --data \"/mnt/my chain\"");
            let before = machine.unit();

            let output = machine.run(&[]);
            assert!(
                !output.status.success(),
                "{} rewrote a line it could not carry",
                script.unit
            );
            assert_eq!(machine.unit(), before, "and changed the unit doing it");
            assert!(
                machine.log("systemctl.log").is_empty(),
                "and touched the service"
            );
        }
    }

    /// A network the machine leaves keeps its chain beside the new directory,
    /// and the new network starts from nothing.
    ///
    /// At a reset the scripts changed the network and nothing else, so the
    /// node started on the old network's directory. It either set every block
    /// aside, because none of them is on the new chain, or refused to start
    /// over the old network's ledger, five times and then for good, under a
    /// closing note saying it was running. Nothing moved the directory, and a
    /// script that left it where it was passed.
    #[test]
    fn a_retired_network_leaves_its_chain_beside_the_new_one() {
        for shell in shells() {
            for script in [&INSTALL, &EXPLORER] {
                let machine = Machine::new(script, "retired", shell);
                machine.running("testnet-6", "testnet-6");
                machine.building("testnet-7", "testnet-7");
                let data = machine.at(script.data);
                fs::create_dir_all(&data).unwrap();
                fs::write(data.join("blocks.log"), "testnet-6").unwrap();
                fs::write(data.join("cairn.conf"), "status = 30\n").unwrap();
                machine.installed(&format!("--network testnet-6 --data {}", data.display()));

                let output = machine.run(&[]);
                assert!(output.status.success(), "{}", said(&output));
                assert!(
                    machine.exec_start().contains(" --network testnet-7 "),
                    "{} did not move to the network the build has: {}",
                    script.unit,
                    machine.exec_start()
                );
                let kept = PathBuf::from(format!("{}.testnet-6", data.display()));
                assert!(
                    kept.join("blocks.log").exists(),
                    "{} started testnet-7 on testnet-6's chain rather than keeping it aside",
                    script.unit
                );
                assert!(
                    !data.join("blocks.log").exists(),
                    "{} left testnet-6's blocks where testnet-7 will open them",
                    script.unit
                );
                if script.program == "cairnd" {
                    assert_eq!(
                        fs::read_to_string(data.join("cairn.conf")).unwrap_or_default(),
                        "status = 30\n",
                        "the settings written for this machine did not go along"
                    );
                }
                assert!(
                    said(&output).contains(&kept.display().to_string()),
                    "{} did not say where the old chain went",
                    script.unit
                );
            }
        }
    }

    /// The same word naming another network after an update is a change of
    /// network.
    ///
    /// `testnet` names whichever test network is current. A unit written with
    /// it is on testnet-6 under the build that wrote it and on the next one
    /// under the build after, and the new build does not refuse the word, so
    /// nothing was retired and nothing was moved: the new network opened the
    /// old one's chain.
    #[test]
    fn the_same_word_naming_another_network_is_a_change_of_network() {
        for script in [&INSTALL, &EXPLORER] {
            let machine = Machine::new(script, "alias", "sh");
            machine.running("testnet-6", "testnet-6");
            machine.building("testnet-7", "testnet-7");
            let data = machine.at(script.data);
            fs::create_dir_all(&data).unwrap();
            fs::write(data.join("blocks.log"), "testnet-6").unwrap();
            machine.installed(&format!("--network testnet --data {}", data.display()));

            let output = machine.run(&[]);
            assert!(output.status.success(), "{}", said(&output));
            assert!(
                PathBuf::from(format!("{}.testnet-6", data.display()))
                    .join("blocks.log")
                    .exists(),
                "{} opened testnet-6's chain on testnet-7 because both are called testnet",
                script.unit
            );
        }
    }

    /// A network that stays keeps its directory where it is.
    ///
    /// The other half of the two tests above: moving a chain aside on every
    /// update would pass both of them, and cost every machine its chain.
    #[test]
    fn a_network_that_stays_keeps_its_directory() {
        for script in [&INSTALL, &EXPLORER] {
            let machine = Machine::new(script, "stays", "sh");
            machine.running("testnet-6", "testnet-6");
            machine.building("testnet-6 testnet-7", "testnet-6");
            let data = machine.at(script.data);
            fs::create_dir_all(&data).unwrap();
            fs::write(data.join("blocks.log"), "testnet-6").unwrap();
            machine.installed(&format!("--network testnet-6 --data {}", data.display()));

            let output = machine.run(&[]);
            assert!(output.status.success(), "{}", said(&output));
            assert!(
                data.join("blocks.log").exists(),
                "{} moved a chain aside with the network unchanged",
                script.unit
            );
        }
    }

    /// A line the program refuses changes nothing on the machine.
    ///
    /// Only the mining key was checked, by hand. A port or a seed the node
    /// refuses was written into the unit, enabled and restarted, the service
    /// failed five times and stopped, and the script then died at the
    /// firewall on the same bad port with all of that already done.
    #[test]
    fn a_line_the_program_refuses_changes_nothing_on_the_machine() {
        for shell in shells() {
            for script in [&INSTALL, &EXPLORER] {
                let machine = Machine::new(script, "refused", shell);
                machine.running("testnet-6", "testnet-6");
                machine.building("testnet-6", "testnet-6");
                machine.installed("--network testnet-6");
                let before = machine.unit();

                let output = machine.run(&[("PORT", "abc")]);
                assert!(
                    !output.status.success(),
                    "{} installed a line its program refuses",
                    script.unit
                );
                assert_eq!(
                    machine.unit(),
                    before,
                    "{} wrote a unit its program will not start",
                    script.unit
                );
                assert!(
                    !machine.log("systemctl.log").contains("restart"),
                    "{} restarted a service it had just broken: {}",
                    script.unit,
                    machine.log("systemctl.log")
                );
                assert!(
                    said(&output).contains("refuses the line"),
                    "{} did not say why nothing was installed: {}",
                    script.unit,
                    said(&output)
                );
            }
        }
    }

    /// A `cairn.conf` wherever the installer is started from has no say in
    /// the network, and a check that fails for another reason does not hand
    /// the machine another network.
    ///
    /// The installer asked `cairnd --check --network <name>` from the
    /// directory it was started in, which reads a `cairn-data/cairn.conf`
    /// there, and took any failure for a retired name. A setting file left in
    /// root's home refused the install as if testnet-6 were gone; a failure
    /// that was not about the name at all moved the machine to the build's
    /// network without a word.
    #[test]
    fn only_a_refused_name_is_taken_for_a_retired_network() {
        let machine = Machine::new(&INSTALL, "elsewhere", "sh");
        machine.running("testnet-6 testnet-7", "testnet-7");
        machine.building("testnet-6 testnet-7", "testnet-7");
        machine.installed("--network testnet-6");
        let stray = machine.at("work/cairn-data");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("cairn.conf"), "refused = yes\n").unwrap();

        let output = machine.run(&[]);
        assert!(
            output.status.success(),
            "a cairn.conf where the installer was started refused the install: {}",
            said(&output)
        );
        assert!(
            machine.exec_start().contains(" --network testnet-6 "),
            "and moved the machine off its network: {}",
            machine.exec_start()
        );

        let machine = Machine::new(&INSTALL, "not-the-name", "sh");
        machine.running("testnet-6 testnet-7", "testnet-7");
        machine.building("testnet-6 testnet-7", "testnet-7");
        machine.installed("--network testnet-6");
        fs::write(machine.root.join("fails-with-a-name"), "").unwrap();
        let before = machine.unit();

        let output = machine.run(&[]);
        assert!(
            !machine.exec_start().contains("testnet-7"),
            "a check that failed for another reason moved the machine to the build's network"
        );
        assert!(!output.status.success(), "and the install went on");
        assert_eq!(machine.unit(), before, "and rewrote the unit");
    }

    /// The restart that follows an update is not refused for the failures it
    /// has just mended.
    ///
    /// A unit that failed five starts inside its interval is refused a sixth
    /// until the interval has passed, a start asked for by hand included, and
    /// the scripts restarted without clearing the count.
    #[test]
    fn the_count_of_failed_starts_is_cleared_before_the_restart() {
        for script in [&INSTALL, &EXPLORER] {
            let machine = Machine::new(script, "cleared", "sh");
            machine.running("testnet-6", "testnet-6");
            machine.building("testnet-6", "testnet-6");
            machine.installed("--network testnet-6");

            let output = machine.run(&[]);
            assert!(output.status.success(), "{}", said(&output));
            let log = machine.log("systemctl.log");
            let name = script.unit.trim_end_matches(".service");
            let cleared = log.find(&format!("reset-failed {name}"));
            let restarted = log.find(&format!("restart {name}"));
            assert!(
                cleared.is_some() && cleared < restarted,
                "{} restarted without clearing the failures it had come to mend: {log}",
                script.unit
            );
        }
    }

    /// A service that is not running is not said to be.
    ///
    /// The closing note said the node was running, read the moment after the
    /// restart, while a node that cannot start was still on its way down.
    #[test]
    fn a_service_that_is_not_running_is_not_said_to_be() {
        for script in [&INSTALL, &EXPLORER] {
            let machine = Machine::new(script, "stopped", "sh");
            machine.running("testnet-6", "testnet-6");
            machine.building("testnet-6", "testnet-6");
            machine.installed("--network testnet-6");
            fs::write(machine.root.join("stopped"), "").unwrap();

            let output = machine.run(&[]);
            let words = said(&output);
            assert!(
                !words.contains("is running"),
                "{} said a service that had stopped is running: {words}",
                script.unit
            );
            assert!(
                words.contains("not running") && !output.status.success(),
                "{} ended as if nothing were wrong: {words}",
                script.unit
            );
        }
    }

    /// The names of the headers the explorer's server sends with every answer,
    /// read out of `cairn-http` where they are written.
    fn headers_the_server_sends() -> Vec<String> {
        const SERVER: &str = include_str!("../../../crates/cairn-http/src/http.rs");
        let block = SERVER
            .split_once("const SECURITY_HEADERS: &str = concat!(")
            .and_then(|(_, rest)| rest.split_once(");"))
            .expect("the server's headers are written in one place")
            .0;
        let joined: String = block
            .lines()
            .filter_map(|line| {
                let start = line.find('"')?;
                let end = line.rfind('"')?;
                line.get(start + 1..end)
            })
            .collect();
        joined
            .split("\\r\\n")
            .filter_map(|header| header.split_once(':'))
            .map(|(name, _)| name.trim().to_ascii_lowercase())
            .collect()
    }

    /// The Caddyfile an explorer machine is left with, run under `name`.
    fn caddyfile(name: &str) -> String {
        let machine = Machine::new(&EXPLORER, name, "sh");
        machine.running("testnet-6", "testnet-6");
        machine.building("testnet-6", "testnet-6");
        let output = machine.run(&[("DOMAIN", "example.org")]);
        assert!(output.status.success(), "{}", said(&output));
        fs::read_to_string(machine.at("/etc/caddy/Caddyfile")).unwrap()
    }

    /// The public site is served the explorer's own security headers, and the
    /// proxy in front writes none of them over.
    ///
    /// Caddy's `header Name value` replaces what the server behind it sent,
    /// and the Caddyfile set a Content-Security-Policy of its own, looser than
    /// the server's (`form-action 'self'` where the server says `'none'`,
    /// `default-src 'self'` where it says `'none'`). So the public site was
    /// served the policy nobody tested, and a tightening made in `cairn-http`
    /// never reached it. Nothing read the two places together.
    #[test]
    fn the_proxy_writes_none_of_the_headers_the_explorer_sends() {
        let sent = headers_the_server_sends();
        assert!(
            sent.iter().any(|name| name == "content-security-policy"),
            "the server's headers were not found where they are written: {sent:?}"
        );
        let written = caddyfile("headers");
        for line in written.lines() {
            let Some(name) = line.split_whitespace().next() else {
                continue;
            };
            assert!(
                !sent.contains(&name.to_ascii_lowercase()),
                "the Caddyfile writes {name} over the one the explorer sends: {line}"
            );
        }
    }

    /// A request that could carry a body is answered by the proxy and never
    /// reaches the explorer.
    ///
    /// The explorer serves nothing but GET and HEAD. Behind the proxy every
    /// reader arrives from the loopback, where the explorer's limit per
    /// address applies to nobody, and the proxy imposed nothing per client: a
    /// POST whose body never came held one of the explorer's connections for
    /// its whole deadline, and one laptop holding all of them took the public
    /// site down. The explorer now refuses a POST on its head; this keeps it
    /// from reaching the explorer at all.
    #[test]
    fn a_request_with_a_body_never_reaches_the_explorer() {
        let written = caddyfile("methods");
        let matcher = written
            .split_once("not method GET HEAD")
            .map(|(before, _)| before)
            .and_then(|before| before.rsplit_once('@'))
            .and_then(|(_, name)| name.split_whitespace().next())
            .map(str::to_owned);
        let Some(matcher) = matcher else {
            panic!("the Caddyfile names no matcher for methods other than GET and HEAD: {written}");
        };
        let refusal = written
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(&format!("respond @{matcher} ")));
        assert!(
            refusal.is_some_and(|line| line.ends_with(" 405")),
            "the Caddyfile does not answer @{matcher} itself with a 405, so it is \
             passed to the explorer: {written}"
        );
        let answered = written.find(&format!("respond @{matcher} "));
        let proxied = written.find("reverse_proxy");
        assert!(
            answered.is_some() && proxied.is_some(),
            "the refusal and the proxy are both in the site block: {written}"
        );
    }
}
