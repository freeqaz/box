//! A host command reads the command's input as a pipe while it runs.

#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

use box_shell::{HostSpawnOutcome, HostSpawner};
use strands_shell::Shell;
use tokio::io::AsyncReadExt as _;

/// A host folder at `/workspace` holding the host program `stdin-probe`, and a Shell whose spawner
/// stands in for it.
struct Probe {
    folder: tempfile::TempDir,
    program: String,
    shell: Shell,
}

/// Run `body` on a current-thread runtime.
fn on_runtime<F: std::future::Future>(body: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

fn probe(reads_stdin: bool) -> Probe {
    let folder = tempfile::tempdir().expect("host folder");
    let program = folder.path().join("stdin-probe");
    std::fs::write(&program, "#!/bin/sh\n").expect("a program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    // Like a contained program, it prints the input it reads, or reads none.
    let spawner: HostSpawner = Arc::new(move |spawn: box_shell::HostSpawn| {
        Box::pin(async move {
            let mut stdout = Vec::new();
            if reads_stdin && let Some(mut stdin) = spawn.stdin {
                stdin.read_to_end(&mut stdout).await?;
            }
            Ok(HostSpawnOutcome {
                status: 0,
                stdout,
                stderr: Vec::new(),
            })
        })
    });
    let shell = support::builder()
        .bind_direct(folder.path().to_str().expect("UTF-8"), "/workspace")
        .host_spawner(spawner)
        .build()
        .expect("shell builds");
    Probe {
        program: program.to_str().expect("UTF-8").to_string(),
        folder,
        shell,
    }
}

/// A host program reads what an earlier stage of the command wrote, byte for byte.
#[test]
fn a_host_command_reads_what_its_command_pipes_to_it() {
    let mut probe = probe(true);
    on_runtime(async {
        let out = probe
            .shell
            .run(&format!("printf 'one\\ntwo\\n' | {}", probe.program))
            .await;
        assert_eq!(
            (out.status, out.stdout.as_str()),
            (0, "one\ntwo\n"),
            "{}",
            out.stderr
        );
    });
}

/// Input larger than the pipe's buffer reaches the program whole, by backpressure.
#[test]
fn a_host_command_reads_input_larger_than_the_pipe_buffer() {
    let mut probe = probe(true);
    let large = "x".repeat(256 * 1024);
    std::fs::write(probe.folder.path().join("large"), &large).expect("a large input");
    on_runtime(async {
        let out = probe
            .shell
            .run(&format!("cat /workspace/large | {}", probe.program))
            .await;
        assert_eq!(out.status, 0, "{}", out.stderr);
        assert_eq!(out.stdout.len(), large.len());
    });
}

/// A host command with no input reads none.
#[test]
fn a_host_command_with_no_input_reads_nothing() {
    let mut probe = probe(true);
    on_runtime(async {
        let out = probe.shell.run(&probe.program).await;
        assert_eq!((out.status, out.stdout.as_str()), (0, ""), "{}", out.stderr);
    });
}

/// A host program that never reads its input is not held by a writer that keeps writing.
#[test]
fn a_host_command_that_reads_no_input_is_not_held() {
    let mut probe = probe(false);
    let large = "x".repeat(1024 * 1024);
    std::fs::write(probe.folder.path().join("large"), &large).expect("a large input");
    on_runtime(async {
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            probe
                .shell
                .run(&format!("cat /workspace/large | {}", probe.program)),
        )
        .await
        .expect("the program's end ends the command");
        assert_eq!(out.status, 0, "{}", out.stderr);
    });
}
