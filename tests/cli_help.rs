// The README shows the binary's `-h` output exactly as printed.
//
// The help text is generated from the doc comments in `main.rs`, so an
// option added, renamed or removed there changes it without touching the
// README. These tests run the binary and fail until the README shows the
// new text.

use std::process::Command;

/// The README, read at compile time: `include_str!` embeds a file's text
/// in the test binary, its path relative to this source file. Cargo
/// rebuilds the test when the file changes.
const README: &str = include_str!("../README.md");

/// What `cc-extract <args>` prints on stdout.
fn output_of(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_cc-extract"))
        .args(args)
        .output()
        .expect("the binary runs");
    assert!(
        output.status.success(),
        "`cc-extract {}` failed",
        args.join(" ")
    );
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

/// Fail unless the README holds the help `args` print, line for line.
fn assert_readme_shows(args: &[&str]) {
    let help = output_of(args);
    assert!(
        README.contains(help.trim_end()),
        "README.md doesn't show `cc-extract {}` as printed:\n\n{help}",
        args.join(" ")
    );
}

#[test]
fn readme_shows_the_crawl_help() {
    assert_readme_shows(&["-h"]);
}

#[test]
fn readme_shows_the_merge_help() {
    assert_readme_shows(&["merge", "-h"]);
}
