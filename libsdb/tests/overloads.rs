/////////////////////////////////////////
use std::path::PathBuf;
/////////////////////////////////////////
use nix::sys::{signal::Signal, wait::WaitStatus};
/////////////////////////////////////////
use libsdb::{address::VirtAddress, target::Target};
/////////////////////////////////////////

// These tests check source-level breakpoints against the C++ `overload_fixture`
// binary (see `tools/overload_fixture`), which defines three overloads of
// `print_type` (int, double, std::string) and calls them once each, in that
// order, from `main`.

fn launch_fixture() -> Target {
    let path = PathBuf::from(overload_fixture::fixture_path());
    Target::launch(&path, None, true, None).expect("Failed to launch overload_fixture target")
}

/// Resumes the process and waits for its next stop, asserting it was a
/// breakpoint trap, and returns the PC it landed on.
fn expect_breakpoint_hit(target: &mut Target) -> VirtAddress {
    target
        .process
        .resume_process()
        .expect("failed to resume process");
    let reason = target
        .process
        .wait_on_signal(None)
        .expect("failed to wait for process");
    assert!(
        matches!(reason.wait_status, WaitStatus::Stopped(_, Signal::SIGTRAP)),
        "expected the process to stop on a breakpoint, got {:?}",
        reason.wait_status
    );
    target.process.get_pc().expect("failed to get pc")
}

/// `[low_pc, high_pc)` of every DWARF function DIE named `name`.
fn function_ranges(target: &Target, name: &str) -> Vec<(VirtAddress, VirtAddress)> {
    let dwarf = target
        .state
        .dwarf
        .as_ref()
        .expect("fixture binary should carry DWARF info");
    dwarf
        .find_functions(name)
        .into_iter()
        .map(|func| {
            let low = func.low_pc().expect("missing low_pc");
            let high = func.high_pc().expect("missing high_pc");
            (
                low.to_virt_address().expect("low_pc not mapped"),
                high.to_virt_address().expect("high_pc not mapped"),
            )
        })
        .collect()
}

#[test]
fn dwarf_indexes_all_three_overloads() {
    let target = launch_fixture();
    let ranges = function_ranges(&target, "print_type");
    assert_eq!(
        ranges.len(),
        3,
        "expected one DWARF function per print_type overload, got {ranges:?}"
    );
}

#[test]
fn function_breakpoint_on_overloaded_name_plants_a_site_per_overload() {
    let mut target = launch_fixture();
    let ranges = function_ranges(&target, "print_type");
    let (id, _) = target
        .set_function_breakpoint("print_type")
        .expect("set_function_breakpoint should resolve the overloaded name");
    let addresses = target
        .breakpoint_addresses(id)
        .expect("breakpoint should be registered");
    assert_eq!(
        addresses.len(),
        3,
        "expected one site per overload, got {addresses:?}"
    );
    for range in &ranges {
        assert!(
            addresses.iter().any(|a| *a >= range.0 && *a < range.1),
            "no site landed inside overload range {range:?}; sites: {addresses:?}"
        );
    }
}

#[test]
fn function_breakpoint_on_overloaded_name_fires_once_per_overload() {
    let mut target = launch_fixture();
    let (id, _) = target
        .set_function_breakpoint("print_type")
        .expect("set_function_breakpoint should resolve the overloaded name");
    let addresses = target.breakpoint_addresses(id).unwrap();

    let mut hits = Vec::new();
    for _ in 0..addresses.len() {
        hits.push(expect_breakpoint_hit(&mut target));
    }
    let mut unique = hits.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        3,
        "each overload should be hit once: {hits:?}"
    );
    for hit in &hits {
        assert!(addresses.contains(hit), "{hit:?} is not a planted site");
    }
}
