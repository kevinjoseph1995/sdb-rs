/////////////////////////////////////////
use std::{ffi::CString, path::PathBuf};
/////////////////////////////////////////
use nix::sys::{signal::Signal, wait::WaitStatus};
/////////////////////////////////////////
use libsdb::{address::FileAddress, address::VirtAddress, target::Target};
/////////////////////////////////////////

// These tests drive `Target::step_in` / `step_over` / `step_out` against the
// `dwarf_fixture` binary (see `tools/dwarf_fixture`), which is compiled at
// `-O0` with DWARF line info, so calls stay real calls (nothing inlined) and
// every source line maps predictably to machine instructions.
//
// `entry_b` calls `sum_b` exactly once at the top level; `sum_b` then
// recurses over a 3-node linked list. That shape is what makes it a good
// fixture for stepping: a step-over of the `sum_b` call must skip the entire
// recursive call tree, not just one frame.

fn launch_fixture() -> Target {
    let path = PathBuf::from(dwarf_fixture::fixture_path());
    Target::launch(&path, None, true, None).expect("Failed to launch dwarf_fixture target")
}

fn function_range(target: &Target, name: &str) -> (VirtAddress, VirtAddress) {
    let dwarf = target
        .state
        .dwarf
        .as_ref()
        .expect("fixture binary should carry DWARF info");
    let func = dwarf
        .find_functions(name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("function `{name}` not found in fixture binary"));
    let low = func
        .low_pc()
        .expect("missing low_pc")
        .to_virt_address()
        .expect("low_pc not mapped into the running process");
    let high = func
        .high_pc()
        .expect("missing high_pc")
        .to_virt_address()
        .expect("high_pc not mapped into the running process");
    (low, high)
}

fn range_contains(range: (VirtAddress, VirtAddress), addr: VirtAddress) -> bool {
    addr >= range.0 && addr < range.1
}

/// Runs the process to `entry_b`'s first instruction via a temporary
/// breakpoint, asserting the stop looks like a normal breakpoint hit.
fn run_to_entry_b(target: &mut Target, entry_b_low_pc: VirtAddress) {
    let reason = target
        .process
        .run_until_address(entry_b_low_pc)
        .expect("failed to run to entry_b");
    assert!(matches!(
        reason.wait_status,
        WaitStatus::Stopped(_, Signal::SIGTRAP)
    ));
}

/// Calls `step_in` until the PC lands inside `range`, returning that PC.
fn step_in_until_in_range(target: &mut Target, range: (VirtAddress, VirtAddress)) -> VirtAddress {
    for steps_taken in 0.. {
        assert!(steps_taken < 200, "step_in never reached the target range");
        let reason = target.step_in().expect("step_in failed");
        assert!(
            reason.is_step(),
            "step_in stopped for an unexpected reason: {:?}",
            reason.wait_status
        );
        let pc = target.process.get_pc().expect("failed to get pc");
        if range_contains(range, pc) {
            return pc;
        }
    }
    unreachable!()
}

#[test]
fn test_step_over_does_not_descend_into_callee() {
    let mut target = launch_fixture();
    let entry_b_range = function_range(&target, "entry_b");
    let sum_b_range = function_range(&target, "sum_b");
    run_to_entry_b(&mut target, entry_b_range.0);
    // Move past entry_b's prologue first: a real function breakpoint (as
    // opposed to the raw low_pc used above) never lands exactly on it, and
    // stepping over from the bare low_pc is an untested edge case upstream
    // doesn't guard against either.
    target
        .step_in()
        .expect("step_in past the prologue failed");

    // Step line-by-line through entry_b until it returns. At no point should
    // the PC land inside sum_b's address range, even though entry_b's one
    // call to sum_b recurses three levels deep.
    for steps_taken in 0.. {
        assert!(
            steps_taken < 200,
            "step_over did not leave entry_b within a reasonable number of steps"
        );
        let reason = target.step_over().expect("step_over failed");
        assert!(
            reason.is_step(),
            "step_over stopped for an unexpected reason: {:?}",
            reason.wait_status
        );
        let pc = target.process.get_pc().expect("failed to get pc");
        assert!(
            !range_contains(sum_b_range, pc),
            "step_over landed inside sum_b at {pc}"
        );
        if !range_contains(entry_b_range, pc) {
            break;
        }
    }
}

#[test]
fn test_step_in_enters_callee_past_prologue() {
    let mut target = launch_fixture();
    let entry_b_range = function_range(&target, "entry_b");
    let sum_b_range = function_range(&target, "sum_b");
    run_to_entry_b(&mut target, entry_b_range.0);

    let pc = step_in_until_in_range(&mut target, sum_b_range);

    // step_in skips the prologue when it lands on a function's first
    // instruction, so we should be past sum_b's low_pc, not sitting on it.
    assert_ne!(
        pc, sum_b_range.0,
        "step_in should have skipped sum_b's prologue"
    );
}

#[test]
fn test_step_out_returns_to_caller() {
    let mut target = launch_fixture();
    let entry_b_range = function_range(&target, "entry_b");
    let sum_b_range = function_range(&target, "sum_b");
    run_to_entry_b(&mut target, entry_b_range.0);

    // Step into sum_b's outermost invocation (past its prologue, so its
    // frame pointer is set up) before testing step_out from inside it.
    step_in_until_in_range(&mut target, sum_b_range);

    let reason = target.step_out().expect("step_out failed");
    assert!(
        reason.is_step(),
        "step_out stopped for an unexpected reason: {:?}",
        reason.wait_status
    );
    let pc = target.process.get_pc().expect("failed to get pc");
    assert!(
        !range_contains(sum_b_range, pc),
        "step_out should have left sum_b, landed at {pc}"
    );
    assert!(
        range_contains(entry_b_range, pc),
        "step_out should have returned into entry_b, landed at {pc}"
    );
}

// --- Target::set_function_breakpoint ------------------------------------------
//
// These tests drive `Target::set_function_breakpoint` end to end: they resume
// the real inferior and check it actually traps where the breakpoint claims
// to live, rather than just inspecting the `Breakpoint`/`BreakpointSite`
// bookkeeping. Expected addresses/ranges are derived independently (straight
// from DWARF low_pc/high_pc, or from the raw ELF symbol table), never by
// re-running the same line-table-walking logic `set_function_breakpoint`
// itself uses to pick a site address.

/// Resumes the process and waits for its next stop, asserting that stop was a
/// real breakpoint trap (`SIGTRAP`), and returns the PC it landed on.
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

#[test]
fn function_breakpoint_stops_past_the_prologue() {
    let mut target = launch_fixture();
    let entry_b_range = function_range(&target, "entry_b");

    let (id, prologue_skipped) = target
        .set_function_breakpoint("entry_b")
        .expect("set_function_breakpoint should find entry_b via DWARF");
    assert!(
        prologue_skipped,
        "DWARF is present, so the prologue should be reported as skipped"
    );

    let addresses = target
        .breakpoint_addresses(id)
        .expect("breakpoint should be registered");
    assert_eq!(
        addresses.len(),
        1,
        "entry_b has exactly one definition, so the function breakpoint should plant exactly one site, got {addresses:?}"
    );
    let planted = addresses[0];
    assert!(
        range_contains(entry_b_range, planted),
        "breakpoint at {planted} lands outside entry_b's own address range {entry_b_range:?}"
    );
    assert_ne!(
        planted, entry_b_range.0,
        "function breakpoint should skip the prologue, not land on entry_b's very first instruction"
    );

    let pc = expect_breakpoint_hit(&mut target);
    assert_eq!(
        pc, planted,
        "process should have stopped exactly at the address the function breakpoint planted"
    );
    assert!(
        target
            .is_breakpoint_enabled(id)
            .expect("breakpoint should exist"),
        "a freshly-set breakpoint should be enabled by default"
    );
}

#[test]
fn function_breakpoint_fires_once_per_recursive_call_then_lets_the_process_finish() {
    let mut target = launch_fixture();
    let sum_b_range = function_range(&target, "sum_b");

    let (id, _) = target
        .set_function_breakpoint("sum_b")
        .expect("set_function_breakpoint should find sum_b via DWARF");
    let addresses = target
        .breakpoint_addresses(id)
        .expect("breakpoint should be registered");
    assert_eq!(addresses.len(), 1, "got {addresses:?}");
    let planted = addresses[0];

    // entry_b builds a 3-node list and calls `sum_b(&head)`; sum_b recurses
    // once per node (head, mid, tail) and once more on the NULL base case at
    // the end of the list, so the breakpoint should fire exactly 4 times.
    for call_number in 1..=4 {
        let pc = expect_breakpoint_hit(&mut target);
        assert_eq!(
            pc, planted,
            "call #{call_number}: breakpoint hit at an unexpected address"
        );
        assert!(
            range_contains(sum_b_range, pc),
            "call #{call_number}: PC {pc} is outside sum_b's address range {sum_b_range:?}"
        );
    }

    // Nothing else in the program should stop the process now, so it should
    // simply run to completion. If sum_b's recursion depth were miscounted
    // (e.g. the breakpoint missed the NULL base case, or fired an extra
    // time), this would instead hit the breakpoint a 5th time or hang.
    target
        .process
        .resume_process()
        .expect("failed to resume process");
    let reason = target
        .process
        .wait_on_signal(None)
        .expect("failed to wait for process");
    assert!(
        matches!(reason.wait_status, WaitStatus::Exited(_, _)),
        "expected the process to run to completion after the 4th sum_b call, got {:?}",
        reason.wait_status
    );
}

#[test]
fn function_breakpoint_falls_back_to_elf_symbol_table_without_dwarf() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let mut target =
        Target::launch(&path, None, true, None).expect("failed to launch no_debug fixture");
    assert!(
        target.state.dwarf.is_none(),
        "no_debug fixture should carry no DWARF info"
    );

    // Ground truth for where `add` should land, read straight out of the ELF
    // symbol table rather than through anything `set_function_breakpoint`
    // itself uses to compute the address.
    let add_name = CString::new("add").unwrap();
    let add_symbol = target
        .state
        .elf
        .get_symbols_with_name(&add_name)
        .into_iter()
        .next()
        .expect("no_debug fixture's .symtab should still contain `add`");
    let expected_address = FileAddress::new(&target.state.elf, add_symbol.st_value as usize)
        .to_virt_address()
        .expect("`add`'s file address should map into the running process");

    let (id, prologue_skipped) = target
        .set_function_breakpoint("add")
        .expect("set_function_breakpoint should fall back to the ELF symbol table without DWARF");
    assert!(
        !prologue_skipped,
        "without DWARF there's no prologue to skip, so this should be reported as not skipped"
    );
    let addresses = target
        .breakpoint_addresses(id)
        .expect("breakpoint should be registered");
    assert_eq!(addresses.len(), 1, "got {addresses:?}");
    assert_eq!(
        addresses[0], expected_address,
        "without DWARF there is no prologue to skip, so the breakpoint should land exactly on the symbol's address"
    );

    let pc = expect_breakpoint_hit(&mut target);
    assert_eq!(pc, expected_address);
}

#[test]
fn function_breakpoint_on_unknown_name_does_not_silently_succeed() {
    let mut target = launch_fixture();

    let result = target.set_function_breakpoint("this_function_does_not_exist_anywhere");

    // Every other by-name/by-id lookup on `Target` (remove/enable/disable/
    // breakpoint_addresses/is_breakpoint_enabled) fails loudly when the thing
    // it was asked for doesn't exist. A function name matching neither DWARF
    // nor the ELF symbol table should follow the same contract rather than
    // quietly registering a breakpoint that can never fire.
    assert!(
        result.is_err(),
        "setting a breakpoint on a nonexistent function should return an error, got {result:?}"
    );
}

#[test]
fn duplicate_function_breakpoints_on_the_same_function_are_independently_functional() {
    let mut target = launch_fixture();

    let (id1, _) = target
        .set_function_breakpoint("entry_a")
        .expect("first set_function_breakpoint failed");
    let (id2, _) = target
        .set_function_breakpoint("entry_a")
        .expect("second set_function_breakpoint failed");
    assert_ne!(id1, id2, "each call should mint a distinct breakpoint ID");

    let addresses2 = target
        .breakpoint_addresses(id2)
        .expect("second breakpoint should be registered");
    assert!(
        !addresses2.is_empty(),
        "a second function breakpoint set on the same function ended up with no backing \
         breakpoint site at all, so it can never fire, be queried, or be removed independently \
         of the first one"
    );

    // Disabling the first breakpoint on entry_a should not silently disable
    // the second, independently-requested breakpoint at the same address.
    target
        .disable_breakpoint(id1)
        .expect("failed to disable id1");
    assert!(
        target
            .is_breakpoint_enabled(id2)
            .expect("id2 should exist"),
        "id2 should still report itself enabled after only id1 was disabled"
    );

    let pc = expect_breakpoint_hit(&mut target);
    assert_eq!(
        pc, addresses2[0],
        "id2's breakpoint on entry_a should still fire even though id1 (at the same address) was disabled"
    );
}

#[test]
fn function_breakpoint_error_suggests_close_matches_on_typo() {
    let mut target = launch_fixture();

    let err = target
        .set_function_breakpoint("entri_a") // typo for `entry_a`
        .expect_err("typo'd function name should still fail to resolve");

    let message = err.to_string();
    assert!(
        message.contains("entry_a"),
        "expected a suggestion mentioning `entry_a` in the error, got: {message}"
    );
}

#[test]
fn function_breakpoint_error_has_no_suggestions_for_nonsense_name() {
    let mut target = launch_fixture();

    let err = target
        .set_function_breakpoint("this_function_does_not_exist_anywhere")
        .expect_err("nonexistent function name should fail to resolve");

    let message = err.to_string();
    assert!(
        !message.contains("Did you mean"),
        "a name with no plausible match shouldn't suggest anything, got: {message}"
    );
}

#[test]
fn all_function_names_includes_dwarf_indexed_functions() {
    let target = launch_fixture();

    let names = target.all_function_names();

    for expected in ["entry_a", "compute_a", "add_a", "entry_b", "sum_b"] {
        assert!(
            names.iter().any(|n| n == expected),
            "expected `{expected}` in all_function_names(), got {names:?}"
        );
    }
}
