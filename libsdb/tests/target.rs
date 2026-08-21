/////////////////////////////////////////
use std::path::PathBuf;
/////////////////////////////////////////
use nix::sys::{signal::Signal, wait::WaitStatus};
/////////////////////////////////////////
use libsdb::{address::VirtAddress, target::Target};
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
