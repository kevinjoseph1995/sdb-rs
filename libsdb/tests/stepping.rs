use std::path::PathBuf;
/////////////////////////////////////////
use libsdb::{
    address::VirtAddress,
    process::{StopReason, TrapType},
    register_info::{RegisterId, RegisterValue},
    target::Target,
};
use nix::sys::{signal::Signal, wait::WaitStatus};
/////////////////////////////////////////

// These tests step through the C++ `step_test_fixture` binary (see
// `tools/step_test_fixture`). `main` calls `find_happiness` twice,
// `find_happiness` calls `pet_cat`, and `pet_cat` has `scratch_ears` inlined
// into it.

fn launch_fixture() -> Target {
    let path = PathBuf::from(step_test_fixture::fixture_path());
    Target::launch(&path, None, true, None).expect("Failed to launch step_test_fixture target")
}

/// The (demangled, for C++) name of the function containing the current PC.
fn function_name(target: &Target) -> String {
    let pc = target.process.get_pc().expect("failed to get pc");
    target
        .function_signature_at(pc)
        .expect("no function symbol at pc")
}

/// Launches the fixture and runs it to the breakpoint on `main`.
fn launch_at_main() -> Target {
    let mut target = launch_fixture();
    target
        .set_function_breakpoint("main")
        .expect("failed to set breakpoint on main");
    target
        .process
        .resume_process()
        .expect("failed to resume process");
    target
        .process
        .wait_on_signal(None)
        .expect("failed to wait for process");
    assert_eq!(function_name(&target), "main");
    target
}

#[test]
fn step_over_stays_in_the_calling_function() {
    let mut target = launch_at_main();
    let pc = target.process.get_pc().unwrap();
    target.step_over().expect("step_over failed");
    // Stepping over the `find_happiness()` call on line 18 lands on line 19.
    assert_ne!(target.process.get_pc().unwrap(), pc);
    assert_eq!(function_name(&target), "main");
}

#[test]
fn step_in_enters_a_function_past_its_prologue() {
    let mut target = launch_at_main();
    target.step_over().expect("step_over failed");
    target.step_in().expect("step_in failed");
    assert_eq!(function_name(&target), "find_happiness()");
    assert_eq!(target.state.stack.get_inline_height(), 0);
}

#[test]
fn step_in_walks_into_an_inlined_function_without_moving_the_pc() {
    let mut target = launch_at_main();
    target.step_in().expect("step_in into find_happiness failed");
    target.step_in().expect("step_in into pet_cat failed");
    // `scratch_ears` begins at the first instruction past `pet_cat`'s prologue,
    // so the PC sits on the start of the inlined frame, one level deep.
    assert_eq!(function_name(&target), "pet_cat()");
    assert_eq!(target.state.stack.get_inline_height(), 1);

    let pc = target.process.get_pc().unwrap();
    target.step_in().expect("step_in into scratch_ears failed");
    assert_eq!(target.process.get_pc().unwrap(), pc);
    assert_eq!(target.state.stack.get_inline_height(), 0);
}

#[test]
fn step_out_leaves_the_inlined_function_then_each_caller() {
    let mut target = launch_at_main();
    target.step_in().expect("step_in into find_happiness failed");
    target.step_in().expect("step_in into pet_cat failed");
    target.step_in().expect("step_in into scratch_ears failed");
    let pc = target.process.get_pc().unwrap();

    // Out of the inlined `scratch_ears`: still inside `pet_cat`, further on.
    target.step_out().expect("step_out of scratch_ears failed");
    assert_ne!(target.process.get_pc().unwrap(), pc);
    assert_eq!(function_name(&target), "pet_cat()");

    // Out of `pet_cat`: back in `find_happiness`.
    target.step_out().expect("step_out of pet_cat failed");
    assert_eq!(function_name(&target), "find_happiness()");

    // Out of `find_happiness`: back in `main`.
    target.step_out().expect("step_out of find_happiness failed");
    assert_eq!(function_name(&target), "main");
}

// ---------------------------------------------------------------------------
// Corner cases
// ---------------------------------------------------------------------------

/// The source line covering the current PC.
fn current_line(target: &Target) -> usize {
    target
        .line_entry_at_pc()
        .expect("failed to read the line table")
        .expect("no line entry at pc")
        .line() as usize
}

/// How many entries the inline stack has at the current PC: the real function
/// plus each inlined function containing the PC.
fn inline_stack_len(target: &Target) -> usize {
    target
        .state
        .stack
        .inline_stack_at_pc(&target.state, &target.process)
        .expect("failed to build the inline stack")
        .len()
}

fn rbp(target: &Target) -> u64 {
    match target
        .process
        .get_registers()
        .get_register_value(RegisterId::rbp)
        .expect("failed to read rbp")
    {
        RegisterValue::U64(value) => value,
        other => panic!("unexpected rbp value {other:?}"),
    }
}

/// Resumes and waits, asserting the stop was a breakpoint trap.
fn resume_to_breakpoint(target: &mut Target) -> StopReason {
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
        "expected a breakpoint stop, got {:?}",
        reason.wait_status
    );
    reason
}

/// Launches the fixture and runs it to the first instruction past the
/// prologue of `function`.
fn launch_at(function: &str) -> Target {
    let mut target = launch_fixture();
    target
        .set_function_breakpoint(function)
        .unwrap_or_else(|e| panic!("failed to set breakpoint on {function}: {e}"));
    resume_to_breakpoint(&mut target);
    target
}

fn line_of(marker: &str) -> usize {
    step_test_fixture::marked_line(marker)
}

/// Step over until the current line is `marker`'s line, at most `max` times.
fn step_over_until_line(target: &mut Target, marker: &str, max: usize) {
    let wanted = line_of(marker);
    for _ in 0..max {
        if current_line(target) == wanted {
            return;
        }
        target.step_over().expect("step_over failed");
    }
    assert_eq!(current_line(target), wanted, "never reached {marker}");
}

#[test]
fn step_over_inlined_function_at_depth_three_skips_all_of_it() {
    let mut target = launch_at("nested_inline_scenario");
    // `outer`, `middle` and `inner` all begin at this address.
    assert_eq!(target.state.stack.get_inline_height(), 3);
    assert_eq!(inline_stack_len(&target), 4);

    target.step_over().expect("step_over failed");
    assert_eq!(function_name(&target), "nested_inline_scenario()");
    assert_eq!(inline_stack_len(&target), 1);
    assert_eq!(current_line(&target), line_of("nested_after"));
}

#[test]
fn step_in_peels_one_inline_level_at_a_time() {
    let mut target = launch_at("nested_inline_scenario");
    let pc = target.process.get_pc().unwrap();
    for expected_height in [2, 1, 0] {
        target.step_in().expect("step_in failed");
        assert_eq!(target.state.stack.get_inline_height(), expected_height);
        assert_eq!(target.process.get_pc().unwrap(), pc);
    }
}

#[test]
fn step_out_peels_one_inline_frame_at_a_time() {
    let mut target = launch_at("nested_inline_scenario");
    for _ in 0..3 {
        target.step_in().expect("step_in failed");
    }
    // Innermost: `inner` -> `middle` -> `outer` -> the real function.
    for expected_len in [3, 2, 1] {
        target.step_out().expect("step_out failed");
        assert_eq!(inline_stack_len(&target), expected_len);
        assert_eq!(function_name(&target), "nested_inline_scenario()");
    }
    assert_eq!(current_line(&target), line_of("nested_after"));
}

#[test]
fn step_out_at_the_outermost_virtual_frame_leaves_the_real_function() {
    let mut target = launch_at("nested_inline_scenario");
    // Height 3 means the inlined calls have not been entered yet, so the
    // virtual frame is `nested_inline_scenario` itself.
    target.step_out().expect("step_out failed");
    assert_eq!(function_name(&target), "main");
}

#[test]
fn step_over_walks_across_two_consecutive_inlined_calls() {
    let mut target = launch_at("inline_twice_scenario");
    assert_eq!(target.state.stack.get_inline_height(), 1);
    let first_pc = target.process.get_pc().unwrap();

    // Skipping the first copy lands on the start of the second copy.
    target.step_over().expect("step_over failed");
    assert_ne!(target.process.get_pc().unwrap(), first_pc);
    assert_eq!(target.state.stack.get_inline_height(), 1);
    assert_eq!(function_name(&target), "inline_twice_scenario()");

    // Skipping the second copy lands on the code after both.
    target.step_over().expect("step_over failed");
    assert_eq!(target.state.stack.get_inline_height(), 0);
    assert_eq!(current_line(&target), line_of("inline_twice_after"));
}

#[test]
fn step_in_through_an_inlined_function_reaches_its_callee() {
    let mut target = launch_at("inline_with_call_scenario");
    assert_eq!(target.state.stack.get_inline_height(), 1);

    target.step_in().expect("step_in into the inline frame failed");
    assert_eq!(target.state.stack.get_inline_height(), 0);

    target.step_in().expect("step_in into leaf failed");
    assert_eq!(function_name(&target), "leaf()");
    assert_eq!(current_line(&target), line_of("leaf_body"));

    // Returning lands back in the scenario function, inside the inlined body.
    target.step_out().expect("step_out of leaf failed");
    assert_eq!(function_name(&target), "inline_with_call_scenario()");
}

#[test]
fn step_over_a_loop_revisits_the_body_then_exits() {
    let mut target = launch_at("loop_scenario");
    let body = line_of("loop_body");
    let after = line_of("loop_after");

    let mut body_visits = 0;
    for _ in 0..50 {
        if current_line(&target) == body {
            body_visits += 1;
        }
        if current_line(&target) == after {
            break;
        }
        target.step_over().expect("step_over failed");
    }
    assert_eq!(current_line(&target), after, "loop never finished");
    assert_eq!(body_visits, 3);
    assert_eq!(function_name(&target), "loop_scenario()");
}

#[test]
#[ignore = "bug: step_over stops at the shared return site in a deeper recursive frame"]
fn step_over_a_call_that_returns_to_a_shared_address_in_a_recursive_function() {
    let mut target = launch_at("recurse");
    // First hit is `recurse(2)`; stepping over the recursive call must not
    // stop in a deeper frame that returns to the same address.
    let frame = rbp(&target);
    step_over_until_line(&mut target, "recurse_call", 3);
    target.step_over().expect("step_over failed");
    assert_eq!(rbp(&target), frame, "stopped in a different frame");
    assert_eq!(function_name(&target), "recurse(int)");
}

#[test]
#[ignore = "bug: step_out stops at the shared return address in a deeper recursive frame"]
fn step_out_of_a_recursive_call_returns_to_the_immediate_caller() {
    let mut target = launch_at("recurse");
    // `recurse(2)`, called from `recursion_scenario`.
    target.step_out().expect("step_out failed");
    assert_eq!(function_name(&target), "recursion_scenario()");
}

#[test]
fn step_over_two_calls_on_one_line_reaches_the_next_line() {
    let mut target = launch_at("two_calls_scenario");
    // The line has two line-table rows; allow one stop between the two calls.
    step_over_until_line(&mut target, "two_calls_after", 2);
    assert_eq!(function_name(&target), "two_calls_scenario()");
}

#[test]
fn step_over_skips_the_untaken_branch() {
    let mut target = launch_at("clamp");
    assert_eq!(current_line(&target), line_of("clamp_if"));
    target.step_over().expect("step_over failed");
    assert_eq!(current_line(&target), line_of("clamp_return_x"));
    target.step_over().expect("step_over failed");
    assert_eq!(current_line(&target), line_of("clamp_end"));
}

#[test]
fn step_over_an_indirect_call_does_not_enter_the_callee() {
    let mut target = launch_at("function_pointer_scenario");
    step_over_until_line(&mut target, "fp_call", 2);
    target.step_over().expect("step_over failed");
    assert_eq!(current_line(&target), line_of("fp_after"));
    assert_eq!(function_name(&target), "function_pointer_scenario()");
}

#[test]
fn step_in_follows_an_indirect_call() {
    let mut target = launch_at("function_pointer_scenario");
    step_over_until_line(&mut target, "fp_call", 2);
    target.step_in().expect("step_in failed");
    assert_eq!(function_name(&target), "leaf()");
}

#[test]
fn step_in_follows_a_virtual_call_to_the_override() {
    let mut target = launch_at("virtual_scenario");
    step_over_until_line(&mut target, "virtual_call", 4);
    target.step_in().expect("step_in failed");
    assert_eq!(function_name(&target), "Derived::speak()");
    assert_eq!(current_line(&target), line_of("derived_speak"));
}

#[test]
fn step_in_to_a_single_line_empty_function_skips_the_prologue() {
    let mut target = launch_at("empty_scenario");
    let call_site_pc = target.process.get_pc().unwrap();
    target.step_in().expect("step_in failed");
    assert_eq!(function_name(&target), "empty()");
    assert_ne!(target.process.get_pc().unwrap(), call_site_pc);
    assert_eq!(current_line(&target), line_of("empty"));

    target.step_out().expect("step_out failed");
    assert_eq!(function_name(&target), "empty_scenario()");
}

#[test]
fn step_over_a_call_into_code_without_debug_info() {
    let mut target = launch_at("libc_scenario");
    assert_eq!(current_line(&target), line_of("libc_call"));
    target.step_over().expect("step_over failed");
    assert_eq!(current_line(&target), line_of("libc_after"));
}

#[test]
#[ignore = "bug: step_in strands the PC in puts@plt, which has no symbol or line info"]
fn step_in_on_a_line_that_only_calls_code_without_debug_info_stays_in_source() {
    let mut target = launch_at("libc_scenario");
    target.step_in().expect("step_in failed");
    // `puts` has no line info, so the debugger should not strand us in it.
    assert_eq!(function_name(&target), "libc_scenario()");
    assert_eq!(current_line(&target), line_of("libc_after"));
}

#[test]
fn step_over_stops_at_a_breakpoint_in_the_callee() {
    let mut target = launch_at("breakpoint_in_callee_scenario");
    target
        .set_function_breakpoint("leaf")
        .expect("failed to set breakpoint on leaf");

    let reason = target.step_over().expect("step_over failed");
    assert_eq!(reason.trap_type, Some(TrapType::SoftwareBreakpoint));
    assert_eq!(function_name(&target), "leaf()");
}

#[test]
fn step_over_onto_a_breakpoint_does_not_report_it_twice() {
    let mut target = launch_at("breakpoint_in_callee_scenario");
    let after = line_of("bp_callee_after");
    target
        .set_line_breakpoint(&PathBuf::from(step_test_fixture::source_path()), after)
        .expect("failed to set line breakpoint");

    step_over_until_line(&mut target, "bp_callee_after", 2);
    // Continuing must not re-trigger the breakpoint we are standing on, and
    // nothing else is set, so the program should run to completion.
    target.process.resume_process().expect("failed to resume");
    let reason = target
        .process
        .wait_on_signal(None)
        .expect("failed to wait for process");
    assert!(
        matches!(reason.wait_status, WaitStatus::Exited(_, 0)),
        "expected a clean exit, got {:?}",
        reason.wait_status
    );
}

#[test]
#[ignore = "bug: step_out reads rbp before the prologue has set it up, so it returns to the caller's caller"]
fn step_out_at_a_function_entry_returns_to_the_caller() {
    let mut target = launch_at("breakpoint_in_callee_scenario");
    // Break on `leaf`'s very first instruction, before `push rbp`, so rbp is
    // still the caller's.
    let leaf = step_test_fixture_function_entry(&target, "leaf");
    target
        .set_address_breakpoint(leaf, false)
        .expect("failed to set address breakpoint");
    resume_to_breakpoint(&mut target);
    assert_eq!(target.process.get_pc().unwrap(), leaf);

    target.step_out().expect("step_out failed");
    assert_eq!(function_name(&target), "breakpoint_in_callee_scenario()");
}

#[test]
#[ignore = "bug: notify_stop errors when a step lands outside the main executable (libc)"]
fn stepping_off_the_end_of_main_leaves_the_program() {
    let mut target = launch_at("empty_scenario");
    step_over_until_line(&mut target, "empty_after", 3);
    // Return from `empty_scenario`, then walk off the end of `main`.
    target.step_out().expect("step_out failed");
    assert_eq!(function_name(&target), "main");
    step_over_until_line(&mut target, "main_end", 4);
    let reason = target.step_over().expect("step_over off main failed");
    assert!(matches!(
        reason.wait_status,
        WaitStatus::Stopped(_, Signal::SIGTRAP)
    ));
    // We are now in libc, outside the main executable.
    assert!(
        target
            .line_entry_at_pc()
            .expect("line lookup failed")
            .is_none()
    );

    target.process.resume_process().expect("failed to resume");
    let reason = target
        .process
        .wait_on_signal(None)
        .expect("failed to wait for process");
    assert!(matches!(reason.wait_status, WaitStatus::Exited(_, 0)));
}

#[test]
fn step_over_through_the_whole_program_terminates() {
    let mut target = launch_at("main");
    for _ in 0..10_000 {
        match target.step_over() {
            Ok(reason) if matches!(reason.wait_status, WaitStatus::Stopped(..)) => {}
            // Exited, or an error from stepping outside the executable.
            _ => return,
        }
    }
    panic!("step_over never left the program");
}

/// The address of the first instruction of `name`, before any prologue skip.
fn step_test_fixture_function_entry(target: &Target, name: &str) -> VirtAddress {
    target
        .state
        .dwarf
        .as_ref()
        .expect("fixture binary should carry DWARF info")
        .find_functions(name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no DWARF function named {name}"))
        .low_pc()
        .expect("missing low_pc")
        .to_virt_address()
        .expect("low_pc not mapped")
}
