#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/src/target/activation.rs")
text = path.read_text(encoding="utf-8")

old = '''fn ensure_target_not_disabled(disable_path: &Path) -> Result<()> {
    if workspace::safe_exists(disable_path)? {
        bail!("target disable receipt is visible; guided activation active result was withheld");
    }
    Ok(())
}
'''
new = '''#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisableGateTestPhase {
    BeforeObservation,
    AfterClearObservation,
}

#[cfg(test)]
std::thread_local! {
    static DISABLE_GATE_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut(DisableGateTestPhase)>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_disable_gate_test_hook(hook: Option<Box<dyn FnMut(DisableGateTestPhase)>>) {
    DISABLE_GATE_TEST_HOOK.with(|slot| {
        *slot.borrow_mut() = hook;
    });
}

#[cfg(test)]
fn invoke_disable_gate_test_hook(phase: DisableGateTestPhase) {
    DISABLE_GATE_TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(phase);
        }
    });
}

fn ensure_target_not_disabled(disable_path: &Path) -> Result<()> {
    #[cfg(test)]
    invoke_disable_gate_test_hook(DisableGateTestPhase::BeforeObservation);

    if workspace::safe_exists(disable_path)? {
        bail!("target disable receipt is visible; guided activation active result was withheld");
    }

    #[cfg(test)]
    invoke_disable_gate_test_hook(DisableGateTestPhase::AfterClearObservation);

    Ok(())
}
'''
if old not in text:
    raise SystemExit("missing activation disable gate helper anchor")
text = text.replace(old, new, 1)

insert = r'''

    fn concurrency_fixture(name: &str, completed: bool) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!(
            "nxb153-activation-disable-race-{name}-{}-{}",
            std::process::id(),
            workspace::random_hex(8).unwrap()
        ));
        workspace::initialize_value(&root, "Activation Disable Race Test").unwrap();
        let authorization = root.join("tmp").join("authorization-evidence.txt");
        std::fs::write(&authorization, b"authorized deterministic concurrency fixture\n").unwrap();
        workspace::set_private_file_permissions(&authorization).unwrap();

        let preview_sha256 = {
            let _authority = workspace::target_authority_scope();
            super::super::build_guided_setup(
                &root,
                "example-app",
                "Example App",
                "https://example.org",
                vec!["/api".to_owned()],
                vec!["/api/logout".to_owned()],
                "Example Program",
                "hackerone",
                Some("https://hackerone.com/example"),
                "hackerone/program/example#scope-2026",
                &authorization,
                "test-researcher",
                AuthorizationBasis::ProgramPolicy,
                "2099-01-01T00:00:00Z",
                "I_HAVE_EXPLICIT_AUTHORIZATION",
                false,
                1.0,
                1,
                10,
            )
            .unwrap()
            .preview
            .preview_sha256
        };

        if completed {
            let _authority = workspace::target_authority_scope();
            let value = activate_race_fixture(&root, &authorization, &preview_sha256).unwrap();
            assert_eq!(value.get("status").and_then(Value::as_str), Some("active"));
        }

        (root, authorization, preview_sha256)
    }

    fn activate_race_fixture(
        root: &Path,
        authorization: &Path,
        preview_sha256: &str,
    ) -> Result<Value> {
        activate_value(
            root,
            "example-app",
            "Example App",
            "https://example.org",
            vec!["/api".to_owned()],
            vec!["/api/logout".to_owned()],
            "Example Program",
            "hackerone",
            Some("https://hackerone.com/example"),
            "hackerone/program/example#scope-2026",
            authorization,
            "test-researcher",
            AuthorizationBasis::ProgramPolicy,
            "2099-01-01T00:00:00Z",
            "I_HAVE_EXPLICIT_AUTHORIZATION",
            false,
            1.0,
            1,
            10,
            preview_sha256,
            ACTIVATION_ACKNOWLEDGEMENT,
        )
    }

    fn run_disable_race(completed: bool, disable_before_final_observation: bool) {
        use std::sync::mpsc;
        use std::time::Duration;

        let label = match (completed, disable_before_final_observation) {
            (false, true) => "normal-disable-first",
            (false, false) => "normal-activation-first",
            (true, true) => "recovery-disable-first",
            (true, false) => "recovery-activation-first",
        };
        let (root, authorization, preview_sha256) = concurrency_fixture(label, completed);
        let root_worker = root.clone();
        let authorization_worker = authorization.clone();
        let preview_worker = preview_sha256.clone();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();

        let activation = std::thread::spawn(move || {
            let _authority = workspace::target_authority_scope();
            let mut gate_index = 0_u8;
            set_disable_gate_test_hook(Some(Box::new(move |phase| {
                if phase == DisableGateTestPhase::BeforeObservation {
                    gate_index = gate_index.saturating_add(1);
                }
                let selected_phase = if disable_before_final_observation {
                    DisableGateTestPhase::BeforeObservation
                } else {
                    DisableGateTestPhase::AfterClearObservation
                };
                if gate_index == 2 && phase == selected_phase {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            })));
            let result = activate_race_fixture(
                &root_worker,
                &authorization_worker,
                &preview_worker,
            );
            set_disable_gate_test_hook(None);
            result
        });

        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("activation did not reach deterministic final disable gate");

        {
            let _authority = workspace::target_authority_scope();
            let disabled = super::super::disable_value(
                &root,
                "example-app",
                super::super::DisableReason::OperatorHold,
            )
            .expect("concurrent disable publication failed");
            assert_eq!(disabled.get("status").and_then(Value::as_str), Some("disabled"));
        }

        resume_tx.send(()).unwrap();
        let activation_result = activation.join().expect("activation thread panicked");
        if disable_before_final_observation {
            let error = activation_result.expect_err(
                "activation must fail closed when disable publishes before final observation",
            );
            assert!(error.to_string().contains(
                "target disable receipt is visible; guided activation active result was withheld"
            ));
        } else {
            let value = activation_result.expect(
                "activation may linearize before a disable published after its clear final observation",
            );
            assert_eq!(value.get("status").and_then(Value::as_str), Some("active"));
        }

        {
            let _authority = workspace::target_authority_scope();
            let final_value = super::super::show_value(&root, "example-app").unwrap();
            assert_eq!(
                final_value.get("status").and_then(Value::as_str),
                Some("disabled")
            );
        }

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn normal_publication_withholds_active_when_disable_wins_final_gate() {
        run_disable_race(false, true);
    }

    #[test]
    fn normal_publication_linearizes_before_later_disable_and_final_state_is_disabled() {
        run_disable_race(false, false);
    }

    #[test]
    fn completed_recovery_withholds_active_when_disable_wins_final_gate() {
        run_disable_race(true, true);
    }

    #[test]
    fn completed_recovery_linearizes_before_later_disable_and_final_state_is_disabled() {
        run_disable_race(true, false);
    }
'''
anchor = "\n    #[test]\n    fn guided_path_byte_preflight_rejects_nonliteral_or_non_rfc3986_bytes()"
if "normal_publication_withholds_active_when_disable_wins_final_gate" not in text:
    if anchor not in text:
        raise SystemExit("missing activation test insertion anchor")
    text = text.replace(anchor, insert + anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
