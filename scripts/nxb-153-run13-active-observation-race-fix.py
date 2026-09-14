#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/src/target.rs")
text = path.read_text(encoding="utf-8")

old = '''fn reconcile_effective_target(
    targets: &Path,
    profile: TargetProfile,
    known_receipt: Option<DisableReceipt>,
) -> Result<EffectiveTarget> {
    let receipt = match known_receipt {
        Some(receipt) => Some(receipt),
        None => read_optional_receipt(&disable_path(targets, &profile.target_id), &profile)?,
    };
    Ok(effective_target(profile, receipt))
}
'''
new = '''#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationGateTestPhase {
    BeforeReceiptObservation,
    AfterClearReceiptObservation,
}

#[cfg(test)]
type ObservationGateTestHook = Box<dyn FnMut(ObservationGateTestPhase)>;

#[cfg(test)]
std::thread_local! {
    static OBSERVATION_GATE_TEST_HOOK: std::cell::RefCell<Option<ObservationGateTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_observation_gate_test_hook(hook: Option<ObservationGateTestHook>) {
    OBSERVATION_GATE_TEST_HOOK.with(|slot| {
        *slot.borrow_mut() = hook;
    });
}

#[cfg(test)]
fn invoke_observation_gate_test_hook(phase: ObservationGateTestPhase) {
    OBSERVATION_GATE_TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(phase);
        }
    });
}

fn reconcile_effective_target(
    targets: &Path,
    profile: TargetProfile,
    known_receipt: Option<DisableReceipt>,
) -> Result<EffectiveTarget> {
    let receipt = match known_receipt {
        Some(receipt) => Some(receipt),
        None => {
            #[cfg(test)]
            invoke_observation_gate_test_hook(ObservationGateTestPhase::BeforeReceiptObservation);

            let receipt =
                read_optional_receipt(&disable_path(targets, &profile.target_id), &profile)?;

            #[cfg(test)]
            if receipt.is_none() {
                invoke_observation_gate_test_hook(
                    ObservationGateTestPhase::AfterClearReceiptObservation,
                );
            }

            receipt
        }
    };
    Ok(effective_target(profile, receipt))
}
'''
if old not in text:
    raise SystemExit("missing active-observation reconciliation anchor")
text = text.replace(old, new, 1)

anchor = '''    #[test]
    fn creates_validates_lists_shows_and_disables_target() {
'''
insert = r'''    #[derive(Debug, Clone, Copy)]
    enum ObservationOperation {
        Create,
        List,
        Show,
        Validate,
    }

    fn run_observation_operation(
        operation: ObservationOperation,
        root: &Path,
        policy: &Path,
        authorization: &Path,
    ) -> Result<Value> {
        match operation {
            ObservationOperation::Create => create_value(
                root,
                "example-app",
                "Example App",
                "https://example.org",
                vec!["/api".into()],
                vec!["/api/logout".into()],
                "hackerone/program/example#scope-2026",
                authorization,
                policy,
            ),
            ObservationOperation::List => list_value(root, true),
            ObservationOperation::Show => show_value(root, "example-app"),
            ObservationOperation::Validate => {
                validate_value(root, "example-app", authorization, policy)
            }
        }
    }

    fn observation_status(operation: ObservationOperation, value: &Value) -> Option<&str> {
        match operation {
            ObservationOperation::List => value
                .pointer("/targets/0/status")
                .and_then(Value::as_str),
            _ => value.get("status").and_then(Value::as_str),
        }
    }

    fn run_observation_disable_race(
        operation: ObservationOperation,
        disable_before_observation: bool,
    ) {
        use std::sync::mpsc;
        use std::time::Duration;

        let fixture = Fixture::new();
        if !matches!(operation, ObservationOperation::Create) {
            let _authority = workspace::target_authority_scope();
            fixture.create();
        }

        let root = fixture.root.clone();
        let policy = fixture.policy.clone();
        let authorization = fixture.authorization.clone();
        let worker_root = root.clone();
        let worker_policy = policy.clone();
        let worker_authorization = authorization.clone();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();

        let worker = std::thread::spawn(move || {
            let _authority = workspace::target_authority_scope();
            let selected_phase = if disable_before_observation {
                ObservationGateTestPhase::BeforeReceiptObservation
            } else {
                ObservationGateTestPhase::AfterClearReceiptObservation
            };
            set_observation_gate_test_hook(Some(Box::new(move |phase| {
                if phase == selected_phase {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            })));
            let result = run_observation_operation(
                operation,
                &worker_root,
                &worker_policy,
                &worker_authorization,
            );
            set_observation_gate_test_hook(None);
            result
        });

        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("target observation did not reach deterministic final receipt gate");
        {
            let _authority = workspace::target_authority_scope();
            let disabled = disable_value(&root, "example-app", DisableReason::OperatorHold)
                .expect("concurrent target disable publication failed");
            assert_eq!(
                disabled.get("status").and_then(Value::as_str),
                Some("disabled")
            );
        }
        resume_tx.send(()).unwrap();

        let observed = worker
            .join()
            .expect("target observation worker panicked")
            .expect("target observation failed unexpectedly");
        let expected = if disable_before_observation {
            "disabled"
        } else {
            "active"
        };
        assert_eq!(observation_status(operation, &observed), Some(expected));

        {
            let _authority = workspace::target_authority_scope();
            let final_value = show_value(&root, "example-app").unwrap();
            assert_eq!(
                final_value.get("status").and_then(Value::as_str),
                Some("disabled")
            );
        }
    }

    fn run_observation_invalid_receipt_race(mismatched: bool) {
        use std::sync::mpsc;
        use std::time::Duration;

        let fixture = Fixture::new();
        {
            let _authority = workspace::target_authority_scope();
            fixture.create();
        }
        let root = fixture.root.clone();
        let worker_root = root.clone();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();

        let worker = std::thread::spawn(move || {
            let _authority = workspace::target_authority_scope();
            set_observation_gate_test_hook(Some(Box::new(move |phase| {
                if phase == ObservationGateTestPhase::BeforeReceiptObservation {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            })));
            let result = show_value(&worker_root, "example-app");
            set_observation_gate_test_hook(None);
            result
        });

        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("show did not reach deterministic final receipt gate");
        let receipt_path = root.join("targets").join("example-app.disabled.json");
        if mismatched {
            let receipt = DisableReceipt {
                receipt_version: DISABLE_RECEIPT_VERSION,
                target_id: "example-app".into(),
                profile_sha256: "0".repeat(64),
                reason: DisableReason::OperatorHold,
                disabled_at: workspace::now(),
            };
            workspace::create_document(&receipt_path, &canonical_json(&receipt).unwrap()).unwrap();
        } else {
            workspace::create_document(&receipt_path, b"{not-json}\n").unwrap();
        }
        resume_tx.send(()).unwrap();

        let error = worker
            .join()
            .expect("show invalid-receipt worker panicked")
            .expect_err("malformed or mismatched concurrent receipt must fail closed");
        let message = error.to_string();
        if mismatched {
            assert!(message.contains("target disable receipt does not match its immutable profile"));
        } else {
            assert!(message.contains("target disable receipt is invalid JSON"));
        }
    }

    #[test]
    fn create_observation_linearizes_against_disable_in_both_legal_orderings() {
        run_observation_disable_race(ObservationOperation::Create, true);
        run_observation_disable_race(ObservationOperation::Create, false);
    }

    #[test]
    fn list_observation_linearizes_against_disable_in_both_legal_orderings() {
        run_observation_disable_race(ObservationOperation::List, true);
        run_observation_disable_race(ObservationOperation::List, false);
    }

    #[test]
    fn show_observation_linearizes_against_disable_in_both_legal_orderings() {
        run_observation_disable_race(ObservationOperation::Show, true);
        run_observation_disable_race(ObservationOperation::Show, false);
    }

    #[test]
    fn validate_observation_linearizes_against_disable_in_both_legal_orderings() {
        run_observation_disable_race(ObservationOperation::Validate, true);
        run_observation_disable_race(ObservationOperation::Validate, false);
    }

    #[test]
    fn concurrent_malformed_and_mismatched_receipts_fail_closed() {
        run_observation_invalid_receipt_race(false);
        run_observation_invalid_receipt_race(true);
    }

'''
if "create_observation_linearizes_against_disable_in_both_legal_orderings" not in text:
    if anchor not in text:
        raise SystemExit("missing target test insertion anchor")
    text = text.replace(anchor, insert + anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
