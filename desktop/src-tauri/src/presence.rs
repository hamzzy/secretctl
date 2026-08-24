//! User-presence verification via the macOS LocalAuthentication framework.
//!
//! Presence is a real check or it is nothing. This module either obtains a
//! genuine Touch ID / password confirmation from the system, or it returns an
//! error — it never reports `false` in a way that could be read as "checked and
//! absent", and it never reports `true` without a system-verified result.
//!
//! The daemon does not trust this outcome on its own account: `approval.decide`
//! and `grant.create` both re-check the presence requirement against the policy
//! decision they hold. This is the human ceremony, not the enforcement point.

use crate::commands::CommandError;
use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};

/// Ask the system to confirm the user is present.
///
/// `purpose` completes the sentence macOS shows in the system prompt, so it
/// must describe the authority being granted rather than the mechanism.
pub async fn verify(purpose: &str) -> Result<bool, CommandError> {
    let reason = format!("secretctl needs to confirm it is you to {purpose}.");
    let (sender, receiver) = tokio::sync::oneshot::channel();

    // LocalAuthentication must be driven from the main thread: it presents UI.
    let dispatch = std::thread::spawn(move || {
        let result = evaluate(&reason);
        let _ = sender.send(result);
    });

    let outcome = receiver.await.map_err(|_| CommandError {
        message: "Presence verification did not complete.".to_string(),
        code: None,
        disconnected: false,
    })?;
    let _ = dispatch.join();
    outcome
}

fn evaluate(reason: &str) -> Result<bool, CommandError> {
    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthentication;

    // Refuse rather than silently degrade when the machine cannot verify
    // presence at all: the caller's decision depends on a real answer.
    if let Err(error) = unsafe { context.canEvaluatePolicy_error(policy) } {
        tracing::warn!(%error, "LocalAuthentication cannot evaluate the presence policy");
        return Err(CommandError {
            message: "This Mac cannot verify user presence, so authority that requires it cannot be granted here.".to_string(),
            code: None,
            disconnected: false,
        });
    }

    let localized = NSString::from_str(reason);
    let flag = std::sync::Arc::new(std::sync::Mutex::new(None::<bool>));
    let condition = std::sync::Arc::new(std::sync::Condvar::new());
    let (flag_for_block, condition_for_block) = (flag.clone(), condition.clone());

    let block = block2::RcBlock::new(move |success: objc2::runtime::Bool, _error: *mut objc2_foundation::NSError| {
        *flag_for_block.lock().unwrap() = Some(success.as_bool());
        condition_for_block.notify_all();
    });

    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &localized, &block);
    }

    let mut guard = flag.lock().unwrap();
    while guard.is_none() {
        let (next, timeout) = condition
            .wait_timeout(guard, std::time::Duration::from_secs(120))
            .unwrap();
        guard = next;
        if timeout.timed_out() && guard.is_none() {
            return Err(CommandError {
                message: "Presence verification timed out.".to_string(),
                code: None,
                disconnected: false,
            });
        }
    }

    match *guard {
        Some(true) => Ok(true),
        // A refused or failed prompt is a decision, not an error: report it as
        // "not present" so the caller stops rather than retries.
        Some(false) => Err(CommandError {
            message: "Presence was not confirmed, so nothing was authorized.".to_string(),
            code: None,
            disconnected: false,
        }),
        None => unreachable!("loop exits only once a result is recorded"),
    }
}
