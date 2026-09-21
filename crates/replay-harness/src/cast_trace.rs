//! Faithful call traces without a paid trace API.
//!
//! `debug_traceTransaction` / `trace_transaction` are gated behind paid
//! plans at most RPC providers. `cast run <tx>` (Foundry) instead
//! re-executes the transaction locally, at its true position in its
//! block (earlier same-block transactions are applied first), using only
//! ordinary state-read RPC calls that free tiers allow, and can emit the
//! resulting call tree as JSON. This module converts that JSON into
//! `tripwire-core` call frames.
//!
//! Note the deliberate contrast with resending a transaction's calldata
//! from an impersonated account on a fork: that skips same-block state
//! and produced a reverted, unfaithful trace for the Beanstalk exploit.

use std::process::Command;
use std::str::FromStr;

use serde_json::Value;
use thiserror::Error;
use tripwire_core::{Address, CallFrame};

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("`cast` is not available on PATH (install Foundry via foundryup)")]
    CastMissing,
    #[error("`cast run` failed: {0}")]
    CastFailed(String),
    #[error("malformed cast trace JSON: {0}")]
    Malformed(String),
}

/// True if a `cast` binary can be executed.
pub fn cast_available() -> bool {
    Command::new("cast")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Re-executes `tx_hash` via `cast run` and returns its decoded call
/// frames in execution (pre-order) order.
pub fn fetch_frames(tx_hash: &str, rpc_url: &str) -> Result<Vec<CallFrame>, TraceError> {
    let out = Command::new("cast")
        .args(["run", tx_hash, "--rpc-url", rpc_url, "--json"])
        .output()
        .map_err(|_| TraceError::CastMissing)?;
    if !out.status.success() {
        // stderr is scrubbed of the RPC URL: it embeds the provider API key.
        let stderr = String::from_utf8_lossy(&out.stderr).replace(rpc_url, "<rpc-url>");
        return Err(TraceError::CastFailed(stderr.trim().to_string()));
    }
    frames_from_cast_json(&String::from_utf8_lossy(&out.stdout))
}

/// Converts `cast run --json` output into call frames.
///
/// The JSON is `{"arena": [node, ...]}` where each node carries
/// `parent`, `children` (indices into `arena`) and a `trace` object with
/// `kind`, `depth`, `caller`, `address`, `data` and a hex `value`. Frames
/// are emitted by walking `children` from the single root, so ordering
/// doesn't depend on how the arena happens to be laid out.
pub fn frames_from_cast_json(json: &str) -> Result<Vec<CallFrame>, TraceError> {
    let doc: Value =
        serde_json::from_str(json).map_err(|e| TraceError::Malformed(e.to_string()))?;
    let arena = doc
        .get("arena")
        .and_then(Value::as_array)
        .ok_or_else(|| TraceError::Malformed("missing `arena` array".into()))?;

    let roots: Vec<usize> = arena
        .iter()
        .enumerate()
        .filter(|(_, n)| n.get("parent").map(Value::is_null).unwrap_or(false))
        .map(|(i, _)| i)
        .collect();
    let [root] = roots.as_slice() else {
        return Err(TraceError::Malformed(format!(
            "expected exactly one root node, found {}",
            roots.len()
        )));
    };

    let mut frames = Vec::with_capacity(arena.len());
    let mut stack = vec![*root];
    while let Some(idx) = stack.pop() {
        let node = arena
            .get(idx)
            .ok_or_else(|| TraceError::Malformed(format!("child index {idx} out of range")))?;
        frames.push(frame_from_node(node)?);
        let children = node
            .get("children")
            .and_then(Value::as_array)
            .ok_or_else(|| TraceError::Malformed("node missing `children`".into()))?;
        // Reverse so the first child is popped (visited) first.
        for c in children.iter().rev() {
            let ci = c
                .as_u64()
                .ok_or_else(|| TraceError::Malformed("non-integer child index".into()))?
                as usize;
            stack.push(ci);
        }
    }
    Ok(frames)
}

fn frame_from_node(node: &Value) -> Result<CallFrame, TraceError> {
    let t = node
        .get("trace")
        .ok_or_else(|| TraceError::Malformed("node missing `trace`".into()))?;
    let text = |k: &str| -> Result<&str, TraceError> {
        t.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| TraceError::Malformed(format!("trace missing string `{k}`")))
    };
    let addr = |k: &str| -> Result<Address, TraceError> {
        Address::from_str(text(k)?)
            .map_err(|e| TraceError::Malformed(format!("bad address in `{k}`: {e}")))
    };

    let depth =
        t.get("depth")
            .and_then(Value::as_u64)
            .ok_or_else(|| TraceError::Malformed("trace missing `depth`".into()))? as u32;
    let kind = text("kind")?;
    let data = t.get("data").and_then(Value::as_str).unwrap_or("");

    // Only message calls carry a function selector; for CREATE the data
    // is initcode, whose first 4 bytes are meaningless as a selector.
    let is_message_call = matches!(kind, "CALL" | "STATICCALL" | "DELEGATECALL" | "CALLCODE");
    let selector = (is_message_call && data.len() >= 10).then(|| data[..10].to_ascii_lowercase());

    // A value too large for u128 (>3.4e20 ETH) cannot occur on mainnet.
    let value_wei = u128::from_str_radix(text("value")?.trim_start_matches("0x"), 16).unwrap_or(0);

    Ok(CallFrame {
        depth,
        from: addr("caller")?,
        to: addr("address")?,
        selector,
        value_wei,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0x0000000000000000000000000000000000000001";
    const B: &str = "0x0000000000000000000000000000000000000002";
    const C: &str = "0x0000000000000000000000000000000000000003";

    fn node(
        parent: &str,
        children: &str,
        kind: &str,
        depth: u32,
        data: &str,
        value: &str,
    ) -> String {
        format!(
            r#"{{"parent":{parent},"children":{children},"trace":{{"kind":"{kind}","depth":{depth},"caller":"{A}","address":"{B}","data":"{data}","value":"{value}"}}}}"#
        )
    }

    fn doc(nodes: &[String]) -> String {
        format!(r#"{{"arena":[{}]}}"#, nodes.join(","))
    }

    #[test]
    fn walks_children_in_execution_order_not_arena_order() {
        // Arena order is deliberately NOT execution order: root's children
        // are [2, 1], so node 2 must be visited before node 1.
        let json = doc(&[
            node("null", "[2,1]", "CREATE", 0, "0x60806040", "0x0"),
            node("0", "[]", "CALL", 1, "0xaaaaaaaa00", "0x0"),
            node("0", "[]", "CALL", 1, "0xbbbbbbbb00", "0x0"),
        ]);
        let frames = frames_from_cast_json(&json).unwrap();
        let sels: Vec<_> = frames.iter().map(|f| f.selector.clone()).collect();
        assert_eq!(
            sels,
            vec![None, Some("0xbbbbbbbb".into()), Some("0xaaaaaaaa".into())]
        );
    }

    #[test]
    fn create_frames_have_no_selector_but_calls_do() {
        let json = doc(&[
            node("null", "[1,2,3]", "CREATE", 0, "0x6080604052", "0x0"),
            node("0", "[]", "CALL", 1, "0xa9059cbb0000", "0x0"),
            node("0", "[]", "STATICCALL", 1, "0x70a082310000", "0x0"),
            node("0", "[]", "DELEGATECALL", 1, "0xdd62ed3e0000", "0x0"),
        ]);
        let f = frames_from_cast_json(&json).unwrap();
        assert_eq!(f[0].selector, None);
        assert_eq!(f[1].selector.as_deref(), Some("0xa9059cbb"));
        assert_eq!(f[2].selector.as_deref(), Some("0x70a08231"));
        assert_eq!(f[3].selector.as_deref(), Some("0xdd62ed3e"));
    }

    #[test]
    fn empty_or_short_calldata_yields_no_selector() {
        let json = doc(&[
            node("null", "[1]", "CALL", 0, "0x", "0x0"),
            node("0", "[]", "CALL", 1, "0xab", "0x0"),
        ]);
        let f = frames_from_cast_json(&json).unwrap();
        assert!(f.iter().all(|x| x.selector.is_none()));
    }

    #[test]
    fn preserves_depth_and_parses_hex_value() {
        let json = doc(&[
            node("null", "[1]", "CALL", 0, "0x", "0x0"),
            node("0", "[]", "CALL", 1, "0x", "0xde0b6b3a7640000"),
        ]);
        let f = frames_from_cast_json(&json).unwrap();
        assert_eq!(f[1].depth, 1);
        assert_eq!(f[1].value_wei, 1_000_000_000_000_000_000);
    }

    #[test]
    fn selectors_are_lowercased() {
        let json = doc(&[node("null", "[]", "CALL", 0, "0xABCDEF1200", "0x0")]);
        assert_eq!(
            frames_from_cast_json(&json).unwrap()[0].selector.as_deref(),
            Some("0xabcdef12")
        );
    }

    #[test]
    fn rejects_malformed_inputs() {
        assert!(frames_from_cast_json("not json").is_err());
        assert!(frames_from_cast_json(r#"{"nope":[]}"#).is_err());
        // no root
        assert!(frames_from_cast_json(&doc(&[node("0", "[]", "CALL", 0, "0x", "0x0")])).is_err());
        // two roots
        let two = doc(&[
            node("null", "[]", "CALL", 0, "0x", "0x0"),
            node("null", "[]", "CALL", 0, "0x", "0x0"),
        ]);
        assert!(frames_from_cast_json(&two).is_err());
        // child index out of range
        assert!(
            frames_from_cast_json(&doc(&[node("null", "[9]", "CALL", 0, "0x", "0x0")])).is_err()
        );
        // bad address
        let bad = format!(
            r#"{{"arena":[{{"parent":null,"children":[],"trace":{{"kind":"CALL","depth":0,"caller":"zz","address":"{C}","data":"0x","value":"0x0"}}}}]}}"#
        );
        assert!(frames_from_cast_json(&bad).is_err());
    }
}
