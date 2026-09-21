//! Engine state-machine tests on an in-memory chain that can reorg, fail
//! RPC calls, and change underneath a read — none of which can be forced on
//! a real chain. Real-chain behaviour (real contracts, a real reorg) is
//! covered separately by `tests/engine_anvil.rs`.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tripwire_core::{CallFrame, CallKind, Condition, ConditionKind, LogEvent, SignatureCategory};

use super::*;

const TARGET: &str = "0x00000000000000000000000000000000000000aa";
const ATTACKER: &str = "0x00000000000000000000000000000000000000bb";
const OTHER: &str = "0x00000000000000000000000000000000000000cc";
const TOKEN: &str = "0x00000000000000000000000000000000000000dd";
const EXPLOIT: &str = "0xdeadbeef";
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

fn addr(s: &str) -> Address {
    Address::from_str(s).unwrap()
}

fn pad(a: &str) -> String {
    format!("0x{:0>64}", a.trim_start_matches("0x"))
}

// ---------------------------------------------------------------- fake chain

struct ChainState {
    blocks: Vec<BlockHeader>,
    events: Vec<Vec<TxEvent>>,
    nonce: u64,
    fail_events: u32,
    /// Applied right after the next `get_block_tx_events` returns: models a
    /// reorg landing in the middle of the engine's read of a block.
    reorg_after_next_events: Option<(u64, Vec<Vec<TxEvent>>)>,
}

#[derive(Clone)]
struct FakeChain(Arc<Mutex<ChainState>>);

impl FakeChain {
    fn new() -> Self {
        let genesis = BlockHeader {
            number: 0,
            hash: "0xblk0".into(),
            parent_hash: "0x00".into(),
        };
        Self(Arc::new(Mutex::new(ChainState {
            blocks: vec![genesis],
            events: vec![vec![]],
            nonce: 0,
            fail_events: 0,
            reorg_after_next_events: None,
        })))
    }

    fn mine(&self, events: Vec<TxEvent>) {
        let mut s = self.0.lock().unwrap();
        Self::push(&mut s, events);
    }

    fn push(s: &mut ChainState, events: Vec<TxEvent>) {
        s.nonce += 1;
        let parent = s.blocks.last().unwrap().hash.clone();
        let number = s.blocks.len() as u64;
        s.blocks.push(BlockHeader {
            number,
            hash: format!("0xblk{number}_{}", s.nonce),
            parent_hash: parent,
        });
        s.events.push(events);
    }

    /// Replace every block from `from` onward with `new_blocks`.
    fn reorg(&self, from: u64, new_blocks: Vec<Vec<TxEvent>>) {
        let mut s = self.0.lock().unwrap();
        Self::apply_reorg(&mut s, from, new_blocks);
    }

    fn apply_reorg(s: &mut ChainState, from: u64, new_blocks: Vec<Vec<TxEvent>>) {
        s.blocks.truncate(from as usize);
        s.events.truncate(from as usize);
        for ev in new_blocks {
            Self::push(s, ev);
        }
    }

    fn head(&self) -> u64 {
        self.0.lock().unwrap().blocks.len() as u64 - 1
    }
}

#[async_trait]
impl ChainAdapter for FakeChain {
    fn chain_id(&self) -> ChainId {
        ChainId(31337)
    }

    async fn latest_block_number(&self) -> Result<u64, ChainAdapterError> {
        Ok(self.head())
    }

    async fn block_header(&self, n: u64) -> Result<BlockHeader, ChainAdapterError> {
        self.0
            .lock()
            .unwrap()
            .blocks
            .get(n as usize)
            .cloned()
            .ok_or(ChainAdapterError::BlockNotFound(n))
    }

    async fn get_block_tx_events(&self, n: u64) -> Result<Vec<TxEvent>, ChainAdapterError> {
        let mut s = self.0.lock().unwrap();
        if s.fail_events > 0 {
            s.fail_events -= 1;
            return Err(ChainAdapterError::Transport("injected RPC failure".into()));
        }
        let ev = s
            .events
            .get(n as usize)
            .cloned()
            .ok_or(ChainAdapterError::BlockNotFound(n))?;
        if let Some((from, blocks)) = s.reorg_after_next_events.take() {
            FakeChain::apply_reorg(&mut s, from, blocks);
        }
        Ok(ev)
    }
}

// --------------------------------------------------------------- fake pauser

#[derive(Default)]
struct PauserState {
    paused: bool,
    submitted: Vec<String>,
    fail_submits: u32,
    is_paused_errors: bool,
}

#[derive(Clone, Default)]
struct FakePauser(Arc<Mutex<PauserState>>);

impl FakePauser {
    fn submitted(&self) -> usize {
        self.0.lock().unwrap().submitted.len()
    }
}

#[async_trait]
impl Pauser for FakePauser {
    async fn is_paused(&self, _t: &Address) -> Result<bool, PauseError> {
        let s = self.0.lock().unwrap();
        if s.is_paused_errors {
            return Err(PauseError("injected read failure".into()));
        }
        Ok(s.paused)
    }

    async fn submit_pause(&self, _d: &PauseDecision) -> Result<String, PauseError> {
        let mut s = self.0.lock().unwrap();
        if s.fail_submits > 0 {
            s.fail_submits -= 1;
            return Err(PauseError("injected submit failure".into()));
        }
        s.paused = true;
        let h = format!("0xpause{}", s.submitted.len() + 1);
        s.submitted.push(h.clone());
        Ok(h)
    }
}

// ------------------------------------------------------------------- fixtures

fn signature() -> Signature {
    Signature {
        id: "exploit".into(),
        description: "the exploit selector".into(),
        category: SignatureCategory::FlashLoanDrain,
        window_seconds: 60,
        conditions: vec![Condition {
            id: "sel".into(),
            kind: ConditionKind::CallSequence {
                selectors: vec![EXPLOIT.into()],
            },
            weight: 100.0,
        }],
    }
}

fn frame(selector: &str) -> CallFrame {
    CallFrame {
        depth: 0,
        from: Address::ZERO,
        to: addr(ATTACKER),
        selector: Some(selector.into()),
        value_wei: 0,
        kind: CallKind::Call,
    }
}

fn tx(hash: &str, to: &str, frames: Vec<CallFrame>, logs: Vec<LogEvent>) -> TxEvent {
    TxEvent {
        chain: ChainId(31337),
        tx_hash: hash.into(),
        block_number: 0,
        confirmations: 0,
        from: Address::ZERO,
        to: Some(addr(to)),
        value_wei: 0,
        logs,
        call_frames: frames,
        timestamp_unix: 0,
    }
}

/// An exploit that never addresses the target directly (like the real
/// Beanstalk/Euler transactions): sent to an attacker contract, visible to
/// the target only through an ERC-20 `Transfer` topic naming it.
fn attack(hash: &str) -> TxEvent {
    tx(
        hash,
        ATTACKER,
        vec![frame(EXPLOIT)],
        vec![LogEvent {
            address: addr(TOKEN),
            topics: vec![TRANSFER_TOPIC.into(), pad(TARGET), pad(ATTACKER)],
            data: "0x".into(),
        }],
    )
}

fn benign(hash: &str) -> TxEvent {
    tx(hash, TARGET, vec![frame("0x11111111")], vec![])
}

fn unrelated(hash: &str) -> TxEvent {
    tx(hash, OTHER, vec![frame(EXPLOIT)], vec![])
}

type TestEngine = Engine<FakeChain, FakePauser, NoContext>;

fn engine_with(
    chain: &FakeChain,
    pauser: &FakePauser,
    tweak: impl FnOnce(&mut EngineConfig),
) -> TestEngine {
    let mut cfg = EngineConfig::new(ChainId(31337), addr(TARGET), Confidence::new(80.0));
    tweak(&mut cfg);
    Engine::new(
        chain.clone(),
        pauser.clone(),
        NoContext,
        vec![signature()],
        cfg,
    )
}

fn engine(chain: &FakeChain, pauser: &FakePauser, min_conf: u64) -> TestEngine {
    engine_with(chain, pauser, |c| c.min_confirmations = min_conf)
}

// ---------------------------------------------------------------------- tests

#[tokio::test]
async fn first_tick_anchors_at_head_without_scanning_history() {
    let chain = FakeChain::new();
    chain.mine(vec![attack("0xold")]);
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);

    let r = e.tick().await.unwrap();
    assert_eq!(r.blocks_processed, 0);
    assert_eq!(e.tip().unwrap().number, 1);
    let r = e.tick().await.unwrap();
    assert_eq!(
        (r.evaluated, pauser.submitted()),
        (0, 0),
        "history is not re-scanned"
    );
}

/// Regression for the shipped daemon's worst bug: with the default of one
/// required confirmation, a transaction seen at the head (0 confirmations)
/// hit `continue` and the block was then marked processed, so it was never
/// looked at again — the daemon could never pause anything.
#[tokio::test]
async fn pause_waits_for_confirmations_then_fires_exactly_once() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 1);
    e.tick().await.unwrap(); // anchor at genesis

    chain.mine(vec![attack("0xexploit")]);
    let r = e.tick().await.unwrap();
    assert_eq!((r.evaluated, r.pending, pauser.submitted()), (1, 1, 0));

    chain.mine(vec![]);
    let r = e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1);
    assert_eq!(r.pauses.len(), 1);
    assert_eq!(r.pauses[0].triggering_tx_hash, "0xexploit");
    assert_eq!(r.pending, 0);

    chain.mine(vec![]);
    e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1, "no second pause");
}

#[tokio::test]
async fn zero_confirmations_pauses_as_soon_as_the_block_is_seen() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    let r = e.tick().await.unwrap();
    assert_eq!(r.pauses.len(), 1);
}

#[tokio::test]
async fn a_deeper_confirmation_requirement_is_honoured() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 3);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]); // block 1
    for _ in 0..2 {
        chain.mine(vec![]);
        e.tick().await.unwrap();
        assert_eq!(pauser.submitted(), 0, "not yet 3 deep");
    }
    chain.mine(vec![]); // block 4 is 3 above block 1
    e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1);
}

#[tokio::test]
async fn transactions_not_touching_the_target_are_ignored_and_benign_ones_do_not_pause() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![unrelated("0xu"), benign("0xb")]);
    let r = e.tick().await.unwrap();
    assert_eq!(r.evaluated, 1, "only the target-touching tx is scored");
    assert_eq!(pauser.submitted(), 0);
}

#[tokio::test]
async fn reorg_before_confirmation_cancels_the_pause() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 1);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]); // block 1
    assert_eq!(e.tick().await.unwrap().pending, 1);

    // The exploit's block is replaced by one without it.
    chain.reorg(1, vec![vec![], vec![]]);
    let r = e.tick().await.unwrap();
    assert_eq!(r.reorg_depth, Some(1));
    assert_eq!(r.dropped_by_reorg, 1);
    assert_eq!((r.pending, pauser.submitted()), (0, 0));

    chain.mine(vec![]);
    e.tick().await.unwrap();
    assert_eq!(
        pauser.submitted(),
        0,
        "a transaction that never happened must not pause"
    );
}

#[tokio::test]
async fn a_transaction_reincluded_after_a_reorg_pauses_once() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 1);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    e.tick().await.unwrap();

    chain.reorg(1, vec![vec![attack("0xexploit")], vec![]]);
    let r = e.tick().await.unwrap();
    assert_eq!(r.reorg_depth, Some(1));
    assert_eq!(r.dropped_by_reorg, 1, "old pending cancelled...");
    assert_eq!(r.evaluated, 1, "...and the re-included copy scored afresh");
    assert_eq!(pauser.submitted(), 1, "block 1' is already 1 deep");
    chain.mine(vec![]);
    e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1);
}

#[tokio::test]
async fn a_reorg_that_shortens_the_chain_is_handled() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![]);
    chain.mine(vec![]);
    chain.mine(vec![]);
    e.tick().await.unwrap();
    assert_eq!(e.tip().unwrap().number, 3);

    chain.reorg(2, vec![vec![]]); // head is now 2, below our tip of 3
    let r = e.tick().await.unwrap();
    // Old blocks 3 (gone) and 2 (replaced by 2') were both abandoned...
    assert_eq!(r.reorg_depth, Some(2));
    // ...and, in the same tick, the engine follows the new canonical 2'.
    assert_eq!(r.blocks_processed, 1);
    let new_two = chain.0.lock().unwrap().blocks[2].clone();
    assert_eq!(e.tip().unwrap(), &new_two);

    chain.mine(vec![attack("0xexploit")]);
    chain.mine(vec![]);
    e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1);
}

#[tokio::test]
async fn a_reorg_deeper_than_the_window_reanchors_and_drops_unverifiable_pending() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine_with(&chain, &pauser, |c| {
        c.min_confirmations = 10;
        c.reorg_window = 2;
    });
    e.tick().await.unwrap();
    for _ in 0..4 {
        chain.mine(vec![]);
    }
    chain.mine(vec![attack("0xexploit")]); // block 5
    e.tick().await.unwrap();
    assert_eq!(e.pending_len(), 1);

    chain.reorg(1, vec![vec![], vec![], vec![], vec![], vec![]]);
    let r = e.tick().await.unwrap();
    assert!(r.reorg_depth.is_some());
    assert_eq!(r.dropped_by_reorg, 1);
    assert_eq!(e.pending_len(), 0);
    assert_eq!(
        e.tip().unwrap().number,
        chain.head(),
        "re-anchored at the head"
    );
    assert_eq!(pauser.submitted(), 0);
}

#[tokio::test]
async fn a_block_that_changes_while_being_read_is_not_scored() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    // The chain reorganises just after the engine reads block 1's txs.
    chain.0.lock().unwrap().reorg_after_next_events = Some((1, vec![vec![], vec![]]));

    let r = e.tick().await.unwrap();
    assert_eq!(r.blocks_processed, 0, "inconsistent read is discarded");
    assert_eq!(pauser.submitted(), 0);

    let r = e.tick().await.unwrap();
    assert_eq!(
        r.blocks_processed, 2,
        "the new canonical blocks are then processed"
    );
    assert_eq!(
        pauser.submitted(),
        0,
        "the exploit was on the abandoned fork"
    );
}

#[tokio::test]
async fn a_failed_pause_is_retried_until_it_lands() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    pauser.0.lock().unwrap().fail_submits = 2;
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);

    let r = e.tick().await.unwrap();
    assert_eq!((r.pause_errors, r.pending, r.pauses.len()), (1, 1, 0));
    let r = e.tick().await.unwrap();
    assert_eq!((r.pause_errors, r.pending, r.pauses.len()), (1, 1, 0));
    let r = e.tick().await.unwrap();
    assert_eq!((r.pause_errors, r.pending), (0, 0));
    assert_eq!(r.pauses[0].attempts, 3);
    assert_eq!(pauser.submitted(), 1);
}

#[tokio::test]
async fn an_already_paused_target_is_not_paused_again() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    pauser.0.lock().unwrap().paused = true;
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    let r = e.tick().await.unwrap();
    assert_eq!((r.dropped_already_paused, pauser.submitted()), (1, 0));
}

#[tokio::test]
async fn two_exploit_transactions_in_one_block_produce_one_pause() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xfirst"), attack("0xsecond")]);
    let r = e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1);
    assert_eq!(r.dropped_already_paused, 1);
}

#[tokio::test]
async fn an_unreadable_paused_state_still_attempts_the_pause() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    pauser.0.lock().unwrap().is_paused_errors = true;
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    e.tick().await.unwrap();
    assert_eq!(pauser.submitted(), 1, "fail toward action, not inaction");
}

#[tokio::test]
async fn an_rpc_error_mid_block_neither_advances_nor_duplicates() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    chain.0.lock().unwrap().fail_events = 1;

    assert!(e.tick().await.is_err());
    assert_eq!(e.tip().unwrap().number, 0, "block not marked processed");
    assert_eq!(pauser.submitted(), 0);

    e.tick().await.unwrap();
    assert_eq!(
        pauser.submitted(),
        1,
        "processed exactly once after the retry"
    );
}

#[tokio::test]
async fn catching_up_is_bounded_per_tick_and_processes_every_block_once() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine_with(&chain, &pauser, |c| {
        c.min_confirmations = 0;
        c.max_blocks_per_tick = 2;
    });
    e.tick().await.unwrap();
    for i in 1..=5 {
        chain.mine(if i == 4 {
            vec![attack("0xexploit")]
        } else {
            vec![]
        });
    }
    let (mut processed, mut evaluated, mut ticks) = (0, 0, 0);
    while e.tip().unwrap().number < 5 {
        let r = e.tick().await.unwrap();
        assert!(r.blocks_processed <= 2);
        processed += r.blocks_processed;
        evaluated += r.evaluated;
        ticks += 1;
        assert!(ticks < 10);
    }
    assert_eq!((processed, evaluated, ticks), (5, 1, 3));
    assert_eq!(pauser.submitted(), 1);
}

#[tokio::test]
async fn pause_latency_is_recorded() {
    let chain = FakeChain::new();
    let pauser = FakePauser::default();
    let mut e = engine(&chain, &pauser, 0);
    e.tick().await.unwrap();
    chain.mine(vec![attack("0xexploit")]);
    let r = e.tick().await.unwrap();
    assert_eq!(r.pauses[0].attempts, 1);
    assert!(r.pauses[0].latency < std::time::Duration::from_secs(5));
}

// ------------------------------------------------------- touches_target unit

#[test]
fn touches_target_covers_every_way_a_transaction_can_involve_it() {
    let t = addr(TARGET);
    assert!(
        touches_target(&tx("0x1", TARGET, vec![], vec![]), &t),
        "direct to"
    );

    let mut from = tx("0x2", OTHER, vec![], vec![]);
    from.from = t;
    assert!(touches_target(&from, &t), "sent from the target");

    let mut via_frame = tx("0x3", OTHER, vec![frame("0x1")], vec![]);
    via_frame.call_frames[0].to = t;
    assert!(
        touches_target(&via_frame, &t),
        "internal call to the target"
    );

    let emitted = tx(
        "0x4",
        OTHER,
        vec![],
        vec![LogEvent {
            address: t,
            topics: vec![],
            data: "0x".into(),
        }],
    );
    assert!(touches_target(&emitted, &t), "log emitted by the target");

    let upper = tx(
        "0x5",
        OTHER,
        vec![],
        vec![LogEvent {
            address: addr(TOKEN),
            topics: vec![
                TRANSFER_TOPIC.into(),
                pad(TARGET).to_uppercase().replace("0X", "0x"),
            ],
            data: "0x".into(),
        }],
    );
    assert!(
        touches_target(&upper, &t),
        "topic match is case-insensitive"
    );
    assert!(
        touches_target(&attack("0x6"), &t),
        "the exploit shape: attacker contract + Transfer topic"
    );
}

#[test]
fn touches_target_rejects_unrelated_transactions() {
    let t = addr(TARGET);
    assert!(!touches_target(&unrelated("0x1"), &t));
    let near_miss = tx(
        "0x2",
        OTHER,
        vec![],
        vec![LogEvent {
            address: addr(TOKEN),
            // a topic that merely *ends* like the target's padded address
            topics: vec![
                TRANSFER_TOPIC.into(),
                pad("0x00000000000000000000000000000000000000ab"),
            ],
            data: "0x".into(),
        }],
    );
    assert!(!touches_target(&near_miss, &t));
}
