// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IPausable} from "./interfaces/IPausable.sol";

/// @title Guardian
/// @notice On-chain pause authority for Tripwire-protected protocols.
/// See ARCHITECTURE.md §3.4 and SECURITY.md for the full threat model
/// and the gas-cost/speed tradeoff this design makes explicit.
///
/// `PAUSER_ROLE` is intended to be held by the off-chain detection
/// service's hot wallet and nothing else — it can call `pause()` on a
/// registered target, full stop. `DEFAULT_ADMIN_ROLE` (able to
/// register/deregister targets, grant/revoke `PAUSER_ROLE`, and
/// unpause) is intended to be an OpenZeppelin `TimelockController`
/// behind a multisig, never the hot wallet or any single EOA. Solidity
/// can't enforce "this address is a timelock" as a type-level
/// constraint, so that separation is a deployment-time responsibility —
/// documented here, in `docs/INTEGRATION.md`, and checked by this
/// repo's own deploy script, not something this contract can verify
/// about its own admin at construction time.
contract Guardian is AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Targets this Guardian is authorized to pause. A target
    /// must be explicitly registered by `DEFAULT_ADMIN_ROLE` before any
    /// pause call against it can succeed — the guardian can never be
    /// pointed at an arbitrary address purely from off-chain confidence-
    /// score output; on-chain registration is a separate, deliberate
    /// admin action.
    mapping(address target => bool isRegistered) public registeredTargets;

    event TargetRegistered(address indexed target);
    event TargetDeregistered(address indexed target);
    event Paused(address indexed target, address indexed caller, string reason);
    event Unpaused(address indexed target, address indexed caller);

    error TargetNotRegistered(address target);
    error TargetAlreadyRegistered(address target);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function registerTarget(address target) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (registeredTargets[target]) revert TargetAlreadyRegistered(target);
        registeredTargets[target] = true;
        emit TargetRegistered(target);
    }

    function deregisterTarget(address target) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!registeredTargets[target]) revert TargetNotRegistered(target);
        registeredTargets[target] = false;
        emit TargetDeregistered(target);
    }

    /// @notice Pauses a registered target. Callable only by
    /// `PAUSER_ROLE` — the off-chain detection service's hot wallet in
    /// the intended deployment. `reason` is an opaque string supplied by
    /// the caller (e.g. a signature id or confidence score) purely for
    /// the on-chain audit trail (SECURITY.md §3); it has no on-chain
    /// effect on whether the pause succeeds.
    function pause(address target, string calldata reason) external onlyRole(PAUSER_ROLE) {
        if (!registeredTargets[target]) revert TargetNotRegistered(target);
        // Emitted before the external call so the audit log's event
        // ordering can't be reshuffled by anything `target.pause()`
        // does — a reverted call still unwinds this event with the rest
        // of the transaction, so correctness doesn't depend on the order.
        emit Paused(target, msg.sender, reason);
        IPausable(target).pause();
    }

    /// @notice Unpauses a registered target. Deliberately gated to
    /// `DEFAULT_ADMIN_ROLE` only — never `PAUSER_ROLE` — so the hot
    /// wallet that can trigger a pause can never also reverse one
    /// (ARCHITECTURE.md §3.4, SECURITY.md T4). In the intended
    /// deployment `DEFAULT_ADMIN_ROLE` is a `TimelockController`, so
    /// this call only succeeds after that timelock's delay has elapsed
    /// on a queued proposal — not instantly, by design.
    function unpause(address target) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!registeredTargets[target]) revert TargetNotRegistered(target);
        emit Unpaused(target, msg.sender);
        IPausable(target).unpause();
    }
}
