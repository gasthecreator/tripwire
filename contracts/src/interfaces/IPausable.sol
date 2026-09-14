// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice The minimal interface a protocol must implement to be
/// guardable by Tripwire's `Guardian` contract. Deliberately narrow —
/// see `docs/INTEGRATION.md` for exactly what an already-deployed
/// protocol needs to add to satisfy this, which is meant to be small
/// enough not to require a full contract rewrite to adopt.
interface IPausable {
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
}
