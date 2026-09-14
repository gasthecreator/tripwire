// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IPausable} from "./interfaces/IPausable.sol";

/// @title GuardedVault
/// @notice A minimal demo vault used as the concrete target for
/// Tripwire's historical-exploit replay tests (ARCHITECTURE.md §3.5) and
/// as a reference for what a real protocol's pause entrypoint needs to
/// look like to become guardable (`docs/INTEGRATION.md`). Deliberately
/// simple — deposit/withdraw only, with a standard checks-effects-
/// interactions withdrawal plus `ReentrancyGuard` as defense in depth —
/// because its purpose is to be a real, pausable target for the
/// guardian mechanism, not a production lending/vault protocol in its
/// own right.
contract GuardedVault is AccessControl, Pausable, ReentrancyGuard, IPausable {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    mapping(address account => uint256 balance) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    error InsufficientBalance(uint256 requested, uint256 available);
    error TransferFailed();

    constructor(address admin, address guardian) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
    }

    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        uint256 balance = balances[msg.sender];
        if (balance < amount) revert InsufficientBalance(amount, balance);
        // Effects before interaction -- the correct pattern this demo
        // deliberately follows, contrasted with `signatures/reentrancy-basic.yaml`'s
        // documented anomaly signature for protocols that get this
        // ordering wrong. Event emitted before the external call too, so
        // a reentrant call (blocked by `nonReentrant` regardless) can
        // never reorder it.
        balances[msg.sender] = balance - amount;
        emit Withdrawn(msg.sender, amount);
        // Low-level call, not `transfer`/`send`: forwarding all
        // remaining gas is deliberate so a smart-contract-wallet
        // depositor (a Safe, an account-abstraction wallet) can receive
        // funds -- `transfer`'s fixed 2300-gas stipend breaks those.
        // `nonReentrant` above is what makes this safe against the
        // reentrancy that unrestricted forwarded gas would otherwise
        // enable.
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Only the registered Guardian contract may pause this
    /// vault — not `DEFAULT_ADMIN_ROLE`, and not any other address. This
    /// is the concrete answer to "who can pause a real protocol":
    /// exactly the Guardian this vault was deployed pointing at, nothing
    /// else. SECURITY.md T1's hot-key blast-radius argument depends on
    /// this being true.
    function pause() external override onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external override onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    function paused() public view override(Pausable, IPausable) returns (bool) {
        return super.paused();
    }

    receive() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}
