// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Guardian} from "../../src/Guardian.sol";
import {GuardedVault} from "../../src/GuardedVault.sol";
import {IPausable} from "../../src/interfaces/IPausable.sol";

/// @notice A target that attempts to reenter the Guardian from within its
/// own `pause()`, used to prove the reentrancy-via-registered-target
/// attack SECURITY.md §2 (T5) discusses is blocked by role-based access
/// control alone -- no `nonReentrant` guard needed on `Guardian.pause`.
contract MaliciousReentrantTarget is IPausable {
    Guardian public immutable guardian;
    address public immutable otherTarget;
    bool public pausedFlag;
    bool public reentryReverted;

    constructor(Guardian _guardian, address _otherTarget) {
        guardian = _guardian;
        otherTarget = _otherTarget;
    }

    function pause() external override {
        // Attempt to use this call's context to pause a second target --
        // this must fail, because msg.sender as seen by the Guardian on
        // this reentrant call is *this contract's* address, which never
        // holds PAUSER_ROLE.
        try guardian.pause(otherTarget, "reentrant attempt") {
            reentryReverted = false;
        } catch {
            reentryReverted = true;
        }
        pausedFlag = true;
    }

    function unpause() external override {
        pausedFlag = false;
    }

    function paused() external view override returns (bool) {
        return pausedFlag;
    }
}

contract GuardianTest is Test {
    Guardian internal guardian;
    GuardedVault internal vault;

    address internal admin = makeAddr("admin");
    address internal pauser = makeAddr("pauser");
    address internal stranger = makeAddr("stranger");
    address internal depositor = makeAddr("depositor");

    function setUp() public {
        vm.prank(admin);
        guardian = new Guardian(admin);

        vault = new GuardedVault(admin, address(guardian));

        vm.startPrank(admin);
        guardian.grantRole(guardian.PAUSER_ROLE(), pauser);
        guardian.registerTarget(address(vault));
        vm.stopPrank();
    }

    // --- pausing ---

    function test_pauser_can_pause_registered_target() public {
        vm.prank(pauser);
        guardian.pause(address(vault), "reentrancy-basic confidence=92");
        assertTrue(vault.paused());
    }

    function test_paused_vault_rejects_deposits_and_withdrawals() public {
        vm.deal(depositor, 1 ether);
        vm.prank(depositor);
        vault.deposit{value: 1 ether}();

        vm.prank(pauser);
        guardian.pause(address(vault), "test");

        vm.prank(depositor);
        vm.expectRevert();
        vault.deposit{value: 1 ether}();

        vm.prank(depositor);
        vm.expectRevert();
        vault.withdraw(1 ether);
    }

    function test_non_pauser_cannot_pause() public {
        // Fetched before `vm.prank` -- `vm.prank` is single-shot for the
        // *next* call, and a call made while building the expected
        // revert data would otherwise consume it before it reaches the
        // real `pause()` call below.
        bytes32 pauserRole = guardian.PAUSER_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, pauserRole)
        );
        guardian.pause(address(vault), "unauthorized attempt");
    }

    function test_cannot_pause_unregistered_target() public {
        address randomTarget = makeAddr("randomTarget");
        vm.prank(pauser);
        vm.expectRevert(abi.encodeWithSelector(Guardian.TargetNotRegistered.selector, randomTarget));
        guardian.pause(randomTarget, "test");
    }

    // --- registration ---

    function test_non_admin_cannot_register_target() public {
        address newTarget = makeAddr("newTarget");
        bytes32 adminRole = guardian.DEFAULT_ADMIN_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, adminRole)
        );
        guardian.registerTarget(newTarget);
    }

    function test_cannot_register_same_target_twice() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Guardian.TargetAlreadyRegistered.selector, address(vault)));
        guardian.registerTarget(address(vault));
    }

    function test_deregistered_target_can_no_longer_be_paused() public {
        vm.prank(admin);
        guardian.deregisterTarget(address(vault));

        vm.prank(pauser);
        vm.expectRevert(abi.encodeWithSelector(Guardian.TargetNotRegistered.selector, address(vault)));
        guardian.pause(address(vault), "test");
    }

    // --- unpausing: the hot key must never be able to self-reverse ---

    function test_admin_can_unpause() public {
        vm.prank(pauser);
        guardian.pause(address(vault), "test");

        vm.prank(admin);
        guardian.unpause(address(vault));
        assertFalse(vault.paused());
    }

    function test_pauser_cannot_unpause() public {
        vm.prank(pauser);
        guardian.pause(address(vault), "test");

        // SECURITY.md T4: the hot wallet that triggers a pause must
        // never also be able to reverse it.
        bytes32 adminRole = guardian.DEFAULT_ADMIN_ROLE();
        vm.prank(pauser);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, adminRole)
        );
        guardian.unpause(address(vault));
    }

    // --- reentrancy ---

    function test_malicious_target_cannot_use_reentrancy_to_pause_another_target() public {
        address secondTargetPlaceholder = makeAddr("secondTarget");
        MaliciousReentrantTarget malicious = new MaliciousReentrantTarget(guardian, secondTargetPlaceholder);

        vm.prank(admin);
        guardian.registerTarget(address(malicious));

        vm.prank(pauser);
        guardian.pause(address(malicious), "test");

        // The malicious target's own pause() attempted to reenter
        // Guardian.pause() for a second target using its own address as
        // msg.sender -- which never holds PAUSER_ROLE, so it must have
        // reverted, proving role-based access control alone blocks this
        // reentrancy path with no explicit reentrancy guard needed.
        assertTrue(malicious.reentryReverted());
        assertTrue(malicious.pausedFlag());
    }

    // --- full timelock + multisig-style recovery path (ARCHITECTURE.md §3.4) ---

    function test_unpause_via_timelock_requires_delay_to_elapse() public {
        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = admin;
        uint256 delay = 2 days;

        TimelockController timelock = new TimelockController(delay, proposers, executors, address(0));

        Guardian timelockGuardian = new Guardian(address(timelock));
        GuardedVault timelockVault = new GuardedVault(address(timelock), address(timelockGuardian));

        // Registering the vault and granting PAUSER_ROLE both also go
        // through the timelock in a real deployment; done directly here
        // via vm.prank to isolate this test to the unpause delay itself.
        vm.startPrank(address(timelock));
        timelockGuardian.registerTarget(address(timelockVault));
        timelockGuardian.grantRole(timelockGuardian.PAUSER_ROLE(), pauser);
        vm.stopPrank();

        vm.prank(pauser);
        timelockGuardian.pause(address(timelockVault), "false positive under investigation");
        assertTrue(timelockVault.paused());

        bytes memory unpauseCall = abi.encodeWithSelector(Guardian.unpause.selector, address(timelockVault));

        vm.prank(admin);
        timelock.schedule(address(timelockGuardian), 0, unpauseCall, bytes32(0), bytes32(0), delay);

        // Executing before the delay elapses must revert -- this is the
        // whole point of the recovery path: fast to pause, deliberately
        // not-instant to unpause (SECURITY.md T4).
        vm.prank(admin);
        vm.expectRevert();
        timelock.execute(address(timelockGuardian), 0, unpauseCall, bytes32(0), bytes32(0));

        vm.warp(block.timestamp + delay + 1);

        vm.prank(admin);
        timelock.execute(address(timelockGuardian), 0, unpauseCall, bytes32(0), bytes32(0));
        assertFalse(timelockVault.paused());
    }
}
