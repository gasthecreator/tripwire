// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {GuardedVault} from "../../src/GuardedVault.sol";

/// @notice Attempts a classic reentrant withdrawal via its `receive()`
/// hook -- the exact pattern `signatures/reentrancy-basic.yaml` is
/// written to detect off-chain. On-chain, `GuardedVault.withdraw`'s
/// `nonReentrant` guard and checks-effects-interactions ordering must
/// stop it regardless of whether the off-chain detector also catches it
/// -- defense in depth, not either/or.
contract ReentrantAttacker {
    GuardedVault public immutable vault;
    uint256 public reentryAttempts;
    bool public reentryReverted;

    constructor(GuardedVault _vault) {
        vault = _vault;
    }

    function attack(uint256 amount) external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(amount);
    }

    receive() external payable {
        if (reentryAttempts == 0) {
            reentryAttempts++;
            try vault.withdraw(msg.value) {
                reentryReverted = false;
            } catch {
                reentryReverted = true;
            }
        }
    }
}

contract GuardedVaultTest is Test {
    GuardedVault internal vault;

    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        vault = new GuardedVault(admin, guardian);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function test_deposit_credits_sender_balance() public {
        vm.prank(alice);
        vault.deposit{value: 3 ether}();
        assertEq(vault.balances(alice), 3 ether);
    }

    function test_withdraw_debits_balance_and_transfers_eth() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();

        uint256 balanceBefore = alice.balance;
        vm.prank(alice);
        vault.withdraw(2 ether);

        assertEq(vault.balances(alice), 3 ether);
        assertEq(alice.balance, balanceBefore + 2 ether);
    }

    function test_cannot_withdraw_more_than_balance() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GuardedVault.InsufficientBalance.selector, 2 ether, 1 ether));
        vault.withdraw(2 ether);
    }

    function test_one_users_deposit_does_not_affect_anothers_balance() public {
        vm.prank(alice);
        vault.deposit{value: 10 ether}();
        vm.prank(bob);
        vault.deposit{value: 1 ether}();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(GuardedVault.InsufficientBalance.selector, 5 ether, 1 ether));
        vault.withdraw(5 ether);
    }

    function testFuzz_withdraw_never_exceeds_deposit(uint96 depositAmount, uint96 withdrawAmount) public {
        vm.assume(depositAmount > 0 && depositAmount <= 100 ether);
        vm.deal(alice, depositAmount);

        vm.prank(alice);
        vault.deposit{value: depositAmount}();

        vm.prank(alice);
        if (withdrawAmount > depositAmount) {
            vm.expectRevert(
                abi.encodeWithSelector(GuardedVault.InsufficientBalance.selector, withdrawAmount, depositAmount)
            );
            vault.withdraw(withdrawAmount);
        } else {
            vault.withdraw(withdrawAmount);
            assertEq(vault.balances(alice), depositAmount - withdrawAmount);
        }
    }

    // --- guardian-gated pause/unpause ---

    function test_only_guardian_can_pause() public {
        bytes32 guardianRole = vault.GUARDIAN_ROLE();
        vm.prank(admin); // even the vault's own admin cannot pause directly
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, admin, guardianRole)
        );
        vault.pause();
    }

    function test_guardian_can_pause_and_unpause() public {
        vm.prank(guardian);
        vault.pause();
        assertTrue(vault.paused());

        vm.prank(guardian);
        vault.unpause();
        assertFalse(vault.paused());
    }

    // --- reentrancy: defense in depth on top of off-chain detection ---

    function test_reentrant_withdrawal_is_blocked_by_nonReentrant_guard() public {
        ReentrantAttacker attacker = new ReentrantAttacker(vault);
        vm.deal(address(attacker), 1 ether);

        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}(1 ether);

        assertEq(attacker.reentryAttempts(), 1);
        assertTrue(attacker.reentryReverted(), "reentrant withdraw() must revert");
        // Exactly one withdrawal's worth left the vault, not two --
        // the outcome a reentrancy exploit is trying to achieve.
        assertEq(vault.balances(address(attacker)), 0);
    }
}
