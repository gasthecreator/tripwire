// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Guardian} from "../../src/Guardian.sol";
import {GuardedVault} from "../../src/GuardedVault.sol";
import {DeployGuardianBase} from "../../script/DeployGuardian.sol";

/// Stands in for a Safe: all the deploy script needs from an existing admin is
/// that it is a contract.
contract MockSafe {}

/// Exercises the deploy script's logic (not the `vm.env*` shell around it) by
/// calling the shared base directly with this test as the deployer.
contract DeployGuardianTest is Test, DeployGuardianBase {
    address internal hot = makeAddr("hot");
    address internal proposer = makeAddr("proposer");
    address internal executor = makeAddr("executor");
    address internal attacker = makeAddr("attacker");
    GuardedVault internal vault;

    function setUp() public {
        // A real pausable target owned by a placeholder guardian address; the
        // script only needs `paused()` to work and the address to have code.
        vault = new GuardedVault(address(this), address(this));
    }

    function _cfg() internal view returns (Config memory c) {
        c.proposers = new address[](1);
        c.proposers[0] = proposer;
        c.executors = new address[](1);
        c.executors[0] = executor;
        c.timelockDelay = 1 days;
        c.hotWallet = hot;
        c.targets = new address[](1);
        c.targets[0] = address(vault);
    }

    function _assertFinalState(Guardian g, address admin, Config memory c) internal view {
        assertTrue(g.hasRole(g.DEFAULT_ADMIN_ROLE(), admin));
        assertFalse(g.hasRole(g.DEFAULT_ADMIN_ROLE(), address(this)), "deployer renounced");
        assertFalse(g.hasRole(g.DEFAULT_ADMIN_ROLE(), c.hotWallet), "hot wallet not admin");
        assertTrue(g.hasRole(g.PAUSER_ROLE(), c.hotWallet));
        assertFalse(g.hasRole(g.PAUSER_ROLE(), admin), "admin cannot pause");
        assertFalse(g.hasRole(g.PAUSER_ROLE(), address(this)));
        for (uint256 i; i < c.targets.length; ++i) {
            assertTrue(g.registeredTargets(c.targets[i]));
        }
    }

    function test_new_timelock_happy_path() public {
        Config memory c = _cfg();
        (Guardian g, address admin) = this.deployExternal(c);
        _assertFinalState(g, admin, c);
        TimelockController t = TimelockController(payable(admin));
        assertEq(t.getMinDelay(), 1 days);
        assertTrue(t.hasRole(t.PROPOSER_ROLE(), proposer));
        assertTrue(t.hasRole(t.EXECUTOR_ROLE(), executor));
        // The timelock administers itself; no deployer backdoor.
        assertFalse(t.hasRole(t.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(t.hasRole(t.DEFAULT_ADMIN_ROLE(), hot));
    }

    function test_existing_multisig_admin_is_accepted() public {
        Config memory c = _cfg();
        address safe = address(new MockSafe());
        c.existingAdmin = safe;
        (Guardian g, address admin) = this.deployExternal(c);
        assertEq(admin, safe);
        _assertFinalState(g, admin, c);
    }

    function test_existing_admin_that_is_an_eoa_is_rejected() public {
        Config memory c = _cfg();
        c.existingAdmin = attacker;
        vm.expectRevert(abi.encodeWithSelector(AdminNotAContract.selector, attacker));
        this.deployExternal(c);
    }

    function test_existing_admin_equal_to_hot_wallet_is_rejected() public {
        Config memory c = _cfg();
        // Give the hot wallet code so the "is a contract" check passes and the
        // role-separation check is what fires.
        vm.etch(hot, address(new MockSafe()).code);
        c.existingAdmin = hot;
        vm.expectRevert(abi.encodeWithSelector(HotWalletHoldsGovernanceRole.selector, hot));
        this.deployExternal(c);
    }

    function test_short_timelock_delay_is_rejected() public {
        Config memory c = _cfg();
        c.timelockDelay = 9 minutes;
        vm.expectRevert(abi.encodeWithSelector(TimelockDelayTooShort.selector, 9 minutes, 10 minutes));
        this.deployExternal(c);
    }

    function test_minimum_timelock_delay_is_accepted() public {
        Config memory c = _cfg();
        c.timelockDelay = MIN_TIMELOCK_DELAY;
        (, address admin) = this.deployExternal(c);
        assertEq(TimelockController(payable(admin)).getMinDelay(), MIN_TIMELOCK_DELAY);
    }

    function test_hot_wallet_as_proposer_is_rejected() public {
        Config memory c = _cfg();
        c.proposers[0] = hot;
        vm.expectRevert(abi.encodeWithSelector(HotWalletHoldsGovernanceRole.selector, hot));
        this.deployExternal(c);
    }

    function test_hot_wallet_as_executor_is_rejected() public {
        Config memory c = _cfg();
        c.executors[0] = hot;
        vm.expectRevert(abi.encodeWithSelector(HotWalletHoldsGovernanceRole.selector, hot));
        this.deployExternal(c);
    }

    function test_empty_proposers_or_executors_rejected() public {
        Config memory c = _cfg();
        c.proposers = new address[](0);
        vm.expectRevert(NoProposers.selector);
        this.deployExternal(c);

        c = _cfg();
        c.executors = new address[](0);
        vm.expectRevert(NoExecutors.selector);
        this.deployExternal(c);
    }

    function test_zero_hot_wallet_and_deployer_as_hot_wallet_rejected() public {
        Config memory c = _cfg();
        c.hotWallet = address(0);
        vm.expectRevert(HotWalletIsZero.selector);
        this.deployExternal(c);

        c = _cfg();
        c.hotWallet = address(this);
        vm.expectRevert(DeployerIsHotWallet.selector);
        this.deployExternal(c);
    }

    function test_target_that_is_an_eoa_aborts_the_whole_deploy() public {
        Config memory c = _cfg();
        c.targets[0] = attacker;
        vm.expectRevert(abi.encodeWithSelector(Guardian.TargetNotContract.selector, attacker));
        this.deployExternal(c);
    }

    function test_target_that_is_not_pausable_aborts_the_whole_deploy() public {
        Config memory c = _cfg();
        address notPausable = address(new MockSafe());
        c.targets[0] = notPausable;
        vm.expectRevert(abi.encodeWithSelector(Guardian.TargetNotPausable.selector, notPausable));
        this.deployExternal(c);
    }

    function test_zero_targets_is_allowed_and_targets_can_be_added_later_by_the_timelock_only() public {
        Config memory c = _cfg();
        c.targets = new address[](0);
        (Guardian g, address admin) = this.deployExternal(c);
        assertFalse(g.registeredTargets(address(vault)));

        // Neither the hot wallet nor the (renounced) deployer can register.
        vm.prank(hot);
        vm.expectRevert();
        g.registerTarget(address(vault));
        vm.expectRevert();
        g.registerTarget(address(vault));

        // The timelock can, after its delay.
        TimelockController t = TimelockController(payable(admin));
        bytes memory data = abi.encodeCall(Guardian.registerTarget, (address(vault)));
        vm.prank(proposer);
        t.schedule(address(g), 0, data, bytes32(0), bytes32(0), 1 days);
        vm.warp(block.timestamp + 1 days);
        vm.prank(executor);
        t.execute(address(g), 0, data, bytes32(0), bytes32(0));
        assertTrue(g.registeredTargets(address(vault)));
    }

    /// The end state is *usable*: the hot wallet can pause, and can't unpause;
    /// the timelock is the only path back.
    function test_deployed_guardian_pauses_via_hot_wallet_and_unpauses_only_via_timelock() public {
        GuardedVault v = new GuardedVault(address(this), address(this));
        Config memory c = _cfg();
        c.targets[0] = address(v);
        (Guardian g, address admin) = this.deployExternal(c);
        v.grantRole(v.GUARDIAN_ROLE(), address(g));

        vm.prank(hot);
        g.pause(address(v), "test");
        assertTrue(v.paused());

        vm.prank(hot);
        vm.expectRevert();
        g.unpause(address(v));

        TimelockController t = TimelockController(payable(admin));
        bytes memory data = abi.encodeCall(Guardian.unpause, (address(v)));
        vm.prank(proposer);
        t.schedule(address(g), 0, data, bytes32(0), bytes32(0), 1 days);
        vm.prank(executor);
        vm.expectRevert();
        t.execute(address(g), 0, data, bytes32(0), bytes32(0));
        vm.warp(block.timestamp + 1 days);
        vm.prank(executor);
        t.execute(address(g), 0, data, bytes32(0), bytes32(0));
        assertFalse(v.paused());
    }

    /// `vm.expectRevert` needs an external call boundary.
    function deployExternal(Config memory c) external returns (Guardian, address) {
        return _deployGuardian(c, address(this));
    }
}
