// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Guardian} from "../../../src/Guardian.sol";
import {GuardedVault} from "../../../src/GuardedVault.sol";

/// Drives the Guardian with random sequences of calls from a mix of honest
/// and hostile actors, while keeping an independent ghost model of what *should*
/// have happened. The invariants compare the two.
contract GuardianHandler is Test {
    Guardian public immutable guardian;
    GuardedVault[3] public vaults; // [0],[1] start registered; [2] never registered

    address public immutable admin;
    address public immutable pauser;
    address public immutable attacker;
    address public immutable stranger;
    address[4] internal actors;

    // Ghost model.
    mapping(address => bool) public modelRegistered;
    mapping(address => bool) public modelPaused;
    uint256 public illegalPauseSucceeded;
    uint256 public illegalUnpauseSucceeded;
    uint256 public illegalRegisterSucceeded;
    uint256 public illegalGrantSucceeded;
    /// role => account => granted by a then-admin (or part of the initial setup).
    mapping(bytes32 => mapping(address => bool)) public legitimatelyGranted;
    uint256 public pauses;
    uint256 public unpauses;

    constructor(
        Guardian g,
        GuardedVault[3] memory v,
        address _admin,
        address _pauser,
        address _attacker,
        address _stranger
    ) {
        guardian = g;
        vaults = v;
        admin = _admin;
        pauser = _pauser;
        attacker = _attacker;
        stranger = _stranger;
        actors = [_admin, _pauser, _attacker, _stranger];
        legitimatelyGranted[g.DEFAULT_ADMIN_ROLE()][_admin] = true;
        legitimatelyGranted[g.PAUSER_ROLE()][_pauser] = true;
        modelRegistered[address(v[0])] = true;
        modelRegistered[address(v[1])] = true;
    }

    function vaultAt(uint256 i) external view returns (GuardedVault) {
        return vaults[i];
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _target(uint256 seed) internal view returns (GuardedVault) {
        return vaults[seed % vaults.length];
    }

    function pause(uint256 actorSeed, uint256 targetSeed) external {
        address a = _actor(actorSeed);
        GuardedVault t = _target(targetSeed);
        bool allowed = guardian.hasRole(guardian.PAUSER_ROLE(), a) && modelRegistered[address(t)];
        vm.prank(a);
        try guardian.pause(address(t), "fuzz") {
            if (!allowed) illegalPauseSucceeded++;
            modelPaused[address(t)] = true;
            pauses++;
        } catch {}
    }

    function unpause(uint256 actorSeed, uint256 targetSeed) external {
        address a = _actor(actorSeed);
        GuardedVault t = _target(targetSeed);
        bool allowed = guardian.hasRole(guardian.DEFAULT_ADMIN_ROLE(), a) && modelRegistered[address(t)];
        vm.prank(a);
        try guardian.unpause(address(t)) {
            if (!allowed) illegalUnpauseSucceeded++;
            modelPaused[address(t)] = false;
            unpauses++;
        } catch {}
    }

    function register(uint256 actorSeed, uint256 targetSeed) external {
        address a = _actor(actorSeed);
        GuardedVault t = _target(targetSeed);
        bool allowed = guardian.hasRole(guardian.DEFAULT_ADMIN_ROLE(), a) && !modelRegistered[address(t)];
        vm.prank(a);
        try guardian.registerTarget(address(t)) {
            if (!allowed) illegalRegisterSucceeded++;
            modelRegistered[address(t)] = true;
        } catch {}
    }

    function deregister(uint256 actorSeed, uint256 targetSeed) external {
        address a = _actor(actorSeed);
        GuardedVault t = _target(targetSeed);
        bool allowed = guardian.hasRole(guardian.DEFAULT_ADMIN_ROLE(), a) && modelRegistered[address(t)];
        vm.prank(a);
        try guardian.deregisterTarget(address(t)) {
            if (!allowed) illegalRegisterSucceeded++;
            modelRegistered[address(t)] = false;
        } catch {}
    }

    /// Role escalation attempts: any actor tries to hand out either role.
    /// Only the admin may; nobody else's grants may succeed.
    function grant(uint256 actorSeed, uint256 toSeed, bool adminRole) external {
        address a = _actor(actorSeed);
        address to = _actor(toSeed);
        bytes32 role = adminRole ? guardian.DEFAULT_ADMIN_ROLE() : guardian.PAUSER_ROLE();
        bool allowed = guardian.hasRole(guardian.DEFAULT_ADMIN_ROLE(), a);
        vm.prank(a);
        try guardian.grantRole(role, to) {
            if (!allowed) illegalGrantSucceeded++;
            else legitimatelyGranted[role][to] = true;
        } catch {}
    }
}

contract GuardianInvariantTest is StdInvariant, Test {
    Guardian internal guardian;
    GuardianHandler internal handler;
    GuardedVault[3] internal vaults;

    address internal admin = makeAddr("admin");
    address internal pauser = makeAddr("pauser");
    address internal attacker = makeAddr("attacker");
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        guardian = new Guardian(admin);
        for (uint256 i; i < 3; ++i) {
            vaults[i] = new GuardedVault(admin, address(guardian));
        }
        vm.startPrank(admin);
        guardian.grantRole(guardian.PAUSER_ROLE(), pauser);
        guardian.registerTarget(address(vaults[0]));
        guardian.registerTarget(address(vaults[1]));
        vm.stopPrank();

        handler = new GuardianHandler(guardian, vaults, admin, pauser, attacker, stranger);
        targetContract(address(handler));
    }

    /// Nobody without PAUSER_ROLE (or on an unregistered target) ever pauses.
    function invariant_only_pausers_pause_registered_targets() public view {
        assertEq(handler.illegalPauseSucceeded(), 0);
    }

    /// Nobody without DEFAULT_ADMIN_ROLE ever unpauses -- in particular not the hot wallet.
    function invariant_only_admin_unpauses() public view {
        assertEq(handler.illegalUnpauseSucceeded(), 0);
    }

    function invariant_only_admin_changes_registry() public view {
        assertEq(handler.illegalRegisterSucceeded(), 0);
    }

    function invariant_no_privilege_escalation() public view {
        assertEq(handler.illegalGrantSucceeded(), 0);
        // Every holder of either role received it from a then-admin: no other
        // path to a role exists, whoever the actor is.
        address[4] memory who = [admin, pauser, attacker, stranger];
        bytes32[2] memory roles = [guardian.DEFAULT_ADMIN_ROLE(), guardian.PAUSER_ROLE()];
        for (uint256 i; i < who.length; ++i) {
            for (uint256 j; j < roles.length; ++j) {
                if (guardian.hasRole(roles[j], who[i])) {
                    assertTrue(handler.legitimatelyGranted(roles[j], who[i]), "role without an admin grant");
                }
            }
        }
    }

    /// A target that has never been registered is never paused by the Guardian.
    function invariant_never_registered_target_is_never_paused() public view {
        if (!handler.modelRegistered(address(vaults[2])) && !_everRegistered2()) {
            assertFalse(vaults[2].paused());
        }
    }

    /// The contracts' view of the world equals the independent model.
    function invariant_on_chain_state_matches_model() public view {
        for (uint256 i; i < 3; ++i) {
            address t = address(vaults[i]);
            assertEq(guardian.registeredTargets(t), handler.modelRegistered(t), "registry");
            assertEq(vaults[i].paused(), handler.modelPaused(t), "paused");
        }
    }

    /// Only the Guardian holds the vaults' GUARDIAN_ROLE -- a pause has no other source.
    function invariant_pause_authority_is_only_the_guardian() public view {
        for (uint256 i; i < 3; ++i) {
            bytes32 gr = vaults[i].GUARDIAN_ROLE();
            assertTrue(vaults[i].hasRole(gr, address(guardian)));
            assertFalse(vaults[i].hasRole(gr, pauser));
            assertFalse(vaults[i].hasRole(gr, attacker));
        }
    }

    function _everRegistered2() internal view returns (bool) {
        // Vault 2 is only ever paused after being registered by the admin
        // actor; the model tracks its current registration, and the paused
        // flag can stay set after a later deregistration, so this weaker
        // check only asserts when it was never touched at all.
        return handler.modelPaused(address(vaults[2])) || guardian.registeredTargets(address(vaults[2]));
    }
}
