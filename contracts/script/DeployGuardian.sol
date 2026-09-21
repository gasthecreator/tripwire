// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Guardian} from "../src/Guardian.sol";

/// @notice Deploys a `Guardian` with the role separation SECURITY.md relies on,
/// and *refuses* to finish if any of it doesn't hold.
///
/// The properties this enforces are exactly the ones a deployment can get
/// wrong and Solidity can't check inside `Guardian` itself:
///
///  1. The admin (who can unpause, register targets and grant roles) is a
///     **contract** — a `TimelockController`, or a multisig such as a Safe —
///     never an EOA.
///  2. The unpause path is not instant: a new timelock must have a delay of
///     at least `MIN_TIMELOCK_DELAY`.
///  3. The off-chain hot wallet holds `PAUSER_ROLE` and *nothing else*: not
///     the admin role, and it is not a proposer or executor on the timelock.
///     A compromised hot key can then only pause (recoverable), never
///     unpause, reconfigure or upgrade.
///  4. The deployer's temporary admin rights are renounced.
///
/// Flow: the deployer bootstraps (grants `PAUSER_ROLE`, registers targets),
/// hands `DEFAULT_ADMIN_ROLE` to the timelock/multisig, and renounces its own.
///
/// Setting each target's own `GUARDIAN_ROLE` (or equivalent) to the deployed
/// Guardian is protocol-specific and is done by the protocol, through its own
/// governance; this script deliberately does not touch target contracts.
abstract contract DeployGuardianBase {
    /// Shortest unpause delay a *new* timelock may be deployed with. A
    /// deliberate floor, not a recommendation: pick hours, not minutes,
    /// unless false-positive recovery speed genuinely outweighs the risk of a
    /// hasty unpause during a live exploit (SECURITY.md T4).
    uint256 public constant MIN_TIMELOCK_DELAY = 10 minutes;

    struct Config {
        /// Use an existing timelock / multisig as admin. If zero, a new
        /// `TimelockController` is deployed from `proposers`/`executors`/`timelockDelay`.
        address existingAdmin;
        address[] proposers;
        address[] executors;
        uint256 timelockDelay;
        /// The off-chain detection service's key. PAUSER_ROLE only.
        address hotWallet;
        /// Contracts the Guardian may pause.
        address[] targets;
    }

    error AdminNotAContract(address admin);
    error TimelockDelayTooShort(uint256 given, uint256 minimum);
    error NoProposers();
    error NoExecutors();
    error HotWalletIsZero();
    error HotWalletHoldsGovernanceRole(address hotWallet);
    error DeployerIsHotWallet();
    error PostconditionFailed(string what);

    function _deployGuardian(Config memory c, address deployer) internal returns (Guardian guardian, address admin) {
        if (c.hotWallet == address(0)) revert HotWalletIsZero();
        if (c.hotWallet == deployer) revert DeployerIsHotWallet();

        if (c.existingAdmin != address(0)) {
            // The check the Guardian contract itself cannot make.
            if (c.existingAdmin.code.length == 0) revert AdminNotAContract(c.existingAdmin);
            if (c.existingAdmin == c.hotWallet) revert HotWalletHoldsGovernanceRole(c.hotWallet);
            admin = c.existingAdmin;
        } else {
            if (c.timelockDelay < MIN_TIMELOCK_DELAY) {
                revert TimelockDelayTooShort(c.timelockDelay, MIN_TIMELOCK_DELAY);
            }
            if (c.proposers.length == 0) revert NoProposers();
            if (c.executors.length == 0) revert NoExecutors();
            for (uint256 i; i < c.proposers.length; ++i) {
                if (c.proposers[i] == c.hotWallet) revert HotWalletHoldsGovernanceRole(c.hotWallet);
            }
            for (uint256 i; i < c.executors.length; ++i) {
                if (c.executors[i] == c.hotWallet) revert HotWalletHoldsGovernanceRole(c.hotWallet);
            }
            // admin = address(0): the timelock administers itself, so changes
            // to it go through its own delay rather than a deployer backdoor.
            admin = address(new TimelockController(c.timelockDelay, c.proposers, c.executors, address(0)));
        }

        // Bootstrap as the temporary admin, then hand over and step down.
        guardian = new Guardian(deployer);
        guardian.grantRole(guardian.PAUSER_ROLE(), c.hotWallet);
        for (uint256 i; i < c.targets.length; ++i) {
            guardian.registerTarget(c.targets[i]);
        }
        guardian.grantRole(guardian.DEFAULT_ADMIN_ROLE(), admin);
        guardian.renounceRole(guardian.DEFAULT_ADMIN_ROLE(), deployer);

        _verify(guardian, admin, c, deployer);
    }

    /// Re-reads the resulting on-chain state and reverts if any promised
    /// property is missing — so a script bug can't ship a weaker setup.
    function _verify(Guardian g, address admin, Config memory c, address deployer) internal view {
        bytes32 adminRole = g.DEFAULT_ADMIN_ROLE();
        bytes32 pauserRole = g.PAUSER_ROLE();
        if (admin.code.length == 0) revert PostconditionFailed("admin has no code");
        if (!g.hasRole(adminRole, admin)) revert PostconditionFailed("admin lacks DEFAULT_ADMIN_ROLE");
        if (g.hasRole(adminRole, deployer)) revert PostconditionFailed("deployer still admin");
        if (g.hasRole(adminRole, c.hotWallet)) revert PostconditionFailed("hot wallet is admin");
        if (!g.hasRole(pauserRole, c.hotWallet)) revert PostconditionFailed("hot wallet lacks PAUSER_ROLE");
        if (g.hasRole(pauserRole, admin)) revert PostconditionFailed("admin holds PAUSER_ROLE");
        if (g.hasRole(pauserRole, deployer)) revert PostconditionFailed("deployer holds PAUSER_ROLE");
        for (uint256 i; i < c.targets.length; ++i) {
            if (!g.registeredTargets(c.targets[i])) revert PostconditionFailed("target not registered");
        }
    }
}

/// @notice Entry point: configuration comes from the environment so no
/// secret or address is committed. See `docs/INTEGRATION.md`.
///
///   GUARDIAN_HOT_WALLET      address   (required)
///   GUARDIAN_TARGETS         address[] comma-separated (required)
///   GUARDIAN_EXISTING_ADMIN  address   existing timelock/multisig (optional)
///   GUARDIAN_PROPOSERS       address[] (if no existing admin)
///   GUARDIAN_EXECUTORS       address[] (if no existing admin)
///   GUARDIAN_TIMELOCK_DELAY  seconds   (if no existing admin)
///
///   forge script script/DeployGuardian.sol --rpc-url $RPC --account <keystore> --broadcast
contract DeployGuardian is Script, DeployGuardianBase {
    function run() external returns (Guardian guardian, address admin) {
        Config memory c;
        c.hotWallet = vm.envAddress("GUARDIAN_HOT_WALLET");
        c.targets = vm.envAddress("GUARDIAN_TARGETS", ",");
        c.existingAdmin = vm.envOr("GUARDIAN_EXISTING_ADMIN", address(0));
        if (c.existingAdmin == address(0)) {
            c.proposers = vm.envAddress("GUARDIAN_PROPOSERS", ",");
            c.executors = vm.envAddress("GUARDIAN_EXECUTORS", ",");
            c.timelockDelay = vm.envUint("GUARDIAN_TIMELOCK_DELAY");
        }

        vm.startBroadcast();
        // With `--account`/`--private-key`, the broadcaster is `msg.sender`
        // of every call below; `tx.origin` is that account.
        (guardian, admin) = _deployGuardian(c, tx.origin);
        vm.stopBroadcast();

        console2.log("Guardian:", address(guardian));
        console2.log("Admin (timelock/multisig):", admin);
    }
}
