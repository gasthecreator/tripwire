// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Test-only mocks used by the Rust `tripwire-context` integration test, which
/// deploys them to a live anvil node to exercise real historical balance and
/// reserve reads. Not production code and not part of the audited surface.

contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /// Test-only: no allowance check, so a mock "protocol" can pull payment
    /// from a counterparty inside one transaction.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/// Emits Uniswap-V2-style `Sync` events and serves `getReserves`.
contract MockV2Pair {
    uint112 private r0;
    uint112 private r1;

    event Sync(uint112 reserve0, uint112 reserve1);

    function setReserves(uint112 a, uint112 b) external {
        r0 = a;
        r1 = b;
        emit Sync(a, b);
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (r0, r1, uint32(block.timestamp));
    }
}

/// A "protocol" that custodies tokens and ETH, with one function that both
/// drains an asset and moves a pool price in a single transaction — the shape
/// of an oracle-manipulation exploit.
contract MockVault {
    receive() external payable {}

    function drainAndMove(MockERC20 token, address to, uint256 amount, MockV2Pair pair, uint112 a, uint112 b) external {
        token.transfer(to, amount);
        pair.setReserves(a, b);
    }

    /// A trade: sends `amountOut` of `tokenOut` to the counterparty and takes
    /// `amountIn` of `tokenIn` from them, in one transaction.
    function swap(MockERC20 tokenOut, MockERC20 tokenIn, address counterparty, uint256 amountOut, uint256 amountIn)
        external
    {
        tokenOut.transfer(counterparty, amountOut);
        tokenIn.transferFrom(counterparty, address(this), amountIn);
    }

    function drainNative(address payable to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
