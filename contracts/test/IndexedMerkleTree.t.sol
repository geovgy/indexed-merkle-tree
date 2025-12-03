// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {IndexedMerkleTree, IndexedMerkleTreeLib} from "../src/IndexedMerkleTree.sol";

contract IndexedMerkleTreeTest is Test {
    using IndexedMerkleTreeLib for IndexedMerkleTree;

    IndexedMerkleTree internal tree;

    function test_insert() public {
        tree.insert(1, 1);
        assertEq(tree.root, 3358742217282686339971543825983684697129123898497160683024532050074432897246);
    }
}
