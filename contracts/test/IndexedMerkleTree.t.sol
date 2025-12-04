// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {IndexedMerkleTree, IndexedMerkleTreeLib} from "../src/IndexedMerkleTree.sol";

contract IndexedMerkleTreeTest is Test {
    using IndexedMerkleTreeLib for IndexedMerkleTree;

    IndexedMerkleTree internal tree;

    function test_init() public {
        tree.init();
        assertEq(tree.root, 2351654555892372227640888372176282444150254868378439619268573230312091195718);
    }

    function test_insert() public {
        tree.init();

        tree.insert(1, 1);
        assertEq(
            tree.root, 
            3358742217282686339971543825983684697129123898497160683024532050074432897246,
            "Invalid root after inserting 1, 1"
        );

        tree.insert(2, 2);
        assertEq(
            tree.root,
            13334063658811196589046618147808085794349663728030588018101259058215191250359,
            "Invalid root after inserting 2, 2"
        );

        tree.insert(10, 20);
        assertEq(
            tree.root,
            19928673215413014298979343016333490279477704763646829418221033082874321637015,
            "Invalid root after inserting 10, 20"
        );

        tree.insert(6, 10);
        assertEq(
            tree.root,
            20360384854684935537784946534938679782308351276277208865396381850156490043915,
            "Invalid root after inserting 6, 10"
        );
    }
}
