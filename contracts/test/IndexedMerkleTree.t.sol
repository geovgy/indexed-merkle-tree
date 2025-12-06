// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {IndexedMerkleTree, IndexedMerkleTreeLib, Node} from "../src/IndexedMerkleTree.sol";

contract IndexedMerkleTreeTest is Test {
    using IndexedMerkleTreeLib for IndexedMerkleTree;

    IndexedMerkleTree internal tree;
    uint256 internal depth = 32;

    function test_init() public {
        tree.init(depth);
        assertEq(tree.root, 2351654555892372227640888372176282444150254868378439619268573230312091195718);
    }

    function test_insert() public {
        tree.init(depth);

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

    function test_batchInsert() public {
        tree.init(depth);

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;
        Node[] memory updatedNodes = new Node[](1);
        updatedNodes[0] = Node({key: 0, nextIdx: 1, nextKey: 1, value: 0});
        Node[] memory newNodes = new Node[](4);
        newNodes[0] = Node({key: 1, nextIdx: 2, nextKey: 2, value: 1});
        newNodes[1] = Node({key: 2, nextIdx: 4, nextKey: 6, value: 2});
        newNodes[2] = Node({key: 10, nextIdx: 0, nextKey: 0, value: 20});
        newNodes[3] = Node({key: 6, nextIdx: 3, nextKey: 10, value: 10});

        tree.batchInsert(
            indices,
            updatedNodes,
            newNodes
        );

        assertEq(tree.root, 20360384854684935537784946534938679782308351276277208865396381850156490043915);

        // Test a second batch
        uint256[] memory indices2 = new uint256[](2);
        indices2[0] = 2;
        indices2[1] = 4;
        Node[] memory updatedNodes2 = new Node[](2);
        updatedNodes2[0] = Node({key: 2, nextIdx: 5, nextKey: 3, value: 2});
        updatedNodes2[1] = Node({key: 6, nextIdx: 8, nextKey: 7, value: 10});
        Node[] memory newNodes2 = new Node[](4);
        newNodes2[0] = Node({key: 3, nextIdx: 6, nextKey: 4, value: 3});
        newNodes2[1] = Node({key: 4, nextIdx: 7, nextKey: 5, value: 4});
        newNodes2[2] = Node({key: 5, nextIdx: 4, nextKey: 6, value: 5});
        newNodes2[3] = Node({key: 7, nextIdx: 3, nextKey: 10, value: 7});

        tree.batchInsert(
            indices2,
            updatedNodes2,
            newNodes2
        );

        assertEq(tree.root, 19982073930084574996462179059722364487079539793458010442138680107205274677297);
    }
}
