// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {IndexedMerkleTree, IndexedMerkleTreeLib, Node} from "../src/IndexedMerkleTreePoseidon2.sol";
import {IPoseidon2} from "poseidon2-evm/IPoseidon2.sol";
import {Poseidon2Yul_BN254 as Poseidon2} from "poseidon2-evm/bn254/yul/Poseidon2Yul.sol";

contract IndexedMerkleTreePoseidon2Test is Test {
    using IndexedMerkleTreeLib for IndexedMerkleTree;

    IndexedMerkleTree internal tree;
    uint256 internal depth = 32;

    address internal poseidon2;

    function setUp() public {
        poseidon2 = address(new Poseidon2());
    }

    function test_init() public {
        tree.init(poseidon2, depth);
        assertEq(tree.root, 14809712463008457233891043966654826926909229366582488672652099303846753427764);
    }

    function test_insert() public {
        tree.init(poseidon2, depth);

        tree.insert(1, 1);
        assertEq(
            tree.root, 
            5948006955847191620113266169163947274965863955231850979523349871769094127865,
            "Invalid root after inserting 1, 1"
        );

        tree.insert(2, 2);
        assertEq(
            tree.root,
            7346610513099268552303281777369545286756370696080196489976943887464027364946,
            "Invalid root after inserting 2, 2"
        );

        tree.insert(10, 20);
        assertEq(
            tree.root,
            15626486357390038552677253029126776088777868323846833361184319210488585481845,
            "Invalid root after inserting 10, 20"
        );

        tree.insert(6, 10);
        assertEq(
            tree.root,
            4007562245710124979459307676238324531117099178390077405621145064161009223005,
            "Invalid root after inserting 6, 10"
        );
    }

    function test_insertAt() public {
        tree.init(poseidon2, depth);

        tree.insertAt(0, 1, 1);
        assertEq(
            tree.root, 
            5948006955847191620113266169163947274965863955231850979523349871769094127865,
            "Invalid root after inserting 1, 1"
        );

        tree.insertAt(1, 2, 2);
        assertEq(
            tree.root,
            7346610513099268552303281777369545286756370696080196489976943887464027364946,
            "Invalid root after inserting 2, 2"
        );

        tree.insertAt(2, 10, 20);
        assertEq(
            tree.root,
            15626486357390038552677253029126776088777868323846833361184319210488585481845,
            "Invalid root after inserting 10, 20"
        );

        tree.insertAt(2, 6, 10);
        assertEq(
            tree.root,
            4007562245710124979459307676238324531117099178390077405621145064161009223005,
            "Invalid root after inserting 6, 10"
        );
    }

    function test_insertBatch() public {
        tree.init(poseidon2, depth);

        uint256[] memory indices = new uint256[](4);
        indices[0] = 0;
        indices[1] = 1;
        indices[2] = 4;
        indices[3] = 2;
        Node[] memory newNodes = new Node[](4);
        newNodes[0] = Node({key: 1, nextIdx: 2, nextKey: 2, value: 1});
        newNodes[1] = Node({key: 2, nextIdx: 4, nextKey: 6, value: 2});
        newNodes[2] = Node({key: 10, nextIdx: 0, nextKey: 0, value: 20});
        newNodes[3] = Node({key: 6, nextIdx: 3, nextKey: 10, value: 10});

        tree.insertBatch(
            indices,
            newNodes
        );
        assertEq(tree.root, 4007562245710124979459307676238324531117099178390077405621145064161009223005);

        // Test a second batch
        uint256[] memory indices2 = new uint256[](4);
        indices2[0] = 2;
        indices2[1] = 5;
        indices2[2] = 6;
        indices2[3] = 4;
        Node[] memory newNodes2 = new Node[](4);
        newNodes2[0] = Node({key: 3, nextIdx: 6, nextKey: 4, value: 3});
        newNodes2[1] = Node({key: 4, nextIdx: 7, nextKey: 5, value: 4});
        newNodes2[2] = Node({key: 5, nextIdx: 4, nextKey: 6, value: 5});
        newNodes2[3] = Node({key: 7, nextIdx: 3, nextKey: 10, value: 7});

        tree.insertBatch(
            indices2,
            newNodes2
        );

        assertEq(tree.root, 19705311447914985772101257786871582525805084815247337973942635193056011735918);
    }
}
