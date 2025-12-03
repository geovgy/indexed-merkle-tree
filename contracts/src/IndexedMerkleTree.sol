// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { PoseidonT3 } from "poseidon-solidity/PoseidonT3.sol";
import { PoseidonT5 } from "poseidon-solidity/PoseidonT5.sol";

struct Node {
    uint256 key;
    uint256 nextIdx;
    uint256 nextKey;
    uint256 value;
}

struct IndexedMerkleTree {
    uint256 root;
    mapping(uint256 => Node) nodes;
    mapping(uint256 => uint256) leaves;
    uint256 numOfLeaves;
}

library IndexedMerkleTreeLib {
    uint256 constant ZERO_LEAF = 2351654555892372227640888372176282444150254868378439619268573230312091195718;

    function insert(IndexedMerkleTree storage self, uint256 key, uint256 value) public {
        uint256 prevKey = 0;
        uint256 prevIdx = 0;
        for (uint256 i = 1; i < self.numOfLeaves; i++) {
            if (self.nodes[i].key < key && self.nodes[i].key > prevKey) {
                prevKey = self.nodes[i].key;
                prevIdx = i;
                if (self.nodes[i].key + 1 == key) break;
            }
        }

        uint256 nextIdx = self.nodes[prevIdx].nextIdx;
        uint256 nextKey = self.nodes[prevIdx].nextKey;
        
        uint256 newLeaf = PoseidonT5.hash([key, nextIdx, nextKey, value]);

        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.nodes[self.numOfLeaves].key = key;
        self.nodes[self.numOfLeaves].nextIdx = nextIdx;
        self.nodes[self.numOfLeaves].nextKey = nextKey;
        self.nodes[self.numOfLeaves].value = value;
        
        self.nodes[prevIdx].nextKey = key;
        self.nodes[prevIdx].nextIdx = self.numOfLeaves;
        self.numOfLeaves++;

        self.root = self.root == ZERO_LEAF ? newLeaf : calculateRoot(self);
    }

    function calculateRoot(IndexedMerkleTree storage self) public view returns (uint256) {
        uint256 hash = ZERO_LEAF;

        uint256 size = 1 << (2 ** self.numOfLeaves);

        // Step 2: Create a padded array with existing leaves and ZERO_LEAF padding
        uint256[] memory currentLevel = new uint256[](size);
        for (uint256 i = 0; i < size; i++) {
            if (i < self.numOfLeaves) {
                currentLevel[i] = self.leaves[i];
            } else {
                currentLevel[i] = ZERO_LEAF;
            }
        }

        // Step 3: Build the merkle tree from bottom up
        while (currentLevel.length > 1) {
            uint256[] memory nextLevel = new uint256[](currentLevel.length / 2);
            for (uint256 i = 0; i < currentLevel.length; i += 2) {
                nextLevel[i / 2] = PoseidonT3.hash([currentLevel[i], currentLevel[i + 1]]);
            }
            currentLevel = nextLevel;
        }

        return currentLevel[0];
    }
}