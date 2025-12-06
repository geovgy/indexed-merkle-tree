// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { PoseidonT3 } from "poseidon-solidity/PoseidonT3.sol";
import { PoseidonT5 } from "poseidon-solidity/PoseidonT5.sol";
import { UD60x18, ud } from "prb-math/UD60x18.sol";

struct Node {
    uint256 key;
    uint256 nextIdx;
    uint256 nextKey;
    uint256 value;
}

struct IndexedMerkleTree {
    uint256 root;
    uint256 depth;
    mapping(uint256 => Node) nodes;
    mapping(uint256 => uint256) leaves;
    uint256 numOfLeaves;
}

library IndexedMerkleTreeLib {
    uint256 constant ZERO_LEAF = 2351654555892372227640888372176282444150254868378439619268573230312091195718;

    uint256 constant private SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function init(IndexedMerkleTree storage self, uint256 depth) public {
        require(depth > 0, "IndexedMerkleTree: depth must be greater than 0");
        require(depth <= 254, "IndexedMerkleTree: depth must be less than or equal to 254");

        self.nodes[0] = Node({
            key: 0,
            nextIdx: 0,
            nextKey: 0,
            value: 0
        });
        self.leaves[0] = ZERO_LEAF;
        self.numOfLeaves = 1;
        self.depth = depth;
        self.root = ZERO_LEAF;
    }

    /**
     * @notice Batch insert nodes into the tree
     * @dev The indices, updatedNodes and newNodes must have the same length.
     * This function assumes implementation will verify the batch insertion with a proof or other constraints.
     * @param self The indexed merkle tree
     * @param indices The indices of the nodes to update
     * @param updatedNodes The updated nodes
     * @param newNodes The new nodes to insert
     */
    function insertBatch(
        IndexedMerkleTree storage self, 
        uint256[] memory indices,
        Node[] memory updatedNodes,
        Node[] memory newNodes
    ) public {
        require(self.root != 0, "IndexedMerkleTree: tree must be initialized");
        require(updatedNodes.length == indices.length, "IndexedMerkleTree: updated nodes and indices must have the same length");
        require(newNodes.length % 2 == 0, "IndexedMerkleTree: new nodes must have an even number of elements");
        
        uint256 newNumberOfLeaves = self.numOfLeaves + newNodes.length;
        require(newNumberOfLeaves <= 2 ** self.depth, "IndexedMerkleTree: new number of leaves cannot be greater than 2 ** depth");

        uint256 prevKey = updatedNodes[0].key;
        uint256 prevIdx = indices[0];

        uint256 lastKey = updatedNodes[0].nextKey;
        uint256 lastIdx = updatedNodes[0].nextIdx;
        
        for (uint256 i = 0; i < (newNodes.length > indices.length ? newNodes.length : indices.length); i++) {
            if (i < indices.length) {
                require(indices[i] < self.numOfLeaves, "IndexedMerkleTree: index out of bounds");
                if (i < indices.length - 1) {
                    require(indices[i] < indices[i + 1], "IndexedMerkleTree: indices must be in ascending order");
                }
                Node memory currentNode = self.nodes[indices[i]];
                require(updatedNodes[i].key == currentNode.key && updatedNodes[i].value == currentNode.value, "IndexedMerkleTree: cannot update node with different key or value");
                uint256 updatedLeaf = PoseidonT5.hash([updatedNodes[i].key, updatedNodes[i].nextIdx, updatedNodes[i].nextKey, updatedNodes[i].value]);
                self.nodes[indices[i]] = updatedNodes[i];
                self.leaves[indices[i]] = updatedLeaf;

                if (currentNode.key < prevKey) {
                    prevKey = currentNode.key;
                    prevIdx = indices[i];
                }
                
                if (updatedNodes[i].key >= lastKey && lastKey != 0) {
                    lastKey = updatedNodes[i].nextKey;
                    lastIdx = updatedNodes[i].nextIdx;
                }
            }

            if (i < newNodes.length) {
                require(newNodes[i].nextIdx < newNumberOfLeaves, "IndexedMerkleTree: next idx cannot be greater than new number of leaves");
                uint256 newIdx = self.numOfLeaves + i;
                uint256 newLeaf = PoseidonT5.hash([newNodes[i].key, newNodes[i].nextIdx, newNodes[i].nextKey, newNodes[i].value]);

                self.nodes[newIdx] = newNodes[i];
                self.leaves[newIdx] = newLeaf;

                if (newNodes[i].key < prevKey) {
                    prevKey = newNodes[i].key;
                    prevIdx = newIdx;
                }
                
                if (newNodes[i].key >= lastKey && lastKey != 0) {
                    lastKey = newNodes[i].nextKey;
                    lastIdx = newNodes[i].nextIdx;
                }
            }
        }

        // Validate order of nextKeys and nextIdxs in updated and new nodes
        Node memory node = self.nodes[prevIdx];
        require(node.key == prevKey && node.key < node.nextKey, "IndexedMerkleTree: next key must be greater than previous key");
        uint256 idx = node.nextIdx;

        uint256 batchSize = updatedNodes.length + newNodes.length;
        for (uint256 i = 1; i < batchSize; i++) {
            node = self.nodes[idx];

            if (i == batchSize - 1) {
                require(node.key > prevKey && node.nextKey == lastKey && node.nextIdx == lastIdx, "IndexedMerkleTree: next key and idx must equal last key and idx");
                if (lastKey == 0) {
                    require(node.nextKey == 0 && node.nextIdx == 0, "IndexedMerkleTree: largest key must have next key and idx set to 0");
                }
                break;
            }

            require(node.key > prevKey && node.key < node.nextKey, "IndexedMerkleTree: next key must be greater than previous key");
            prevKey = node.key;
            idx = node.nextIdx;
        }

        self.numOfLeaves = newNumberOfLeaves;
        self.root = calculateRoot(self);
    }

    function insert(IndexedMerkleTree storage self, uint256 key, uint256 value) public {
        require(self.root != 0, "IndexedMerkleTree: tree must be initialized");
        require(key <= SNARK_SCALAR_FIELD, "IndexedMerkleTree: key cannot be greater than SNARK_SCALAR_FIELD");
        require(value <= SNARK_SCALAR_FIELD, "IndexedMerkleTree: value cannot be greater than SNARK_SCALAR_FIELD");

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
        
        self.nodes[self.numOfLeaves] = Node({
            key: key,
            nextIdx: nextIdx,
            nextKey: nextKey,
            value: value
        });
        
        self.nodes[prevIdx].nextKey = key;
        self.nodes[prevIdx].nextIdx = self.numOfLeaves;

        Node memory prevNode = self.nodes[prevIdx];

        uint256 prevLeaf = PoseidonT5.hash([prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value]);
        uint256 newLeaf = PoseidonT5.hash([key, nextIdx, nextKey, value]);
        
        self.leaves[prevIdx] = prevLeaf;
        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.numOfLeaves++;

        self.root = calculateRoot(self);
    }

    function calculateRoot(IndexedMerkleTree storage self) public view returns (uint256) {
        UD60x18 numberOfLeavesUD60x18 = ud(self.numOfLeaves * 1e18);
        uint256 ceilLog2 = numberOfLeavesUD60x18.log2().ceil().unwrap();

        uint256 size = 1 << (ceilLog2 / 1e18);

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

        return currentLevel[0]; // return the root
    }
}