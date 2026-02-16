// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SNARK_SCALAR_FIELD} from "./Constants.sol";
import {UD60x18, ud} from "prb-math/UD60x18.sol";
import {IPoseidon2} from "poseidon2-evm/IPoseidon2.sol";

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
    IPoseidon2 poseidon2;
}

library IndexedMerkleTreeLib {
    uint256 constant ZERO_LEAF = 14809712463008457233891043966654826926909229366582488672652099303846753427764;

    /**
     * @notice Initialize the indexed merkle tree
     * @dev This function initializes the tree with the given depth. It must be called before inserting any nodes.
     * @param self The indexed merkle tree
     * @param poseidon2 The poseidon2 contract address
     * @param depth The depth of the tree
     */
    function init(IndexedMerkleTree storage self, address poseidon2, uint256 depth) internal {
        self.nodes[0] = Node({
            key: 0,
            nextIdx: 0,
            nextKey: 0,
            value: 0
        });
        self.leaves[0] = ZERO_LEAF;
        self.numOfLeaves = 1;
        self.poseidon2 = IPoseidon2(poseidon2);

        self.root = ZERO_LEAF;
        self.depth = depth;
    }


    /**
     * @notice Insert a new node into the tree
     * @dev This function loops through the tree to find and update the previous node.
     * @param self The indexed merkle tree
     * @param key The key of the new node
     * @param value The value of the new node
     */
    function insert(IndexedMerkleTree storage self, uint256 key, uint256 value) internal returns (uint256) {
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

        Node memory prevNode = self.nodes[prevIdx];
        
        prevNode.nextKey = key;
        prevNode.nextIdx = self.numOfLeaves;
        self.nodes[prevIdx] = prevNode;

        uint256 prevLeaf = self.poseidon2.hash_4(prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value);
        uint256 newLeaf = self.poseidon2.hash_4(key, nextIdx, nextKey, value);
        
        self.leaves[prevIdx] = prevLeaf;
        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.numOfLeaves++;

        uint256 newRoot = calculateRoot(self);

        self.root = newRoot;

        return newRoot;
    }

    /**
     * @notice Insert a new node into the tree at a specific index
     * @dev This function requires the index of the previous node to be provided. It is a more efficient version of `insert` when the previous node is known.
     * @param self The indexed merkle tree
     * @param prevIdx The index of the previous node to insert the new node after
     * @param key The key of the new node
     * @param value The value of the new node
     */
    function insertAt(IndexedMerkleTree storage self, uint256 prevIdx, uint256 key, uint256 value) internal returns (uint256) {
        require(self.root != 0, "IndexedMerkleTree: tree must be initialized");
        require(key <= SNARK_SCALAR_FIELD, "IndexedMerkleTree: key cannot be greater than SNARK_SCALAR_FIELD");
        require(value <= SNARK_SCALAR_FIELD, "IndexedMerkleTree: value cannot be greater than SNARK_SCALAR_FIELD");

        Node memory prevNode = self.nodes[prevIdx];
        require(prevIdx < self.numOfLeaves, "IndexedMerkleTree: previous index must be less than the number of leaves");
        require(prevNode.key < key, "IndexedMerkleTree: new node key must be greater than previous node key");
        require(prevNode.nextKey > key || prevNode.nextKey == 0, "IndexedMerkleTree: new node next key must be greater than previous node next key or be 0");

        uint256 nextIdx = prevNode.nextIdx;
        uint256 nextKey = prevNode.nextKey;
        
        self.nodes[self.numOfLeaves] = Node({
            key: key,
            nextIdx: nextIdx,
            nextKey: nextKey,
            value: value
        });
        
        prevNode.nextKey = key;
        prevNode.nextIdx = self.numOfLeaves;
        self.nodes[prevIdx] = prevNode;

        uint256 prevLeaf = self.poseidon2.hash_4(prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value);
        uint256 newLeaf = self.poseidon2.hash_4(key, nextIdx, nextKey, value);
        
        self.leaves[prevIdx] = prevLeaf;
        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.numOfLeaves++;

        uint256 newRoot = calculateRoot(self);

        self.root = newRoot;

        return newRoot;
    }

    /**
     * @notice Batch insert nodes into the tree
     * @dev The indices, updatedNodes and newNodes must have the same length.
     * This function assumes implementation will verify the batch insertion with a proof or other constraints.
     * @param self The indexed merkle tree
     * @param prevIdxs The indices of the previous nodes to new nodes to be inserted after
     * @param newNodes The new nodes to insert
     */
    function insertBatch(
        IndexedMerkleTree storage self, 
        uint256[] memory prevIdxs,
        Node[] memory newNodes
    ) internal returns (uint256 newRoot, uint256[] memory prevLeaves, uint256[] memory newLeaves) {
        require(self.root != 0, "IndexedMerkleTree: tree must be initialized");
        require(newNodes.length == prevIdxs.length, "IndexedMerkleTree: new nodes and prev indices must have the same length");
        require(newNodes.length % 2 == 0, "IndexedMerkleTree: new nodes must have an even number of elements");
        
        uint256 newNumberOfLeaves = self.numOfLeaves + newNodes.length;
        require(newNumberOfLeaves <= 2 ** self.depth, "IndexedMerkleTree: new number of leaves cannot be greater than 2 ** depth");

        prevLeaves = new uint256[](newNodes.length);
        newLeaves = new uint256[](newNodes.length);
        
        for (uint256 i = 0; i < newNodes.length; i++) {
            uint256 idx = self.numOfLeaves + i;
            Node memory prevNode;
            if (prevIdxs[i] < self.numOfLeaves) {
                prevNode = self.nodes[prevIdxs[i]];

                require(prevNode.key < newNodes[i].key, "IndexedMerkleTree: new node key must be greater than previous node key");
                require(prevNode.nextKey > newNodes[i].key || prevNode.nextKey == 0, "IndexedMerkleTree: new node next key must be greater than previous node next key or be 0");

                prevNode.nextKey = newNodes[i].key;
                prevNode.nextIdx = idx;

                self.nodes[prevIdxs[i]] = prevNode;
                self.leaves[prevIdxs[i]] = self.poseidon2.hash_4(prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value);
            } else {
                prevNode = newNodes[prevIdxs[i] - self.numOfLeaves];
                require(prevNode.key < newNodes[i].key, "IndexedMerkleTree: new node key must be greater than previous pending node key");
                require(prevNode.nextKey == newNodes[i].key && prevNode.nextIdx == idx, "IndexedMerkleTree: new node next key and idx must be the same as the previous node");
            }

            require(newNodes[i].nextIdx < newNumberOfLeaves, "IndexedMerkleTree: next idx cannot be greater than new number of leaves");

            self.nodes[idx] = newNodes[i];
            self.leaves[idx] = self.poseidon2.hash_4(newNodes[i].key, newNodes[i].nextIdx, newNodes[i].nextKey, newNodes[i].value);

            prevLeaves[i] = self.leaves[prevIdxs[i]];
            newLeaves[i] = self.leaves[idx];
        }

        self.numOfLeaves = newNumberOfLeaves;
        self.root = calculateRoot(self);
        newRoot = self.root;
    }

    function calculateRoot(IndexedMerkleTree storage self) internal view returns (uint256) {
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
                nextLevel[i / 2] = self.poseidon2.hash_2(currentLevel[i], currentLevel[i + 1]);
            }
            currentLevel = nextLevel;
        }

        return currentLevel[0]; // return the root
    }
}