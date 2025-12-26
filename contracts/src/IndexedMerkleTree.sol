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

    /**
     * @notice Initialize the indexed merkle tree
     * @dev This function initializes the tree with the given depth. It must be called before inserting any nodes.
     * @param self The indexed merkle tree
     * @param depth The depth of the tree
     */
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
     * @notice Insert a new node into the tree
     * @dev This function loops through the tree to find and update the previous node.
     * @param self The indexed merkle tree
     * @param key The key of the new node
     * @param value The value of the new node
     */
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

        Node memory prevNode = self.nodes[prevIdx];
        
        prevNode.nextKey = key;
        prevNode.nextIdx = self.numOfLeaves;
        self.nodes[prevIdx] = prevNode;

        uint256 prevLeaf = PoseidonT5.hash([prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value]);
        uint256 newLeaf = PoseidonT5.hash([key, nextIdx, nextKey, value]);
        
        self.leaves[prevIdx] = prevLeaf;
        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.numOfLeaves++;

        self.root = calculateRoot(self);
    }

    /**
     * @notice Insert a new node into the tree at a specific index
     * @dev This function requires the index of the previous node to be provided. It is a more efficient version of `insert` when the previous node is known.
     * @param self The indexed merkle tree
     * @param prevIdx The index of the previous node to insert the new node after
     * @param key The key of the new node
     * @param value The value of the new node
     */
    function insertAt(IndexedMerkleTree storage self, uint256 prevIdx, uint256 key, uint256 value) public {
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

        uint256 prevLeaf = PoseidonT5.hash([prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value]);
        uint256 newLeaf = PoseidonT5.hash([key, nextIdx, nextKey, value]);
        
        self.leaves[prevIdx] = prevLeaf;
        self.leaves[self.numOfLeaves] = newLeaf;
        
        self.numOfLeaves++;

        self.root = calculateRoot(self);
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
    ) public {
        require(self.root != 0, "IndexedMerkleTree: tree must be initialized");
        require(newNodes.length == prevIdxs.length, "IndexedMerkleTree: new nodes and prev indices must have the same length");
        require(newNodes.length % 2 == 0, "IndexedMerkleTree: new nodes must have an even number of elements");
        
        uint256 newNumberOfLeaves = self.numOfLeaves + newNodes.length;
        require(newNumberOfLeaves <= 2 ** self.depth, "IndexedMerkleTree: new number of leaves cannot be greater than 2 ** depth");
        
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
                self.leaves[prevIdxs[i]] = PoseidonT5.hash([prevNode.key, prevNode.nextIdx, prevNode.nextKey, prevNode.value]);
            } else {
                prevNode = newNodes[prevIdxs[i] - self.numOfLeaves];
                require(prevNode.key < newNodes[i].key, "IndexedMerkleTree: new node key must be greater than previous pending node key");
                require(prevNode.nextKey == newNodes[i].key && prevNode.nextIdx == idx, "IndexedMerkleTree: new node next key and idx must be the same as the previous node");
            }

            require(newNodes[i].nextIdx < newNumberOfLeaves, "IndexedMerkleTree: next idx cannot be greater than new number of leaves");

            self.nodes[idx] = newNodes[i];
            self.leaves[idx] = PoseidonT5.hash([newNodes[i].key, newNodes[i].nextIdx, newNodes[i].nextKey, newNodes[i].value]);
        }

        self.numOfLeaves = newNumberOfLeaves;
        self.root = calculateRoot(self);
    }

    /**
     * @notice Calculate the root of the tree
     * @dev This function calculates the root of the tree by padding the leaves and building the tree from bottom up.
     * It is a helper function for `insert`, `insertAt` and `insertBatch`.
     * @param self The indexed merkle tree
     * @return The root of the tree
     */
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