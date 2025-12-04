## IndexedMerkleTree.sol Library

This is a Solidity implementation of the Indexed Merkle Tree using Foundry as the development framework.

### Overview

The `IndexedMerkleTree` library (`src/IndexedMerkleTree.sol`) provides methods to create and manage indexed Merkle trees onchain that can be used alongside the Noir and TypeScript implementations.

*NOTE: The current implementation uses the Poseidon hash. Using a different hash function requires overriding the functions.*

**Key Components:**
- `Node` struct: Stores a key, value, and pointers to the next node in the sequence
- `IndexedMerkleTree` struct: Manages the tree root, node mappings, and leaf cache
- `IndexedMerkleTreeLib` library: Provides initialization, insertion, and root calculation functions

### Installation

```shell
forge install geovgy/indexed-merkle-tree
```

### Implementation

Here's a simple example of how to use the IndexedMerkleTree library:

```solidity
pragma solidity ^0.8.0;

import { IndexedMerkleTree, IndexedMerkleTreeLib } from "indexed-merkle-tree/contracts/IndexedMerkleTree.sol";

contract MyContract {
    using IndexedMerkleTreeLib for IndexedMerkleTree;
    
    IndexedMerkleTree private tree;
    
    constructor() {
        // MUST initialize the tree before use
        tree.init();
    }
    
    function addEntry(uint256 key, uint256 value) public {
        tree.insert(key, value);
    }
    
    function getRoot() public view returns (uint256) {
        return tree.root;
    }
}
```

This contract initializes an indexed merkle tree and provides functions to insert new key-value pairs and retrieve the current merkle root.

### Setup and Building

Run the following commands to compile and test:

```shell
cd contracts
forge build
forge test
```