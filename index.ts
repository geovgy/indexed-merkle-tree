export interface IMTNode {
  key: bigint;
  nextIdx: number;
  nextKey: bigint;
  value: bigint;
}

export interface IMTProof {
  leafIdx: number;
  leaf: IMTNode;
  root: bigint;
  siblings: bigint[];
}

export interface IMTInsertionProof {
  ogLeafIdx: number;
  ogLeafKey: bigint;
  ogLeafNextIdx: number;
  ogLeafNextKey: bigint;
  ogLeafValue: bigint;
  newLeafIdx: number;
  newLeafKey: bigint;
  newLeafValue: bigint;
  rootBefore: bigint;
  rootAfter: bigint;
  siblingsBefore: bigint[];
  siblingsAfterOg: bigint[];
  siblingsAfterNew: bigint[];
}

export interface IMTBatchInsertionProof {
  rootBefore: bigint;
  rootAfter: bigint;
  insertionIdx: number;
  emptySubtreeRoot: bigint;
  emptySubtreeSiblings: bigint[];
  ogLeaves: IMTProof[]; // Proof of existing leaves to be updated before the batch insertion
  prevLeaves: IMTProof[]; // Proof of updated leaves after each insertion (low nullifiers)
  newLeaves: IMTProof[]; // Proof of new leaves after each insertion
}

export class IndexedMerkleTree {
  root: bigint;
  nodes: IMTNode[] = [];
  hasher: (args: bigint[]) => bigint;

  constructor(hasher: (args: bigint[]) => bigint) {
    // Always initialize with a zero item for exclusion proofs below the first item
    this.nodes = [{ key: 0n, nextIdx: 0, nextKey: 0n, value: 0n }];
    this.hasher = hasher;
    this.root = this.hasher([0n, 0n, 0n, 0n]);
  }

  insert(key: bigint, value: bigint): IMTInsertionProof {
    const { nodes } = this;
    if (typeof key !== 'bigint' || key < 1n) throw new Error('invalid_key');
    if (typeof value !== 'bigint' || value < 0n) throw new Error('invalid_value');
    if (nodes.find(x => x.key === key)) throw new Error('duplicate_key');

    // Find previous key
    let prevKey = 0n;
    let prevIdx = 0;
    for (let i = 1; i < nodes.length; i++) {
      if (nodes[i].key < key && nodes[i].key > prevKey) {
        prevKey = nodes[i].key;
        prevIdx = i;
        // Doesn't get any closer
        if (nodes[i].key + 1n === key) break;
      }
    }

    const exProof = this.generateProof(prevKey);

    nodes.push({
      key,
      nextIdx: nodes[prevIdx].nextIdx,
      nextKey: nodes[prevIdx].nextKey,
      value,
    });
    nodes[prevIdx].nextKey = key;
    nodes[prevIdx].nextIdx = nodes.length - 1;

    const newItemProof = this.generateProof(key);
    const updatedPrevProof = this.generateProof(prevKey);

    this.root = newItemProof.root;

    return {
      ogLeafIdx: exProof.leafIdx,
      ogLeafKey: exProof.leaf.key,
      ogLeafNextIdx: exProof.leaf.nextIdx,
      ogLeafNextKey: exProof.leaf.nextKey,
      ogLeafValue: exProof.leaf.value,
      newLeafIdx: newItemProof.leafIdx,
      newLeafKey: newItemProof.leaf.key,
      newLeafValue: newItemProof.leaf.value,
      rootBefore: exProof.root,
      rootAfter: newItemProof.root,
      siblingsBefore: exProof.siblings,
      siblingsAfterOg: updatedPrevProof.siblings,
      siblingsAfterNew: newItemProof.siblings,
    };
  }

  insertBatch(keyValues: { key: bigint, value: bigint }[]): IMTBatchInsertionProof {
    if (keyValues.length === 0) throw new Error('no_key_values');
    const { nodes } = this;

    const insertionIdx = nodes.length;

    // Get empty subtree root

    // Get depth of subtree that fits all the key values
    const subtreeDepth = 1 << Math.ceil(Math.log2(keyValues.length));
    if (subtreeDepth > 254) throw new Error('depth_too_large');

    // Create empty subtree with depth
    const ZERO_LEAF = this.hasher([0n, 0n, 0n, 0n]);
    let level = Array(subtreeDepth).fill(ZERO_LEAF);

    while (level.length > 1) {
      const nextLevel: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        nextLevel.push(this.hasher([level[i], level[i + 1]]));
      }
      level = nextLevel; // ascend one level
    }
    const emptySubtreeRoot = level[0];

    const leaves = nodes.map(x => this.hasher([x.key, BigInt(x.nextIdx), x.nextKey, x.value]));

    // Pad to the next power-of-two with an explicit zero-leaf
    const size = 1 << Math.ceil(Math.log2(leaves.length));
    const subtreeDepthInLevels = Math.ceil(Math.log2(subtreeDepth));
    const idx = leaves.length >> subtreeDepthInLevels;
    while (leaves.length < size) leaves.push(ZERO_LEAF);

    const siblings: bigint[] = [];
    let idxAtLevel = idx;
    level = leaves;

    while (level.length > 1) {
      // flip the low bit instead of calculating left or right side of pair
      const sibIdx = idxAtLevel ^ 1;
      if (sibIdx < level.length) siblings.push(level[sibIdx]);

      const nextLevel: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        nextLevel.push(this.hasher([level[i], level[i + 1]]));
      }

      idxAtLevel >>= 1; // parent index
      level = nextLevel; // ascend one level
    }

    const prevRoot = level[0];

    const newNodes = [
      ...nodes,
      ...keyValues.map(x => ({
        key: x.key,
        nextIdx: nodes.length,
        nextKey: 0n,
        value: x.value,
      }))
    ];

    const ogLeaves: IMTProof[] = [];

    // Get original nodes that will be updated before the batch insertion
    for (const { key, value } of keyValues) {
      if (key < 1n) throw new Error('invalid_key');
      if (value < 0n) throw new Error('invalid_value');
      if (nodes.find(x => x.key === key)) throw new Error('duplicate_key');
  
      // Find previous key
      let prevKey = 0n;
      let prevIdx = 0;
      for (let i = 1; i < newNodes.length; i++) {
        if (newNodes[i].key < key && newNodes[i].key > prevKey) {
          prevKey = newNodes[i].key;
          prevIdx = i;
          // Doesn't get any closer
          if (newNodes[i].key + 1n === key) break;
        }
      }

      if (prevIdx < insertionIdx) {
        ogLeaves.push(this.generateProof(prevKey));
      }
    }

    let newItemProofs: IMTProof[] = [];
    let updatedPrevProofs: IMTProof[] = [];

    for (const { key, value } of keyValues) {
      if (key < 1n) throw new Error('invalid_key');
      if (value < 0n) throw new Error('invalid_value');
      if (nodes.find(x => x.key === key)) throw new Error('duplicate_key');
  
      // Find previous key
      let prevKey = 0n;
      let prevIdx = 0;
      for (let i = 1; i < nodes.length; i++) {
        if (nodes[i].key < key && nodes[i].key > prevKey) {
          prevKey = nodes[i].key;
          prevIdx = i;
          // Doesn't get any closer
          if (nodes[i].key + 1n === key) break;
        }
      }

      nodes.push({
        key,
        nextIdx: nodes[prevIdx].nextIdx,
        nextKey: nodes[prevIdx].nextKey,
        value,
      });
      nodes[prevIdx].nextKey = key;
      nodes[prevIdx].nextIdx = nodes.length - 1;
  
      newItemProofs.push(this.generateProof(key));
      updatedPrevProofs.push(this.generateProof(prevKey));
    }

    // Update the root
    const newRoot = newItemProofs[newItemProofs.length - 1].root;
    this.root = newRoot;

    return {
      rootBefore: prevRoot,
      rootAfter: newRoot,
      emptySubtreeSiblings: siblings,
      emptySubtreeRoot,
      insertionIdx,
      ogLeaves,
      prevLeaves: updatedPrevProofs,
      newLeaves: newItemProofs,
    }
  }

  generateProof(key: bigint): IMTProof {
    const { nodes } = this;
    const idx = nodes.findIndex(x => x.key === key)
    if (idx < 0) throw new Error('invalid_key');

    const leaves = nodes.map(x => this.hasher([x.key, BigInt(x.nextIdx), x.nextKey, x.value]));

    // Pad to the next power-of-two with an explicit zero-leaf
    const ZERO_LEAF = this.hasher([0n, 0n, 0n, 0n]);
    const size = 1 << Math.ceil(Math.log2(leaves.length));
    while (leaves.length < size) leaves.push(ZERO_LEAF);

    const siblings: bigint[] = [];
    let idxAtLevel = idx;
    let level = leaves;

    while (level.length > 1) {
      // flip the low bit instead of calculating left or right side of pair
      const sibIdx = idxAtLevel ^ 1;
      if (sibIdx < level.length) siblings.push(level[sibIdx]);

      const nextLevel: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        nextLevel.push(this.hasher([level[i], level[i + 1]]));
      }

      idxAtLevel >>= 1; // parent index
      level = nextLevel; // ascend one level
    }

    return {
      leafIdx: idx,
      leaf: { ...nodes[idx] }, // copy the leaf instead of passing reference
      root: level[0],
      siblings,
    }
  }

  generateExclusionProof(key: bigint): IMTProof | undefined {
    const { nodes } = this;
    if (typeof key !== 'bigint' || key < 1n) throw new Error('invalid_key');
    for (let i = 0; i < nodes.length; i++) {
      if (nodes[i].key === key) {
        throw new Error('key_exists');
      } else if (nodes[i].key < key && (nodes[i].nextKey > key || nodes[i].nextKey === 0n)) {
        return this.generateProof(nodes[i].key);
      }
    }
  }

  verifyProof(proof: IMTProof): boolean {
    let hash = this.hasher([
      proof.leaf.key,
      BigInt(proof.leaf.nextIdx),
      proof.leaf.nextKey,
      proof.leaf.value
    ]);
    let idx = proof.leafIdx;

    for (const sib of proof.siblings) {
      hash = this.hasher((idx & 1) === 0 ? [hash, sib] : [sib, hash]);
      idx >>= 1;
    }

    return hash === proof.root;
  }

  verifyInsertionProof({
    ogLeafIdx, ogLeafKey, ogLeafNextIdx, ogLeafNextKey, ogLeafValue,
    newLeafIdx, newLeafKey, newLeafValue, rootBefore, rootAfter,
    siblingsBefore, siblingsAfterOg, siblingsAfterNew,
  }: IMTInsertionProof): boolean {
    // 1) All three proofs must be individually valid
    if (
      !this.verifyProof({
        leafIdx: ogLeafIdx,
        leaf: {
          key: ogLeafKey,
          nextIdx: ogLeafNextIdx,
          nextKey: ogLeafNextKey,
          value: ogLeafValue,
        },
        root: rootBefore,
        siblings: siblingsBefore,
      }) ||
      !this.verifyProof({
        leafIdx: newLeafIdx,
        leaf: {
          key: newLeafKey,
          nextIdx: ogLeafNextIdx,
          nextKey: ogLeafNextKey,
          value: newLeafValue,
        },
        root: rootAfter,
        siblings: siblingsAfterNew,
      }) ||
      !this.verifyProof({
        leafIdx: ogLeafIdx,
        leaf: {
          key: ogLeafKey,
          nextIdx: newLeafIdx,
          nextKey: newLeafKey,
          value: ogLeafValue,
        },
        root: rootAfter,
        siblings: siblingsAfterOg,
      })
    ) {
      return false;
    }

    // 2) The "after" proofs must have equal length
    if (siblingsAfterNew.length !== siblingsAfterOg.length) {
      return false;
    }
    //    And the "before" proof’s length must be either the same (no height change)
    //    or exactly one less (height grew by 1, e.g. first insertion or crossing a power‐of‐two).
    if (
      !(
        siblingsBefore.length === siblingsAfterNew.length ||
        siblingsBefore.length + 1 === siblingsAfterNew.length
      )
    ) {
      return false;
    }

    // 3) Find the first level at which the predecessor’s proof changed
    let diffIdx = -1;
    for (let i = 0; i < siblingsAfterNew.length; i++) {
      const before = siblingsBefore[i];
      const after = siblingsAfterOg[i];
      if (before !== after) {
        diffIdx = i;
        break;
      }
    }
    // We must see exactly one "first" change
    if (diffIdx < 0) {
      return false;
    }
    // And ensure nothing *before* that level changed
    for (let i = 0; i < diffIdx; i++) {
      if (siblingsBefore[i] !== siblingsAfterOg[i]) {
        return false;
      }
    }

    // 4) Now recompute the "sub‐root" of the new leaf up to diffIdx, and
    //    check it matches the sibling that was injected into the prev-proof.
    let hash = this.hasher([
      newLeafKey,
      BigInt(ogLeafNextIdx),
      ogLeafNextKey,
      newLeafValue
    ]);
    let idx = newLeafIdx;

    for (let lvl = 0; lvl < diffIdx; lvl++) {
      const sib = siblingsAfterNew[lvl];
      if ((idx & 1) === 0) {
        hash = this.hasher([hash, sib]);
      } else {
        hash = this.hasher([sib, hash]);
      }
      idx >>= 1;
    }

    // That must be exactly the "new" sibling in the updated-prev proof
    return hash === siblingsAfterOg[diffIdx];
  }

  verifyBatchInsertionProof(proof: IMTBatchInsertionProof): boolean {
    const {
      rootBefore,
      rootAfter,
      insertionIdx,
      emptySubtreeRoot,
      emptySubtreeSiblings,
      ogLeaves,
      prevLeaves,
      newLeaves,
    } = proof;

    // // 1) Verify that the empty subtree exists at the insertion location
    // // Get the depth of the empty subtree from the number of leaves being inserted
    // const subtreeDepth = 1 << Math.ceil(Math.log2(newLeaves.length));
    // const subtreeDepthInLevels = Math.ceil(Math.log2(subtreeDepth));
    
    // // Calculate the position in the merkle tree at the subtree level
    // const idx = insertionIdx >> subtreeDepthInLevels;
    
    // // Reconstruct the tree using the empty subtree root and the siblings to verify
    // // that it's at the correct position in the tree and matches rootBefore
    // let hash = emptySubtreeRoot;
    // let idxAtLevel = idx;

    // for (const sib of emptySubtreeSiblings) {
    //   hash = this.hasher((idxAtLevel & 1) === 0 ? [hash, sib] : [sib, hash]);
    //   idxAtLevel >>= 1;
    // }

    // console.log('hash:', hash);
    // console.log('rootBefore:', rootBefore);

    // if (hash !== rootBefore) {
    //   return false;
    // }

    // 2) Verify that all the existing leaves that need updating have valid proofs
    // These proofs should be from the tree before any insertions
    for (const ogLeaf of ogLeaves) {
      if (!this.verifyProof(ogLeaf) || ogLeaf.root !== rootBefore || ogLeaf.leafIdx >= insertionIdx) {
        return false;
      }
    }

    // 3) Verify that after each insertion, the low nullifier (previous leaf) 
    // and new leaf have valid membership proofs
    if (prevLeaves.length !== newLeaves.length) {
      return false;
    }

    for (let i = 0; i < prevLeaves.length; i++) {
      // Each new leaf should have a valid membership proof at its insertion index
      if (!this.verifyProof(newLeaves[i])) {
        return false;
      }

      // Each updated previous leaf (low nullifier) should have a valid membership proof
      if (!this.verifyProof(prevLeaves[i])) {
        return false;
      }

      // Each new leaf should be at the correct insertion index
      if (newLeaves[i].leafIdx !== insertionIdx + i) {
        return false;
      }

      if (newLeaves[i].leaf.key !== prevLeaves[i].leaf.nextKey || newLeaves[i].leafIdx !== prevLeaves[i].leaf.nextIdx) {
        return false;
      }

      // Find ogLeaf that corresponds to the previous leaf
      if (prevLeaves[i].leafIdx < insertionIdx) {
        const ogLeaf = ogLeaves.find(x => x.leafIdx === prevLeaves[i].leafIdx);
        if (
          !ogLeaf ||
          ogLeaf.leaf.key !== prevLeaves[i].leaf.key ||
          (ogLeaf.leaf.nextKey < prevLeaves[i].leaf.nextKey && ogLeaf.leaf.nextKey !== 0n) ||
          ogLeaf.leaf.value !== prevLeaves[i].leaf.value
        ) {
          return false;
        }
      }
    }

    // 4) Verify that the final root from the last insertion matches rootAfter
    if (newLeaves.length > 0 && newLeaves[newLeaves.length - 1].root !== rootAfter) {
      return false;
    }

    return true;
  }
}
