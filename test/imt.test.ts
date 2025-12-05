/// <reference types="bun-types" />
import { describe, it } from 'bun:test';
import { ok } from 'node:assert';

import { IndexedMerkleTree } from '../index';
import { poseidonHash } from './helpers';

describe('IndexedMerkleTree', () => {
  it('should generate and verify exclusion proof on empty tree', () => {
    const tree = new IndexedMerkleTree(poseidonHash);

    tree.insert(1n, 1n)
    tree.insert(2n, 2n)
    tree.insert(10n, 20n)
    tree.insert(6n, 10n)

    let proof = tree.generateProof(1n);
    console.log(proof.leaf)

    proof = tree.generateProof(2n);
    console.log(proof.leaf)

    proof = tree.generateProof(10n);
    console.log(proof.leaf)

    proof = tree.generateProof(6n);
    console.log(proof.leaf)

    console.log("Root:", proof.root)

    tree.insert(3n, 3n)
    tree.insert(4n, 4n)
    tree.insert(5n, 5n)
    tree.insert(7n, 7n)

    console.log("Updated leaves:")
    proof = tree.generateProof(1n);
    console.log({...proof.leaf, idx: proof.leafIdx})

    proof = tree.generateProof(2n);
    console.log({...proof.leaf, idx: proof.leafIdx})

    proof = tree.generateProof(10n);
    console.log({...proof.leaf, idx: proof.leafIdx})

    proof = tree.generateProof(6n);
    console.log({...proof.leaf, idx: proof.leafIdx})

    console.log("New leaves:")
    proof = tree.generateProof(3n);
    console.log(proof.leaf)

    proof = tree.generateProof(4n);
    console.log(proof.leaf)

    proof = tree.generateProof(5n);
    console.log(proof.leaf)

    proof = tree.generateProof(7n);
    console.log(proof.leaf)

    console.log("Root:", proof.root)
  });

  it('should generate and verify exclusion proof on empty tree', () => {
    const tree = new IndexedMerkleTree(poseidonHash);

    const exProof = tree.generateExclusionProof(13n);
    
    ok(exProof && tree.verifyProof(exProof));
  });

  for(let size = 2; size <= (Number(process.env.TEST_SIZE) || 10); size++) {
    it(`should generate and verify proof of ${size} items correctly matrix`, () => {
      const tree = new IndexedMerkleTree(poseidonHash);
      for(let i = 1; i < size; i++) {
        const transition = tree.insert(10n * BigInt(i), 123n * BigInt(i));
        ok(tree.verifyInsertionProof(transition));
      }

      for(let i = 1; i < size; i++) {
        // Test that each item can be successfully proved for inclusion
        const proof = tree.generateProof(10n * BigInt(i));
        ok(tree.verifyProof(proof));

        // Test that a missing item doesn't exist slightly beyond each item
        const exProof = tree.generateExclusionProof(10n * BigInt(i) + 3n);
        ok(exProof && tree.verifyProof(exProof));
      }
    });
  }

  it('should generate and verify insertion proof from further leaves', () => {
    const tree = new IndexedMerkleTree(poseidonHash);

    // Insert items such that the test item won't be neigbor to its previous item
    tree.insert(20n, 234n);
    tree.insert(22n, 234n);
    tree.insert(23n, 234n);
    tree.insert(24n, 234n);
    tree.insert(25n, 234n);
    tree.insert(26n, 234n);
    tree.insert(27n, 234n);
    tree.insert(28n, 234n);

    const transition = tree.insert(21n, 123n);

    ok(tree.verifyInsertionProof(transition))
  });
});

