/// <reference types="bun-types" />
import { describe, expect, it } from 'bun:test';
import { ok } from 'node:assert';

import { IndexedMerkleTree } from '../index';
import { poseidonHash } from './helpers';

describe('IndexedMerkleTree', () => {
  it('should generate and verify batch insertion proof', () => {
    const tree = new IndexedMerkleTree(poseidonHash);
    const tree2 = new IndexedMerkleTree(poseidonHash);
    
    // batch insertion
    const proof = tree.insertBatch([{ key: 1n, value: 1n }, { key: 2n, value: 2n }, { key: 3n, value: 3n }]);

    // individual insertions
    const proof2_1 = tree2.insert(1n, 1n);
    const proof2_2 = tree2.insert(2n, 2n);
    const proof2_3 = tree2.insert(3n, 3n);

    const proof2 = tree2.generateProof(3n);

    expect(proof.rootBefore, 'root before should be the same').toEqual(proof2_1.rootBefore);
    expect(proof.rootAfter, 'root after should be the same').toEqual(proof2.root);
    expect(proof.ogLeaves.length, 'og leaves should be empty').toEqual(1);
    expect(proof2_1.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[0].leafIdx);
    expect(proof2_2.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[1].leafIdx);
    expect(proof2_3.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[2].leafIdx);
  });

  it('should generate and verify batch insertion proof after 2nd batch insertion', () => {
    const tree = new IndexedMerkleTree(poseidonHash);
    const tree2 = new IndexedMerkleTree(poseidonHash);
    
    // batch insertion
    tree.insertBatch([{ key: 1n, value: 1n }, { key: 2n, value: 2n }, { key: 3n, value: 3n }, { key: 6n, value: 6n }]);
    const proof = tree.insertBatch([{ key: 4n, value: 4n }, { key: 5n, value: 5n }, { key: 7n, value: 7n }, { key: 8n, value: 8n }]);

    // individual insertions
    tree2.insert(1n, 1n);
    tree2.insert(2n, 2n);
    tree2.insert(3n, 3n);
    tree2.insert(6n, 6n);

    const proof2Pre = tree2.generateProof(6n);

    const proof2_4 = tree2.insert(4n, 4n);
    const proof2_5 = tree2.insert(5n, 5n);
    const proof2_7 = tree2.insert(7n, 7n);
    const proof2_8 = tree2.insert(8n, 8n);

    const proof2 = tree2.generateProof(8n);

    expect(proof.rootBefore, 'root before should be the same').toEqual(proof2Pre.root);
    expect(proof.rootAfter, 'root after should be the same').toEqual(proof2.root);
    expect(proof.ogLeaves.length, 'og leaves should be empty').toEqual(2);
    expect(proof2_4.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[0].leafIdx);
    expect(proof2_5.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[1].leafIdx);
    expect(proof2_7.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[2].leafIdx);
    expect(proof2_8.ogLeafIdx, 'og leaf idx should be the same').toEqual(proof.prevLeaves[3].leafIdx);
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

