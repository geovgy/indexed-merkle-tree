use poseidon;

pub struct IndexedMerkleTree {
    hasher: fn ([Field; 2]) -> Field,
    leaf_hasher: fn ([Field; 4]) -> Field,
}

pub struct IMTProof<let MAX_DEPTH: u32> {
    leafIdx: u32,
    leafKey: Field,
    leafNextIdx: u32,
    leafNextKey: Field,
    leafValue: Field,
    root: Field,
    siblings: [Field; MAX_DEPTH],
}

pub impl<let MAX_DEPTH: u32> IMTProof<MAX_DEPTH> {
    pub fn new(leafIdx: u32, leafKey: Field, leafNextIdx: u32, leafNextKey: Field, leafValue: Field, root: Field, siblings: [Field; MAX_DEPTH]) -> Self {
        Self { leafIdx, leafKey, leafNextIdx, leafNextKey, leafValue, root, siblings }
    }

    pub fn zero() -> Self {
        Self { leafIdx: 0, leafKey: 0, leafNextIdx: 0, leafNextKey: 0, leafValue: 0, root: 0, siblings: [0; MAX_DEPTH] }
    }
}

pub impl IndexedMerkleTree {
    pub fn new(hasher: fn ([Field; 2]) -> Field, leaf_hasher: fn ([Field; 4]) -> Field) -> Self {
        Self { hasher, leaf_hasher }
    }

    pub fn verify_proof<let MAX_DEPTH: u32>(
        self,
        leafIdx: u32,
        leafKey: Field,
        leafNextIdx: u32,
        leafNextKey: Field,
        leafValue: Field,
        root: Field,
        siblings: [Field; MAX_DEPTH]
    ) {
        let mut hash = (self.leaf_hasher)([
            leafKey, leafNextIdx as Field, leafNextKey, leafValue
        ]);
        let mut idx = leafIdx;
        for i in 0..MAX_DEPTH {
            if siblings[i] != 0 {
                let is_right = ((idx & 1) == 0) as bool;
                let (hash_left, hash_right) = if is_right {
                    (hash, siblings[i])
                } else {
                    (siblings[i], hash)
                };
                hash = (self.hasher)([hash_left, hash_right]);
                idx >>= 1;
            }
        };
        assert(hash == root, "indexed merkle tree mismatch root");
    }

    pub fn verify_exclusion_proof<let MAX_DEPTH: u32>(
        self,
        leafIdx: u32,
        leafKey: Field,
        leafNextIdx: u32,
        leafNextKey: Field,
        leafValue: Field,
        root: Field,
        siblings: [Field; MAX_DEPTH],
        excludedKey: Field
    ) {
        self.verify_proof(leafIdx, leafKey, leafNextIdx, leafNextKey, leafValue, root, siblings);
        std::field::bn254::assert_gt(excludedKey, leafKey);
        if leafNextIdx > 0 {
            std::field::bn254::assert_lt(excludedKey, leafNextKey);
        }
    }

    pub fn verify_insertion_proof<let MAX_DEPTH: u32>(
        self,
        ogLeafIdx: u32,
        ogLeafKey: Field,
        ogLeafNextIdx: u32,
        ogLeafNextKey: Field,
        ogLeafValue: Field,
        newLeafIdx: u32,
        newLeafKey: Field,
        newLeafValue: Field,
        rootBefore: Field,
        rootAfter: Field,
        siblingsBefore: [Field; MAX_DEPTH],
        siblingsAfterOg: [Field; MAX_DEPTH],
        siblingsAfterNew: [Field; MAX_DEPTH]
    ) {
        // 1) All three proofs must be individually valid
        self.verify_proof(ogLeafIdx, ogLeafKey, ogLeafNextIdx, ogLeafNextKey, ogLeafValue, rootBefore, siblingsBefore);
        self.verify_proof(ogLeafIdx, ogLeafKey, newLeafIdx, newLeafKey, ogLeafValue, rootAfter, siblingsAfterOg);
        self.verify_proof(newLeafIdx, newLeafKey, ogLeafNextIdx, ogLeafNextKey, newLeafValue, rootAfter, siblingsAfterNew);

        // 2) The "after" proofs must have equal length
        let mut siblingsBeforeLen: u32 = MAX_DEPTH + 1;
        let mut siblingsAfterOgLen: u32 = MAX_DEPTH + 1;
        let mut siblingsAfterNewLen: u32 = MAX_DEPTH + 1;
        for i in 0..MAX_DEPTH {
            if (siblingsBeforeLen == MAX_DEPTH + 1) & (siblingsBefore[i] == 0) {
                siblingsBeforeLen = i;
            }
            if (siblingsAfterOgLen == MAX_DEPTH + 1) & (siblingsAfterOg[i] == 0) {
                siblingsAfterOgLen = i;
            }
            if (siblingsAfterNewLen == MAX_DEPTH + 1) & (siblingsAfterNew[i] == 0) {
                siblingsAfterNewLen = i;
            }
        }
        assert(siblingsAfterOgLen == siblingsAfterNewLen, "indexed merkle tree siblings after og length must be equal to siblings after new length");
        //    And the "before" proof's length must be either the same (no height change)
        //    or exactly one less (height grew by 1, e.g. first insertion or crossing a power-of-two).
        assert((siblingsBeforeLen == siblingsAfterNewLen)
            | (siblingsBeforeLen + 1 == siblingsAfterNewLen), "indexed merkle tree siblings before length must be either equal to siblings after new length or one less");

        // 3) Find the first level at which the predecessor's proof changed
        let mut diffIdx = MAX_DEPTH + 1;
        for i in 0..MAX_DEPTH {
            if i < siblingsAfterNewLen {
                if (diffIdx == MAX_DEPTH + 1) & (siblingsBefore[i] != siblingsAfterOg[i]) {
                    diffIdx = i;
                }
            }
        }
        // We must see exactly one "first" change
        assert(diffIdx != MAX_DEPTH + 1, "indexed merkle tree diff index must not be equal to max depth plus one");
        // And ensure nothing *before* that level changed
        for i in 0..MAX_DEPTH {
            if i < diffIdx {
                assert(siblingsBefore[i] == siblingsAfterOg[i], "indexed merkle tree siblings before must be equal to siblings after og");
            }
        }
        // 4) Now recompute the "sub-root" of the new leaf up to diffIdx, and
        //    check it matches the sibling that was injected into the prev-proof.
        let mut hash = (self.leaf_hasher)([
            newLeafKey as Field, ogLeafNextIdx as Field, ogLeafNextKey as Field, newLeafValue
        ]);
        let mut idx = newLeafIdx;
        for i in 0..MAX_DEPTH {
            if i < diffIdx {
                let is_right = ((idx & 1) == 0) as bool;
                let (hash_left, hash_right) = if is_right {
                    (hash, siblingsAfterNew[i])
                } else {
                    (siblingsAfterNew[i], hash)
                };
                hash = (self.hasher)([hash_left, hash_right]);
                idx >>= 1;
            }
        };
        assert(hash == siblingsAfterOg[diffIdx], "indexed merkle tree hash must be equal to siblings after og");
    }

    pub fn verify_batch_insertion_proof<let MAX_DEPTH: u32, let BATCH_SIZE: u32>(
        self,
        rootBefore: Field,
        rootAfter: Field,
        insertionIdx: u32,
        ogLeavesLength: u32,
        ogLeaves: [IMTProof<MAX_DEPTH>; BATCH_SIZE],
        prevLeaves: [IMTProof<MAX_DEPTH>; BATCH_SIZE],
        newLeaves: [IMTProof<MAX_DEPTH>; BATCH_SIZE]
    ) {
        for i in 0..BATCH_SIZE {
            if (i < ogLeavesLength) {
                self.verify_proof(ogLeaves[i].leafIdx, ogLeaves[i].leafKey, ogLeaves[i].leafNextIdx, ogLeaves[i].leafNextKey, ogLeaves[i].leafValue, rootBefore, ogLeaves[i].siblings);
            }
            
            assert(newLeaves[i].leafIdx == insertionIdx + i, "indexed merkle tree new leaves must be at the correct insertion index");
            assert(newLeaves[i].leafKey == prevLeaves[i].leafNextKey, "indexed merkle tree new leaves must be at the correct next key");
            assert(newLeaves[i].leafIdx == prevLeaves[i].leafNextIdx, "indexed merkle tree new leaves must be at the correct next index");
            self.verify_proof(prevLeaves[i].leafIdx, prevLeaves[i].leafKey, prevLeaves[i].leafNextIdx, prevLeaves[i].leafNextKey, prevLeaves[i].leafValue, prevLeaves[i].root, prevLeaves[i].siblings);
            self.verify_proof(newLeaves[i].leafIdx, newLeaves[i].leafKey, newLeaves[i].leafNextIdx, newLeaves[i].leafNextKey, newLeaves[i].leafValue, newLeaves[i].root, newLeaves[i].siblings);

            if (prevLeaves[i].leafIdx < insertionIdx) {
                for j in 0..ogLeavesLength {
                    if (ogLeaves[j].leafIdx == prevLeaves[i].leafIdx) {
                        assert(ogLeaves[j].leafKey == prevLeaves[i].leafKey, "indexed merkle tree og leaves must be at the correct key");
                        assert(ogLeaves[j].leafValue == prevLeaves[i].leafValue, "indexed merkle tree og leaves must be at the correct value");
                        let nextKeyGreater = std::field::bn254::gt(ogLeaves[j].leafNextKey, prevLeaves[i].leafNextKey);
                        assert(nextKeyGreater | (ogLeaves[j].leafNextKey == 0), "indexed merkle tree og leaves must be at the correct next key");
                    }
                }
            } else {
                let mut found = false;
                for j in 0..BATCH_SIZE {
                    if (newLeaves[j].leafIdx == prevLeaves[i].leafIdx) {
                        found = true;
                        assert(newLeaves[j].leafKey == prevLeaves[i].leafKey, "indexed merkle tree new leaves must be at the correct key");
                        assert(newLeaves[j].leafValue == prevLeaves[i].leafValue, "indexed merkle tree new leaves must be at the correct value");
                    }
                }
                assert(found, "indexed merkle tree new leaves must be found");
            }
        }

        assert(newLeaves[BATCH_SIZE - 1].root == rootAfter, "indexed merkle tree new leaves must be at the correct root");
    }
}

#[test]
fn test_verifyProof() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_proof(2, 20, 1, 30, 234, 6668943297883148265098278873555187520846124753710152977795611422562477639299, [
        20759673891506207694606256884301953054087839119850062912178024809139786256525,
        13570217411213457836903525328870830571019970122567943123711413970257955169666,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]);
}

#[test]
fn test_verifyExclusionProof() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_exclusion_proof(
        3, 10, 2, 20, 345,
        6668943297883148265098278873555187520846124753710152977795611422562477639299,
        [
            11135396582441045199900643499438439681601330703827922539252138484042051185631,
            13570217411213457836903525328870830571019970122567943123711413970257955169666,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        13
    );
}

#[test]
fn test_verifyExclusionProofPastEnd() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_exclusion_proof(
        1, 30, 0, 0, 123,
        6668943297883148265098278873555187520846124753710152977795611422562477639299,
        [
            6267760970832874298001165242953505942071048916205419224198468699938087185580,
            21006214261944761893288216955619891277091894074878556242157792523868647089882,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        33
    );
}

#[test]
fn test_verifyInsertionProof() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_insertion_proof(
        3, 30, 0, 0, 369, 4, 40, 492,
        2571980431646512226537973716044286349345455446077442026376592565776796645988,
        2963872233248354362054425041526741667834940426492725195869776079054072427609,
        [
            21811187948234496653038156303271104363293342331973867763419216898445358052835,
            19105469470815259923778736722894778945358156111821148490927046754068671364855,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        [
            21811187948234496653038156303271104363293342331973867763419216898445358052835,
            19105469470815259923778736722894778945358156111821148490927046754068671364855,
            21456886111827427998357836449341111815053179374366685590435429032039554303766,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        [
            2351654555892372227640888372176282444150254868378439619268573230312091195718,
            5723720832300544730179969191054372086051633243972178196193101286943139171509,
            14016517550536154496576705664688405808854048460765765188269560158066581900513,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn test_verifyInsertionProofFirstItem() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_insertion_proof(
        0, 0, 0, 0, 0, 1, 20, 123,
        2351654555892372227640888372176282444150254868378439619268573230312091195718,
        2836217617376693946492933683981112348447133126736576175936789834340647102416,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        [
            13677189860694115563321407223668632702349591673439200765301529399505862844187,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        [
            4664863543816217319864329785007088113268005149371563387080652716301581612820,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn test_verifyBatchInsertionProof() {
    // Values from javascript test case
    let tree = IndexedMerkleTree::new(poseidon::poseidon::bn254::hash_2, poseidon::poseidon::bn254::hash_4);
    tree.verify_batch_insertion_proof(
        2266519907652224567576555671824053080230462294756046239787589048484775378016,
        10708396776289982542595546798766671387780524840717354052618359424096841229959,
        5, 
        2, 
        [
            IMTProof::new(3, 3, 4, 6, 3, 2266519907652224567576555671824053080230462294756046239787589048484775378016, [
                544946495124335692546459146687480981438226633824279789780364603174339284394,
                8217429262630257391548006792862500152430307076319845540244442723670796429390,
                4801561768100218710362407938945934428574819277796801506129223653420176285150,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]),
            IMTProof::new(
                4,
                6,
                0,
                0,
                6,
                2266519907652224567576555671824053080230462294756046239787589048484775378016,
                [
                    2351654555892372227640888372176282444150254868378439619268573230312091195718,
                    5723720832300544730179969191054372086051633243972178196193101286943139171509,
                    14232112274192991853757683252937058705182061969493422132058504309740904777053,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::zero(),
            IMTProof::zero(),
        ],
        [
            IMTProof::new(
                3, 3, 5, 4, 3,
                17276837885963546491402476982915948471347545661210915952523708955116910800470,
                [
                    544946495124335692546459146687480981438226633824279789780364603174339284394,
                    8217429262630257391548006792862500152430307076319845540244442723670796429390,
                    10924779262232093978938331820945335730544540508563154753694042243268022274263,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                5, 4, 6, 5, 4,
                16691828162428923583157654924756405818342331135446208287099312720985541573306,
                [
                    5129206303134517420901380673757132364360340022941787130608976806250985528255,
                    3945025810366145813011593824701930389026776102421355346540546402035704948076,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                4, 6, 7, 7, 6, 
                20960213658204319414303434403022242722234455808871756994244900763419950358959,
                [
                    8289872578347810924697216547128785765038959534030329413351779221753280232742,
                    13811284424381769877184840697199432971063043593054849758210496785674092564888,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                7, 7, 8, 8, 7, 
                10708396776289982542595546798766671387780524840717354052618359424096841229959,
                [
                    14900220987059534818818834676145646887225709939133712019486234485510370263180,
                    20015879878571804031102865652965150208484613371428378070776286655489954740710,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    17019003522808813665526429996127622440706569655695057575442930503797150893393,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
        ],
        [
            IMTProof::new(
                5, 4, 4, 6, 4,
                17276837885963546491402476982915948471347545661210915952523708955116910800470,
                [
                    5129206303134517420901380673757132364360340022941787130608976806250985528255,
                    5723720832300544730179969191054372086051633243972178196193101286943139171509,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                6, 5, 4, 6, 5,
                16691828162428923583157654924756405818342331135446208287099312720985541573306,
                [
                    2351654555892372227640888372176282444150254868378439619268573230312091195718,
                    19496164538490093507159537488801856069955771767207376714568242005076614162757,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                7, 7, 0, 0, 7,
                20960213658204319414303434403022242722234455808871756994244900763419950358959,
                [
                    14900220987059534818818834676145646887225709939133712019486234485510370263180,
                    20015879878571804031102865652965150208484613371428378070776286655489954740710,
                    2621684856842519081464658016377726227144735127428481114828169852346251005214,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
            IMTProof::new(
                8, 8, 0, 0, 8,
                10708396776289982542595546798766671387780524840717354052618359424096841229959,
                [
                    2351654555892372227640888372176282444150254868378439619268573230312091195718,
                    5723720832300544730179969191054372086051633243972178196193101286943139171509,
                    11309814339096351919940246139604847090972801355151585175383805197189788604989,
                    17037153852124567872261949920276207291607981624248046662880732817709969946068,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            ),
        ],
    );
}
