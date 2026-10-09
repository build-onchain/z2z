//! Real owner relations over reconstructed insertion roots; no root admission or backing.
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{Action, Role, validate_pair};
use ziquid_protocol::samechain::tree::{NoteInsertion, NoteTree, root_from_path};
use ziquid_proofs::samechain::{
    MerkleMembership, OwnerWitness, RelationError, decrypt_output,
    verify_owner_relation,
};

#[allow(dead_code)]
#[path = "support/samechain.rs"]
mod support;

// Independent pre-migration framing: literal domains/version, direct SHA256,
// LSB-first ordered siblings. Never calls a production leaf/node/path helper.
fn legacy_root(deployment: &[u8; 32], commitment: &[u8; 32], path: &MerkleMembership) -> [u8; 32] {
    let mut leaf = Sha256::new();
    leaf.update(b"Z2Z_SAMECHAIN_MERKLE_LEAF\0");
    leaf.update(1_u16.to_be_bytes());
    leaf.update(deployment);
    leaf.update(path.tree_id.to_be_bytes());
    leaf.update(path.index.to_be_bytes());
    leaf.update(commitment);
    let mut current: [u8; 32] = leaf.finalize().into();
    for (height, sibling) in path.siblings.iter().enumerate() {
        let mut node = Sha256::new();
        node.update(b"Z2Z_SAMECHAIN_MERKLE_NODE\0");
        node.update(1_u16.to_be_bytes());
        if (path.index >> height) & 1 == 0 {
            node.update(current);
            node.update(sibling);
        } else {
            node.update(sibling);
            node.update(current);
        }
        current = node.finalize().into();
    }
    current
}


fn tree_fill() -> (support::KnownFill, NoteTree, [NoteInsertion; 2]) {
    let mut fill = support::known_fill();
    let deployment = fill.packet.deployment.digest().unwrap();
    let mut tree = NoteTree::new(deployment, 9).unwrap();
    let insertions = [
        tree.append(fill.a.input.commitment().unwrap()).unwrap(),
        tree.append(fill.b.input.commitment().unwrap()).unwrap(),
    ];
    for (owner, insertion) in [&mut fill.a, &mut fill.b].into_iter().zip(insertions) {
        owner.membership = MerkleMembership {
            tree_id: insertion.tree_id, index: insertion.index, siblings: insertion.siblings,
        };
        let descriptor = &mut fill.packet.inputs[owner.role.index()];
        descriptor.root = insertion.root;
        descriptor.tree_id = insertion.tree_id;
        descriptor.index = insertion.index;
    }
    // Later genuine note commitments do not update the captured insertion paths.
    for owner in [&fill.a, &fill.b] {
        for output in &owner.owned_outputs {
            tree.append(output.note.commitment().unwrap()).unwrap();
        }
    }
    support::bind_pair(&mut fill);
    (fill, tree, insertions)
}

fn verify_pair(fill: &support::KnownFill) {
    let a = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    validate_pair(&fill.packet, &a, &b).unwrap();
}

#[test]
fn canonical_path_bytes_match_independent_legacy_sha_at_low_and_high_index_bits() {
    for index in [0, 1, 2, 3, 17, 0x8000_0000, 0x8000_0001, u32::MAX] {
        let path = MerkleMembership {
            tree_id: 0x1234_5678, index,
            siblings: std::array::from_fn(|height| std::array::from_fn(|byte| {
                (height as u8).wrapping_mul(7).wrapping_add(byte as u8)
            })),
        };
        let deployment = [13; 32];
        let commitment = [29; 32];
        let expected = legacy_root(&deployment, &commitment, &path);
        assert_eq!(root_from_path(&deployment, path.tree_id, index, &commitment, &path.siblings), expected);
        assert_eq!(path.root(&deployment, &commitment), expected);
        assert_ne!(legacy_root(&[14; 32], &commitment, &path), expected);
        assert_ne!(legacy_root(&deployment, &[30; 32], &path), expected);
    }
}

#[test]
fn actual_fill_owners_verify_retained_insertion_paths_after_later_note_appends() {
    let (fill, tree, insertions) = tree_fill();
    assert_eq!(tree.count(), 6);
    let mut journals = Vec::new();
    for (owner, insertion) in [&fill.a, &fill.b].into_iter().zip(insertions) {
        let descriptor = &fill.packet.inputs[owner.role.index()];
        let commitment = owner.input.commitment().unwrap();
        assert_eq!(descriptor.commitment, commitment);
        assert_eq!(descriptor.root, insertion.root);
        assert_eq!(insertion.count, u64::from(insertion.index) + 1);
        assert_ne!(descriptor.root, tree.root());
        assert_eq!(legacy_root(&owner.input.deployment_digest, &commitment, &owner.membership), insertion.root);
        let decoded = OwnerWitness::decode(&owner.encode().unwrap()).unwrap();
        let journal = verify_owner_relation(&fill.packet, &decoded).unwrap();
        assert_eq!(journal.action, Action::Fill);
        assert_eq!(journal.role, owner.role);
        assert_eq!(journal.root, insertion.root);
        assert_eq!(journal.tree_id, insertion.tree_id);
        assert_eq!(journal.index, insertion.index);
        assert_eq!(journal.input_commitment, commitment);
        assert_eq!(journal.input_nullifier, owner.input.nullifier().unwrap());
        assert_eq!(journal.terms_commitment, fill.packet.terms_commitment);
        assert_eq!(journal.packet_digest, fill.packet.digest().unwrap());
        journals.push(journal);
        for output in &decoded.owned_outputs {
            assert_eq!(decrypt_output(&fill.packet.outputs[output.manifest_index as usize],
                &output.recovery_key, &decoded.input.deployment_digest, &decoded.input.owner_key).unwrap(),
                output.note);
        }
    }
    validate_pair(&fill.packet, &journals[0], &journals[1]).unwrap();
    assert_eq!(journals[0].role, Role::A);
    assert_eq!(journals[1].role, Role::B);
    assert_ne!(journals[0].root, journals[1].root);
}

#[test]
fn freshly_bound_wrong_path_index_tree_and_root_reach_membership_not_stale_consent() {
    let (baseline, _, _) = tree_fill();
    verify_pair(&baseline);
    for role in [Role::A, Role::B] {
        for mutation in 0..5 {
            let (mut fill, _, _) = tree_fill();
            let owner = match role { Role::A => &mut fill.a, Role::B => &mut fill.b };
            let mut descriptor = fill.packet.inputs[role.index()];
            match mutation {
                0 => owner.membership.siblings[0][0] ^= 1,
                1 => {
                    owner.membership.index ^= 2;
                    descriptor.index = owner.membership.index;
                }
                2 => {
                    owner.membership.tree_id += 1;
                    descriptor.tree_id = owner.membership.tree_id;
                }
                3 => descriptor.root[0] ^= 1,
                _ => {
                    let mut wrong_deployment = owner.input.deployment_digest;
                    wrong_deployment[0] ^= 1;
                    descriptor.root = legacy_root(&wrong_deployment, &descriptor.commitment, &owner.membership);
                }
            }
            // Keep the retained root for index/tree mutations. Recomputing a new
            // descriptor root would merely describe a different supplied tree.
            fill.packet.inputs[role.index()] = descriptor;
            support::bind_pair(&mut fill);
            let (wrong, other) = match role {
                Role::A => (&fill.a, &fill.b), Role::B => (&fill.b, &fill.a),
            };
            assert_eq!(verify_owner_relation(&fill.packet, wrong), Err(RelationError::Membership),
                "freshly signed role {role:?}, mutation {mutation}");
            verify_owner_relation(&fill.packet, other).unwrap();
        }
    }
}
