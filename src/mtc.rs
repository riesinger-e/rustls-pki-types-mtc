//! Necessary type to work with [Merkle Tree Certificate](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
//! CAs - they require a more sophisticated setup.

use crate::AlgorithmIdentifier;
use alloc::borrow::{Cow, ToOwned};
use alloc::vec::Vec;
use core::range::RangeInclusive;

macro_rules! oid {
    ( $first:expr, $second:expr, $( $tail:expr ),* ) =>
    (
        [(40 * $first) + $second, $( $tail ),*]
    )
}

pub(crate) use oid;

#[allow(clippy::ptr_arg)]
fn cow_to_static<T>(val: &Cow<'_, T>) -> Cow<'static, T>
where
    T: ToOwned + ?Sized,
    <T as ToOwned>::Owned: Clone,
{
    match val {
        Cow::Borrowed(v) => Cow::Owned((*v).to_owned()),
        Cow::Owned(v) => Cow::Owned((*v).clone()),
    }
}

/// Policy on handling cosignatures
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
pub enum CosignerPolicy {
    /// Only a cosignature by the CA is required
    #[default]
    CaOnly,
    /// A cosignature by all given Cosigners is required
    All,
}

/// Information about a cosigner
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_structs)]
pub struct Cosigner<'a> {
    /// The cosigner ID (relative object identifier)
    pub id: Cow<'a, [u8]>,
    /// The algorithm used for the cosignature
    pub signature_algorithm: AlgorithmIdentifier,
    /// The public key
    pub public_key: Cow<'a, [u8]>,
}

impl Cosigner<'_> {
    /// Yield a `'static` lifetime of the object, allocates.
    pub fn to_owned(&self) -> Cosigner<'static> {
        Cosigner {
            id: cow_to_static(&self.id),
            signature_algorithm: self.signature_algorithm,
            public_key: cow_to_static(&self.public_key),
        }
    }
}

/// MTC hash algorithm, specified by the CA extension
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA256 hash
    Sha256,
}

impl HashAlgorithm {
    /// Return the OID of the corresponding extension
    pub const fn extension_oid(self) -> &'static [u8] {
        static EXT_CA_SHA256_OID: [u8; 8] = oid!(1, 3, 6, 1, 5, 5, 7, 1, 38);

        match self {
            Self::Sha256 => &EXT_CA_SHA256_OID,
        }
    }
}

/// Specify the hash of a trusted subtree for MTCs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hash {
    /// Sha256 hash value
    Sha256([u8; 32]),
}

/// A trusted subtree used for MTC landmark certificates.
/// It's the caller's responsibility to check that the subtree is valid and observed by an appropriate number of cosigners.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TrustedSubtree {
    /// The log number where this subtree is published
    pub log_number: u16,
    /// The subtree hash
    pub hash: Hash,
    /// The start idx of the subtree, max. 2^48 - 1
    pub start: u64,
    /// The end idx of the subtree, max. 2^48 - 1
    pub end: u64,
}

impl TrustedSubtree {
    /// Create new instance.
    /// `start` and `end` may be a maximum of 48 bits --> enforced via `Option`.
    pub fn new(log_number: u16, hash: Hash, start: u64, end: u64) -> Option<Self> {
        const MAX_INDEX: u64 = (1 << 48) - 1;

        if start > MAX_INDEX || end > MAX_INDEX {
            None
        } else {
            Some(Self {
                log_number,
                hash,
                start,
                end,
            })
        }
    }
}

/// Information about an MTC CA
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_structs)]
pub struct MtcCa<'a> {
    /// The hash algorithm used for this MTC CA
    pub hash_algorithm: HashAlgorithm,
    /// The CA ID (= cosigner ID of the CA cosigner)
    pub ca_id: Cow<'a, [u8]>,
    /// The signature algorithm used by the CA in its cosigning capacity
    pub signature_algorithm: Cow<'a, [u8]>,
    /// The revoked serial number ranges for certificates issued by this CA
    pub revoked_ranges: Vec<RangeInclusive<u64>>,
    /// The cosigner policy to use
    pub cosigner_policy: CosignerPolicy,
    /// Any (optional) additional cosigners
    pub additional_cosigners: Vec<Cosigner<'a>>,
    /// Any (optional) trusted subtrees to verify landmark certificates
    pub trusted_subtrees: Vec<TrustedSubtree>,
}

impl MtcCa<'_> {
    /// Yield a `'static` lifetime of the object, allocates.
    pub fn to_owned(&self) -> MtcCa<'static> {
        let additional_cosigners: Vec<Cosigner<'static>> = self
            .additional_cosigners
            .iter()
            .map(Cosigner::to_owned)
            .collect();

        MtcCa::<'static> {
            hash_algorithm: self.hash_algorithm,
            ca_id: cow_to_static(&self.ca_id),
            signature_algorithm: cow_to_static(&self.signature_algorithm),
            revoked_ranges: self.revoked_ranges.clone(),
            cosigner_policy: self.cosigner_policy,
            additional_cosigners,
            trusted_subtrees: self.trusted_subtrees.clone(),
        }
    }
}
