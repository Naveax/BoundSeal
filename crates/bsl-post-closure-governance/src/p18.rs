use std::collections::{BTreeMap, BTreeSet};

use bsl_lifecycle_governance::LifecycleClosureCertificate;
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    PostClosureAuditChain, PostClosureAuditEvent, PostClosureError, RenewalCertificate,
    SuccessionCertificate, MAX_COMPONENTS, MAX_PUBLIC_VERIFIERS, MAX_TRUST_EPOCH_TICKS,
};

include!("p18_part1.rs");
include!("p18_part2.rs");
include!("p18_part3.rs");
include!("p18_part4.rs");
include!("p18_part5.rs");
include!("p18_part6.rs");
