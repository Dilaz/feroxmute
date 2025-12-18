mod collection;
mod detection;
mod types;

pub use collection::{TargetCollection, TargetGroup};
pub use detection::{RelationshipDetector, RelationshipHint};
pub use types::{Target, TargetParseError, TargetType};
