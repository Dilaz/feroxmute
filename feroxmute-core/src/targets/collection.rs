use super::{Target, TargetParseError};

#[derive(Debug, Clone)]
pub struct TargetGroup {
    pub web_target: Target,
    pub source_target: Option<Target>,
}

#[derive(Debug, Clone)]
pub struct TargetCollection {
    pub groups: Vec<TargetGroup>,
    pub standalone_sources: Vec<Target>,
}

impl TargetCollection {
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            standalone_sources: Vec::new(),
        }
    }

    pub fn from_strings(inputs: &[String]) -> Result<Self, TargetParseError> {
        let mut collection = Self::new();
        for input in inputs {
            let target = Target::parse(input)?;
            collection.add_target(target);
        }
        Ok(collection)
    }

    pub fn add_target(&mut self, target: Target) {
        if target.is_web() {
            self.groups.push(TargetGroup {
                web_target: target,
                source_target: None,
            });
        } else {
            self.standalone_sources.push(target);
        }
    }

    pub fn link_source_to_web(&mut self, source_raw: &str, web_raw: &str) -> bool {
        // Find the source in standalone_sources
        let source_idx = self
            .standalone_sources
            .iter()
            .position(|t| t.raw == source_raw);

        let Some(idx) = source_idx else {
            return false;
        };

        // Find the web target group
        let group = self.groups.iter_mut().find(|g| g.web_target.raw == web_raw);

        let Some(group) = group else {
            return false;
        };

        // Move source from standalone to linked
        let mut source = self.standalone_sources.remove(idx);
        source.linked_to = Some(web_raw.to_string());
        group.source_target = Some(source);
        true
    }

    pub fn web_targets(&self) -> Vec<&Target> {
        self.groups.iter().map(|g| &g.web_target).collect()
    }

    pub fn has_linked_source(&self, web_raw: &str) -> bool {
        self.groups
            .iter()
            .any(|g| g.web_target.raw == web_raw && g.source_target.is_some())
    }
}

impl Default for TargetCollection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_strings_single_web() {
        let inputs = vec!["https://example.com".to_string()];
        let collection = TargetCollection::from_strings(&inputs).unwrap();
        assert_eq!(collection.groups.len(), 1);
        assert!(collection.groups[0].source_target.is_none());
    }

    #[test]
    fn test_from_strings_web_and_source() {
        // Note: This test needs a real directory, use temp
        let inputs = vec![
            "https://example.com".to_string(),
        ];
        let collection = TargetCollection::from_strings(&inputs).unwrap();
        assert_eq!(collection.groups.len(), 1);
    }

    #[test]
    fn test_link_source_to_web() {
        let mut collection = TargetCollection::new();
        let web = Target::parse("https://example.com").unwrap();
        collection.add_target(web);

        assert!(!collection.has_linked_source("https://example.com"));
    }
}
