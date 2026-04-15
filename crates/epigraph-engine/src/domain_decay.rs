//! Domain-specific temporal decay for evidence weighting

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DomainDecay {
    pub half_life_days: f64,
    pub minimum_weight: f64,
}

impl DomainDecay {
    pub fn for_domain(domain: &str) -> Self {
        match domain {
            "news" | "current_events" => Self {
                half_life_days: 7.0,
                minimum_weight: 0.1,
            },
            "science" | "biology" | "chemistry" | "physics" => Self {
                half_life_days: 365.0,
                minimum_weight: 0.5,
            },
            "law" | "legal" => Self {
                half_life_days: 730.0,
                minimum_weight: 0.7,
            },
            "math" | "mathematics" | "logic" => Self {
                half_life_days: f64::INFINITY,
                minimum_weight: 1.0,
            },
            "technology" | "software" => Self {
                half_life_days: 90.0,
                minimum_weight: 0.2,
            },
            "medicine" | "medical" => Self {
                half_life_days: 365.0,
                minimum_weight: 0.4,
            },
            _ => Self {
                half_life_days: 180.0,
                minimum_weight: 0.3,
            },
        }
    }

    pub fn weight(&self, evidence_age: Duration) -> f64 {
        if self.half_life_days.is_infinite() {
            return 1.0;
        }
        let days = evidence_age.as_secs_f64() / 86400.0;
        let decay_factor = 0.5_f64.powf(days / self.half_life_days);
        decay_factor.max(self.minimum_weight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_news_decays_fast() {
        let decay = DomainDecay::for_domain("news");
        let weight = decay.weight(Duration::from_secs(7 * 86400));
        assert!(
            weight < 0.6,
            "News should lose >40% in 7 days, got {weight}"
        );
    }

    #[test]
    fn test_science_decays_slow() {
        let decay = DomainDecay::for_domain("science");
        let weight = decay.weight(Duration::from_secs(180 * 86400));
        assert!(
            weight > 0.6,
            "Science should retain >60% at 6 months, got {weight}"
        );
    }

    #[test]
    fn test_math_never_decays() {
        let decay = DomainDecay::for_domain("math");
        let weight = decay.weight(Duration::from_secs(3650 * 86400));
        assert!((weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_minimum_weight_floor() {
        let decay = DomainDecay::for_domain("news");
        let weight = decay.weight(Duration::from_secs(365 * 86400));
        assert!(weight >= decay.minimum_weight);
    }

    #[test]
    fn test_unknown_domain_default() {
        let decay = DomainDecay::for_domain("underwater_basket_weaving");
        assert!((decay.half_life_days - 180.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_zero_age_full_weight() {
        let decay = DomainDecay::for_domain("news");
        assert!((decay.weight(Duration::ZERO) - 1.0).abs() < f64::EPSILON);
    }
}
