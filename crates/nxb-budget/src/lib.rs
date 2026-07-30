use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct RequestBudget {
    remaining: u64,
    max_concurrency: u16,
    in_flight: u16,
    tokens: f64,
    token_capacity: f64,
    refill_per_second: f64,
    last_refill: Duration,
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum BudgetError {
    #[error("the total request budget is exhausted")]
    Exhausted,
    #[error("the maximum request concurrency has been reached")]
    ConcurrencyExceeded,
    #[error("the rate budget is temporarily exhausted; retry after {retry_after:?}")]
    RateLimited { retry_after: Duration },
    #[error("budget configuration is invalid: {0}")]
    InvalidConfiguration(String),
}

impl RequestBudget {
    pub fn new(
        maximum_total_requests: u64,
        maximum_concurrency: u16,
        requests_per_second: f64,
    ) -> Result<Self, BudgetError> {
        if maximum_total_requests == 0 {
            return Err(BudgetError::InvalidConfiguration(
                "maximum_total_requests must be greater than zero".into(),
            ));
        }
        if maximum_concurrency == 0 {
            return Err(BudgetError::InvalidConfiguration(
                "maximum_concurrency must be greater than zero".into(),
            ));
        }
        if !requests_per_second.is_finite() || requests_per_second <= 0.0 {
            return Err(BudgetError::InvalidConfiguration(
                "requests_per_second must be finite and greater than zero".into(),
            ));
        }

        Ok(Self {
            remaining: maximum_total_requests,
            max_concurrency: maximum_concurrency,
            in_flight: 0,
            tokens: requests_per_second,
            token_capacity: requests_per_second,
            refill_per_second: requests_per_second,
            last_refill: Duration::ZERO,
        })
    }

    pub fn try_start(&mut self, elapsed: Duration) -> Result<(), BudgetError> {
        self.refill(elapsed);

        if self.remaining == 0 {
            return Err(BudgetError::Exhausted);
        }
        if self.in_flight >= self.max_concurrency {
            return Err(BudgetError::ConcurrencyExceeded);
        }
        if self.tokens < 1.0 {
            let missing = 1.0 - self.tokens;
            let retry_seconds = missing / self.refill_per_second;
            return Err(BudgetError::RateLimited {
                retry_after: Duration::from_secs_f64(retry_seconds),
            });
        }

        self.tokens -= 1.0;
        self.remaining -= 1;
        self.in_flight += 1;
        Ok(())
    }

    pub fn finish(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub fn in_flight(&self) -> u16 {
        self.in_flight
    }

    fn refill(&mut self, elapsed: Duration) {
        if elapsed <= self.last_refill {
            return;
        }

        let delta = elapsed - self.last_refill;
        self.tokens = (self.tokens + delta.as_secs_f64() * self.refill_per_second)
            .min(self.token_capacity);
        self.last_refill = elapsed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_total_budget() {
        let mut budget = RequestBudget::new(1, 1, 10.0).unwrap();
        budget.try_start(Duration::ZERO).unwrap();
        budget.finish();
        assert_eq!(budget.try_start(Duration::from_secs(1)), Err(BudgetError::Exhausted));
    }

    #[test]
    fn enforces_concurrency() {
        let mut budget = RequestBudget::new(10, 1, 10.0).unwrap();
        budget.try_start(Duration::ZERO).unwrap();
        assert_eq!(
            budget.try_start(Duration::from_millis(10)),
            Err(BudgetError::ConcurrencyExceeded)
        );
    }

    #[test]
    fn refills_rate_tokens_deterministically() {
        let mut budget = RequestBudget::new(10, 10, 1.0).unwrap();
        budget.try_start(Duration::ZERO).unwrap();
        budget.finish();
        assert!(matches!(
            budget.try_start(Duration::from_millis(100)),
            Err(BudgetError::RateLimited { .. })
        ));
        budget.try_start(Duration::from_secs(1)).unwrap();
    }
}
