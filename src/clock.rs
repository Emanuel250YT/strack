//! Match clock: the simulator's minute, interpolated between polls with the speed-up factor.

use std::time::Instant;

use crate::simulator::SimStatus;

#[derive(Debug, Clone)]
pub struct MatchClock {
    sample_minute: f64,
    sampled_at: Instant,
    speedup: f64,
    pub end_min: f64,
    pub finished: bool,
    pub judges_on_duty: Vec<String>,
    pub synced: bool,
}

impl Default for MatchClock {
    fn default() -> Self {
        Self {
            sample_minute: 0.0,
            sampled_at: Instant::now(),
            speedup: 1.0,
            end_min: 105.0,
            finished: false,
            judges_on_duty: Vec::new(),
            synced: false,
        }
    }
}

impl MatchClock {
    /// Current match minute. Before the first sync it stays at the last known sample.
    pub fn now(&self) -> f64 {
        if !self.synced {
            return self.sample_minute;
        }
        self.sample_minute + self.sampled_at.elapsed().as_secs_f64() * self.speedup / 60.0
    }

    pub fn speedup(&self) -> f64 {
        self.speedup
    }

    pub fn update(&mut self, status: &SimStatus) {
        self.sample_minute = status.minute;
        self.sampled_at = Instant::now();
        self.speedup = if status.speedup > 0.0 { status.speedup } else { 1.0 };
        self.end_min = status.end_min;
        self.finished = status.finished;
        self.judges_on_duty = status.judges_on_duty.clone();
        self.synced = true;
    }
}
