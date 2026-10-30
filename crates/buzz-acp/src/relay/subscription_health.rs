//! Socket liveness does not prove the relay served a subscription REQ.
use super::*;

pub(super) const EOSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct SubscriptionHealth {
    pending: HashMap<String, (tokio::time::Instant, Option<u64>)>,
}

impl SubscriptionHealth {
    pub(super) fn sent(&mut self, sub: &str, replay_floor: Option<u64>) {
        // Repeated overflow/retry REQs must not keep an unconfirmed subscription
        // alive forever. EOSE carries only the stable subscription ID, so this
        // verifies a response for that ID, not each superseded REQ individually.
        self.pending
            .entry(sub.to_owned())
            .and_modify(|(_, floor)| {
                *floor = match (*floor, replay_floor) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            })
            .or_insert_with(|| (tokio::time::Instant::now() + EOSE_TIMEOUT, replay_floor));
    }

    pub(super) fn remove(&mut self, sub: &str) -> bool {
        self.pending.remove(sub).is_some()
    }

    pub(super) fn take_replay_floors(&mut self) -> Vec<(String, u64)> {
        std::mem::take(&mut self.pending)
            .into_iter()
            .filter_map(|(sub, (_, floor))| floor.map(|floor| (sub, floor)))
            .collect()
    }

    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        self.pending.values().map(|(deadline, _)| *deadline).min()
    }

    pub(super) fn expired(&self) -> Vec<&str> {
        let now = tokio::time::Instant::now();
        let mut ids: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (deadline, _))| *deadline <= now)
            .map(|(sub, _)| sub.as_str())
            .collect();
        ids.sort_unstable();
        ids
    }
}

pub(super) async fn wait(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
