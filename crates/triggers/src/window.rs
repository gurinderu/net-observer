use std::collections::VecDeque;

use types::{LinkSample, ProxySample, Sample};

/// Ring buffer of the most recent `cap` [`Sample`]s.
pub struct RecentWindow {
    cap: usize,
    buf: VecDeque<Sample>,
}

impl RecentWindow {
    /// Create a window that retains at most `cap` samples.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    /// Append a sample, evicting the oldest when over capacity.
    pub fn push(&mut self, s: Sample) {
        self.buf.push_back(s);
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }

    /// The most recent `n` link samples, newest first.
    pub fn recent_link(&self, n: usize) -> Vec<&LinkSample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Link(l) => Some(l),
                Sample::Proxy(_) => None,
            })
            .take(n)
            .collect()
    }

    /// The most recent `n` proxy samples, newest first.
    pub fn recent_proxy(&self, n: usize) -> Vec<&ProxySample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Proxy(p) => Some(p),
                Sample::Link(_) => None,
            })
            .take(n)
            .collect()
    }

    /// The newest link sample, if any.
    pub fn last_link(&self) -> Option<&LinkSample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Link(l) => Some(l),
            Sample::Proxy(_) => None,
        })
    }

    /// The newest proxy sample, if any.
    pub fn last_proxy(&self) -> Option<&ProxySample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Proxy(p) => Some(p),
            Sample::Link(_) => None,
        })
    }

    /// The second-newest link sample, if any.
    pub fn prev_link(&self) -> Option<&LinkSample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Link(l) => Some(l),
                Sample::Proxy(_) => None,
            })
            .nth(1)
    }
}
