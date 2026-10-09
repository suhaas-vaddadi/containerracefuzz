// SPDX-License-Identifier: GPL-2.0
//
// Which tasks are the victim -- the "genealogy algorithm".
//
// Design doc: Background ("Role", "Role resolution"). A scenario has one role,
// the victim: every thread group in scope whose `comm` matches, every task in
// the container's cgroup, plus their threads and the processes they fork. Each
// run gets a fresh cgroup, so any matching thread group there is the victim's;
// there is nothing to displace.

use crate::config::under_cgroup;
use crate::config::CommMatch;
use crate::config::VictimDecl;
use std::collections::HashSet;

/// An OS process id. A thread-group leader's pid is its tgid.
pub type Pid = i32;

/// The facts about a task that resolution consults.
///
/// Supplied by the backend; on Linux these come from the task's own fields
/// plus its cgroup path. Kept as a plain struct with no kernel types so the
/// resolution algorithm is testable off-target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub pid: Pid,
    /// Thread-group id. Equal to `pid` for a thread-group leader.
    pub tgid: Pid,
    /// Thread-group id of the parent process.
    pub parent_tgid: Pid,
    pub comm: String,
    pub cgroup: String,
}

/// Victim resolution state for one run.
#[derive(Debug)]
pub struct Victims {
    decl: VictimDecl,
    scope: String,
    /// The container's cgroup; every task in it is the victim's.
    container: Option<String>,
    /// Sticky per-pid cache. Evicted on task exit so a pid Linux later reuses
    /// cannot inherit a stale identity (Background, "Role resolution").
    pids: HashSet<Pid>,
    /// Victim thread groups, so siblings and children can inherit.
    tgids: HashSet<Pid>,
}

impl Victims {
    pub fn new(decl: VictimDecl, scope: impl Into<String>, container: Option<String>) -> Self {
        Victims {
            decl,
            scope: scope.into(),
            container,
            pids: HashSet::new(),
            tgids: HashSet::new(),
        }
    }

    /// Whether an already-resolved pid is the victim's.
    pub fn contains(&self, pid: Pid) -> bool {
        self.pids.contains(&pid)
    }

    /// Resolve a newly seen task.
    ///
    /// The task's *own* thread group is consulted before its parent's, because
    /// a Go runtime thread created via `CLONE_THREAD` has a parent pointer that
    /// refers to the wrong process. A task that is not the victim's must be
    /// released unmodified: that is the blast-radius guarantee.
    pub fn resolve(&mut self, task: &TaskInfo) -> bool {
        let is_victim = self.pids.contains(&task.pid)
            || self.tgids.contains(&task.tgid)
            || self.tgids.contains(&task.parent_tgid)
            || self.matches(task);
        if is_victim {
            self.pids.insert(task.pid);
            self.tgids.insert(task.tgid);
        }
        is_victim
    }

    fn matches(&self, task: &TaskInfo) -> bool {
        if let Some(c) = &self.container {
            if under_cgroup(&task.cgroup, c) {
                return true;
            }
        }
        under_cgroup(&task.cgroup, &self.scope)
            && match self.decl.comm_match {
                CommMatch::Exact => task.comm == self.decl.comm,
                CommMatch::Substring => task.comm.contains(&self.decl.comm),
            }
    }

    /// Forget a task. A thread-group leader's exit retires the group; its
    /// siblings and children keep their own entries.
    pub fn on_exit(&mut self, pid: Pid) {
        self.pids.remove(&pid);
        self.tgids.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn victims() -> Victims {
        Victims::new(
            VictimDecl {
                comm: "runc".into(),
                comm_match: CommMatch::Exact,
            },
            "/crfuzz",
            Some("/default/ctr1".into()),
        )
    }

    fn task(pid: Pid, tgid: Pid, parent_tgid: Pid, comm: &str) -> TaskInfo {
        TaskInfo {
            pid,
            tgid,
            parent_tgid,
            comm: comm.to_string(),
            cgroup: "/crfuzz/run0".to_string(),
        }
    }

    #[test]
    fn a_matching_task_is_the_victim() {
        let mut v = victims();
        assert!(v.resolve(&task(100, 100, 1, "runc")));
        assert!(v.contains(100));
    }

    #[test]
    fn a_task_outside_the_scope_is_not() {
        let mut v = victims();
        let mut outsider = task(100, 100, 1, "runc");
        outsider.cgroup = "/system.slice".to_string();
        assert!(!v.resolve(&outsider));
        outsider.cgroup = "/crfuzzer/run0".to_string();
        assert!(!v.resolve(&outsider), "scope stops at a path boundary");
    }

    #[test]
    fn a_thread_inherits_through_its_own_thread_group() {
        let mut v = victims();
        v.resolve(&task(100, 100, 1, "runc"));
        // A Go runtime thread: the leader's tgid, an unrelated parent.
        assert!(v.resolve(&task(101, 100, 9999, "runc")));
    }

    #[test]
    fn a_forked_child_inherits_across_exec() {
        let mut v = victims();
        v.resolve(&task(100, 100, 1, "runc"));
        // `runc init`: a new thread group, another comm, parented by runc.
        assert!(v.resolve(&task(150, 150, 100, "runc:[2:INIT]")));
        // ...and its own threads resolve through it.
        assert!(v.resolve(&task(151, 150, 1, "runc:[2:INIT]")));
    }

    #[test]
    fn an_unrelated_task_is_not_the_victim() {
        let mut v = victims();
        v.resolve(&task(100, 100, 1, "runc"));
        assert!(!v.resolve(&task(200, 200, 1, "sh")));
    }

    #[test]
    fn pid_reuse_after_exit_does_not_inherit() {
        let mut v = victims();
        v.resolve(&task(100, 100, 1, "runc"));
        v.on_exit(100);
        assert!(!v.contains(100));
        assert!(!v.resolve(&task(100, 100, 1, "sshd")));
    }

    #[test]
    fn any_task_in_the_container_cgroup_is_the_victim() {
        let mut v = victims();
        // `runc init` already moved into the container's cgroup, outside the
        // scope, with a parent nothing announced.
        let mut init = task(300, 300, 299, "runc:[2:INIT]");
        init.cgroup = "/default/ctr1".to_string();
        assert!(v.resolve(&init));
        let mut other = task(400, 400, 1, "sh");
        other.cgroup = "/default/ctr12".to_string();
        assert!(!v.resolve(&other), "a sibling container is not");
    }

    #[test]
    fn substring_matching_is_opt_in() {
        let mut exact = victims();
        assert!(!exact.resolve(&task(100, 100, 1, "runc:[2:INIT]")));
        let mut sub = Victims::new(
            VictimDecl {
                comm: "runc".into(),
                comm_match: CommMatch::Substring,
            },
            "/crfuzz",
            None,
        );
        assert!(sub.resolve(&task(100, 100, 1, "runc:[2:INIT]")));
    }
}
