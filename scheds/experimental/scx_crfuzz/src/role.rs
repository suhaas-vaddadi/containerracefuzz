// SPDX-License-Identifier: GPL-2.0
//
// Roles and role resolution -- the "genealogy algorithm".
//
// Design doc: Background ("Role", "Role resolution"), and section 5 (pools).
// Both are reused by discovery mode unmodified; pool-ness is a property of
// the *declaration*, not of identity resolution, which stays per-process
// either way (section 5).

use crate::config::Cardinality;
use crate::config::CommMatch;
use crate::config::RoleDecl;
use std::collections::HashMap;
use std::collections::HashSet;

/// An OS process id. A thread-group leader's pid is its tgid.
pub type Pid = i32;

/// Index of a role *declaration* in the scenario config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleId(pub usize);

/// A resolved role occupant.
///
/// For a `one`-cardinality role this is just the role. For a `pool` role it
/// additionally carries a per-member index, so that a canonical log entry says
/// *which* member was released rather than only which pool.
///
/// NOTE (design doc section 14-C, unresolved): the doc does not say whether a
/// pool hit is logged under the pool's declared name or under a per-member
/// disambiguator, and section 8's schema has no field for one. Without a
/// disambiguator, section 3.5's "the canonical log already is a valid
/// `steps[]` list" claim is false for any scenario using a pool, because
/// replaying such a projected schedule could not tell which physical member to
/// hold. Carrying `member` here is this scaffold's *proposal* for closing
/// that, not something the doc settles; rendered form is `name#index`.
///
/// `Ord` is derived (role declaration index, then member index) so a policy
/// can canonically order or tie-break a set of ready hits by role identity
/// alone, independent of the order they happened to arrive at the engine in
/// -- see `policy::OrderedWalk` and the section 14-A discussion in `lib.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleRef {
    pub role: RoleId,
    pub member: Option<u32>,
}

impl RoleRef {
    pub fn one(role: RoleId) -> Self {
        RoleRef { role, member: None }
    }

    pub fn pool_member(role: RoleId, member: u32) -> Self {
        RoleRef {
            role,
            member: Some(member),
        }
    }
}

/// The facts about a task that role resolution consults.
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

/// How a task came to have the role it has. Recorded for the debug log; the
/// canonical log never sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Sticky per-pid cache hit.
    Cached,
    /// Inherited from the task's own thread group (a `CLONE_THREAD` sibling).
    ThreadGroup,
    /// Inherited from the parent's thread group (a fork/exec child).
    Parent,
    /// First-time match against a declared cgroup/comm matcher.
    Matcher,
}

/// Role resolution state for one run.
///
/// A fresh table per run, per the harness's isolation requirement
/// (Background, "Blast radius and harness").
#[derive(Debug)]
pub struct RoleTable {
    decls: Vec<RoleDecl>,
    /// Sticky per-pid cache. Evicted on task exit so a pid Linux later reuses
    /// cannot inherit a stale role (Background, "Role resolution").
    cache: HashMap<Pid, RoleRef>,
    /// tgid -> role, so siblings and children can inherit.
    tgid_role: HashMap<Pid, RoleRef>,
    /// Next member index to hand out, per pool role.
    pool_next: HashMap<RoleId, u32>,
    /// Which roles have been seen at least once (barrier bookkeeping).
    seen: HashSet<RoleId>,
    /// The scenario-wide cgroup, used when a role declares no cgroup of its own.
    scenario_cgroup: String,
}

impl RoleTable {
    pub fn new(decls: Vec<RoleDecl>, scenario_cgroup: impl Into<String>) -> Self {
        RoleTable {
            decls,
            cache: HashMap::new(),
            tgid_role: HashMap::new(),
            pool_next: HashMap::new(),
            seen: HashSet::new(),
            scenario_cgroup: scenario_cgroup.into(),
        }
    }

    pub fn decls(&self) -> &[RoleDecl] {
        &self.decls
    }

    pub fn decl(&self, role: RoleId) -> &RoleDecl {
        &self.decls[role.0]
    }

    /// Every `one`-cardinality role, in declaration order. This is the set a
    /// policy is told about at barrier time (see `DecisionPolicy::on_barrier`).
    pub fn one_roles(&self) -> Vec<RoleId> {
        self.decls
            .iter()
            .enumerate()
            .filter(|(_, d)| d.cardinality == Cardinality::One)
            .map(|(i, _)| RoleId(i))
            .collect()
    }

    /// Render a role reference the way the canonical log and a schedule's
    /// `steps[]` spell it: `victim`, or `racer#2` for a pool member.
    pub fn render(&self, r: RoleRef) -> String {
        match r.member {
            None => self.decls[r.role.0].id.clone(),
            Some(m) => format!("{}#{}", self.decls[r.role.0].id, m),
        }
    }

    /// Look up an already-resolved pid, without attempting to match.
    ///
    /// Used on events that carry a pid but no `TaskInfo` -- a checkpoint hit,
    /// an exit. A pid that has never been resolved is not a role occupant,
    /// which is the answer the caller wants.
    pub fn lookup(&self, pid: Pid) -> Option<RoleRef> {
        self.cache.get(&pid).copied()
    }

    /// Resolve a task to a role, per Background's four-step algorithm.
    ///
    /// Order matters: the task's *own* thread group is consulted before its
    /// parent's, because a new OS thread created via `CLONE_THREAD` -- which
    /// Go runtimes (runc, containerd) create routinely for goroutine
    /// scheduling -- has a parent pointer that refers to the wrong process.
    /// Resolving such a thread through its parent would misattribute it.
    ///
    /// Returns `None` for any task that is not part of a declared role. The
    /// caller must dispatch those unmodified: that is the blast-radius
    /// guarantee (Background, "Blast radius and harness").
    pub fn resolve_role(&mut self, task: &TaskInfo) -> Option<(RoleRef, Provenance)> {
        // 1. Sticky per-pid cache.
        if let Some(r) = self.cache.get(&task.pid) {
            return Some((*r, Provenance::Cached));
        }

        // 2. The task's own thread group: a CLONE_THREAD sibling.
        if let Some(r) = self.tgid_role.get(&task.tgid).copied() {
            self.cache.insert(task.pid, r);
            return Some((r, Provenance::ThreadGroup));
        }

        // 3. The parent's thread group: a new process via fork/exec.
        if let Some(r) = self.tgid_role.get(&task.parent_tgid).copied() {
            self.cache.insert(task.pid, r);
            self.tgid_role.insert(task.tgid, r);
            return Some((r, Provenance::Parent));
        }

        // 4. First-time match against the declared matchers.
        let matched = self.match_decl(task)?;
        let r = self.claim(matched)?;
        self.seen.insert(matched);
        self.cache.insert(task.pid, r);
        self.tgid_role.insert(task.tgid, r);
        Some((r, Provenance::Matcher))
    }

    fn match_decl(&self, task: &TaskInfo) -> Option<RoleId> {
        self.decls.iter().enumerate().find_map(|(i, d)| {
            let cgroup = d.cgroup.as_deref().unwrap_or(&self.scenario_cgroup);
            if !task.cgroup.starts_with(cgroup) {
                return None;
            }
            let comm_ok = match d.comm_match {
                CommMatch::Exact => task.comm == d.comm,
                CommMatch::Substring => task.comm.contains(&d.comm),
            };
            comm_ok.then_some(RoleId(i))
        })
    }

    /// Allocate an occupant slot for a first-time match.
    ///
    /// A `one` role admits exactly one thread group. A second, unrelated
    /// thread group matching an already-claimed `one` role is not a role
    /// occupant -- it falls through to unmodified dispatch rather than
    /// silently displacing the incumbent.
    fn claim(&mut self, role: RoleId) -> Option<RoleRef> {
        match self.decls[role.0].cardinality {
            Cardinality::One => {
                if self.seen.contains(&role) {
                    None
                } else {
                    Some(RoleRef::one(role))
                }
            }
            Cardinality::Pool => {
                let next = self.pool_next.entry(role).or_insert(0);
                let member = *next;
                *next += 1;
                Some(RoleRef::pool_member(role, member))
            }
        }
    }

    /// Evict a task's cache entries. Called on task exit.
    ///
    /// Without this, a pid Linux later reuses would inherit the dead task's
    /// role from the sticky cache (Background, "Role resolution").
    pub fn on_task_exit(&mut self, pid: Pid) {
        self.cache.remove(&pid);
        // A thread-group leader's exit retires the group's identity. Siblings
        // and children that still exist keep their own cache entries.
        self.tgid_role.remove(&pid);
    }

    /// Barrier condition (Background, plus design doc section 5).
    ///
    /// Evaluated over `one`-cardinality roles only. A pool is open-ended by
    /// definition -- there is no fixed N to wait for -- so requiring "all pool
    /// members seen" is not a well-formed condition and would hang the barrier
    /// forever. A pool is marked seen the first time any member matches, and
    /// later matches are recorded without gating the barrier further.
    pub fn all_roles_seen(&self) -> bool {
        self.decls
            .iter()
            .enumerate()
            .filter(|(_, d)| d.cardinality == Cardinality::One)
            .all(|(i, _)| self.seen.contains(&RoleId(i)))
    }

    pub fn is_seen(&self, role: RoleId) -> bool {
        self.seen.contains(&role)
    }

    /// How many members a pool has admitted so far.
    pub fn pool_len(&self, role: RoleId) -> u32 {
        self.pool_next.get(&role).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoleDecl;

    fn decls() -> Vec<RoleDecl> {
        vec![
            RoleDecl::one("victim", "runc"),
            RoleDecl::pool("racer", "racer"),
        ]
    }

    fn table() -> RoleTable {
        RoleTable::new(decls(), "/sys/fs/cgroup/crfuzz")
    }

    fn task(pid: Pid, tgid: Pid, parent_tgid: Pid, comm: &str) -> TaskInfo {
        TaskInfo {
            pid,
            tgid,
            parent_tgid,
            comm: comm.to_string(),
            cgroup: "/sys/fs/cgroup/crfuzz/run0".to_string(),
        }
    }

    #[test]
    fn first_match_claims_the_role() {
        let mut t = table();
        let (r, p) = t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        assert_eq!(r, RoleRef::one(RoleId(0)));
        assert_eq!(p, Provenance::Matcher);
    }

    #[test]
    fn task_outside_the_scenario_cgroup_is_not_a_role() {
        let mut t = table();
        let mut outsider = task(100, 100, 1, "runc");
        outsider.cgroup = "/sys/fs/cgroup/system.slice".to_string();
        assert!(t.resolve_role(&outsider).is_none());
    }

    #[test]
    fn clone_thread_sibling_inherits_via_its_own_tgid_not_its_parent() {
        let mut t = table();
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();

        // A Go runtime thread: same tgid as the leader, but a parent_tgid
        // pointing at some unrelated process. Resolving through the parent
        // would misattribute it -- and here, would find nothing at all.
        let (r, p) = t.resolve_role(&task(101, 100, 9999, "runc")).unwrap();
        assert_eq!(r, RoleRef::one(RoleId(0)));
        assert_eq!(p, Provenance::ThreadGroup);
    }

    #[test]
    fn thread_group_wins_over_parent_when_the_two_disagree() {
        let mut t = table();
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        t.resolve_role(&task(200, 200, 1, "racer")).unwrap();

        // pid 201 is a thread of the victim's group (tgid 100) whose parent
        // tgid is the racer (200). Own thread group must win.
        let (r, p) = t.resolve_role(&task(201, 100, 200, "anything")).unwrap();
        assert_eq!(r, RoleRef::one(RoleId(0)), "should be victim, not racer");
        assert_eq!(p, Provenance::ThreadGroup);
    }

    #[test]
    fn forked_child_inherits_from_parent_across_exec() {
        let mut t = table();
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();

        // `runc init`: a new thread group, different comm, parented by runc.
        let (r, p) = t
            .resolve_role(&task(150, 150, 100, "runc:[2:INIT]"))
            .unwrap();
        assert_eq!(r, RoleRef::one(RoleId(0)));
        assert_eq!(p, Provenance::Parent);

        // ...and its own threads then resolve through it.
        let (r2, p2) = t.resolve_role(&task(151, 150, 1, "runc:[2:INIT]")).unwrap();
        assert_eq!(r2, RoleRef::one(RoleId(0)));
        assert_eq!(p2, Provenance::ThreadGroup);
    }

    #[test]
    fn pid_reuse_after_exit_does_not_inherit_a_stale_role() {
        let mut t = table();
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        t.on_task_exit(100);

        // Linux hands pid 100 to something unrelated, outside any matcher.
        assert!(t.resolve_role(&task(100, 100, 1, "sshd")).is_none());
    }

    #[test]
    fn pool_members_get_distinct_indices() {
        let mut t = table();
        let (a, _) = t.resolve_role(&task(300, 300, 1, "racer")).unwrap();
        let (b, _) = t.resolve_role(&task(301, 301, 1, "racer")).unwrap();
        assert_eq!(a, RoleRef::pool_member(RoleId(1), 0));
        assert_eq!(b, RoleRef::pool_member(RoleId(1), 1));
        assert_eq!(t.pool_len(RoleId(1)), 2);
    }

    #[test]
    fn a_second_thread_group_cannot_displace_a_claimed_one_role() {
        let mut t = table();
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        // Unrelated thread group, same comm, same cgroup.
        assert!(t.resolve_role(&task(400, 400, 1, "runc")).is_none());
    }

    #[test]
    fn barrier_ignores_pool_roles_entirely() {
        let mut t = table();
        assert!(!t.all_roles_seen());
        // Only the pool has shown up: the barrier must still be waiting on the
        // `one` role...
        t.resolve_role(&task(300, 300, 1, "racer")).unwrap();
        assert!(!t.all_roles_seen());
        // ...and must complete on the `one` role alone, without waiting for
        // any particular number of pool members.
        t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        assert!(t.all_roles_seen());
    }

    #[test]
    fn pool_is_marked_seen_on_first_match() {
        let mut t = table();
        assert!(!t.is_seen(RoleId(1)));
        t.resolve_role(&task(300, 300, 1, "racer")).unwrap();
        assert!(t.is_seen(RoleId(1)));
    }

    #[test]
    fn render_spells_pool_members_with_a_disambiguator() {
        let mut t = table();
        let (v, _) = t.resolve_role(&task(100, 100, 1, "runc")).unwrap();
        let (r, _) = t.resolve_role(&task(300, 300, 1, "racer")).unwrap();
        assert_eq!(t.render(v), "victim");
        assert_eq!(t.render(r), "racer#0");
    }

    #[test]
    fn substring_matching_is_opt_in() {
        let mut exact = RoleTable::new(vec![RoleDecl::one("victim", "runc")], "/c");
        let mut t = task(100, 100, 1, "runc:[2:INIT]");
        t.cgroup = "/c/run0".into();
        assert!(exact.resolve_role(&t).is_none());

        let mut sub = RoleTable::new(
            vec![RoleDecl::one("victim", "runc").with_substring_match()],
            "/c",
        );
        assert!(sub.resolve_role(&t).is_some());
    }
}
