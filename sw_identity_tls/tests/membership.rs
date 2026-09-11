//! Unit tests for the authorization seam — the `MembershipAuthority` trait and its static impls.
//! Pure CPU work, no sockets or node calls (the whole point of the seam).

use std::collections::HashSet;

use sw_identity_tls::{MembershipAuthority, Role, StaticMembership};

#[test]
fn empty_static_membership_admits_nobody() {
    let authority = StaticMembership::new();
    assert_eq!(authority.role_of("ANYONE"), None);
    assert!(!authority.is_member("ANYONE"));
}

#[test]
fn from_sets_assigns_node_and_client_roles() {
    let authority = StaticMembership::from_sets(
        ["NODE_A".to_string(), "NODE_B".to_string()],
        ["CALLER_A".to_string()],
    );
    assert_eq!(authority.role_of("NODE_A"), Some(Role::ClusterNode));
    assert_eq!(authority.role_of("NODE_B"), Some(Role::ClusterNode));
    assert_eq!(authority.role_of("CALLER_A"), Some(Role::Client));
    assert!(authority.is_member("NODE_A") && authority.is_member("CALLER_A"));
}

#[test]
fn node_role_wins_over_client_on_overlap() {
    // an address enrolled as both a node and a caller resolves to the more-privileged cluster role.
    let authority = StaticMembership::from_sets(["BOTH".to_string()], ["BOTH".to_string()]);
    assert_eq!(authority.role_of("BOTH"), Some(Role::ClusterNode));
}

#[test]
fn unknown_identity_fails_closed() {
    let authority = StaticMembership::new().with("KNOWN", Role::Client);
    assert_eq!(authority.role_of("KNOWN"), Some(Role::Client));
    // a miss returns None (fail closed) rather than admitting or erroring.
    assert_eq!(authority.role_of("STRANGER"), None);
    assert!(!authority.is_member("STRANGER"));
}

#[test]
fn hashset_allow_set_is_a_client_authority() {
    // a bare allow-set authorizes every listed address as a Client, so existing allow-set call sites
    // plug into the trait seam without building a role map.
    let allow: HashSet<String> = ["X".to_string()].into_iter().collect();
    assert_eq!(allow.role_of("X"), Some(Role::Client));
    assert_eq!(allow.role_of("Y"), None);
}
