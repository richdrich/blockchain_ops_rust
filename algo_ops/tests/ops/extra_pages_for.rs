//! Unit tests for `AlgoOps::extra_pages_for`, the create-time extra-program-page count that combines
//! the minimum needed to fit the program with a caller-requested reservation of spare pages, clamped
//! to Algorand's maximum. Pure arithmetic, no node.

use algo_ops::AlgoOps;

#[test]
fn no_reservation_matches_required() {
    // reserve_extra_pages = 0 must behave exactly like required_extra_pages.
    for size in [0usize, 1, 2048, 2049, 2078, 4096, 4097, 6145] {
        assert_eq!(
            AlgoOps::extra_pages_for(size, 0),
            AlgoOps::required_extra_pages(size),
            "size {size}"
        );
    }
}

#[test]
fn reservation_raises_pages_when_program_is_small() {
    // A one-page program (needs 0 extra) but a reservation of 3 => 3 extra pages (4 total).
    assert_eq!(AlgoOps::extra_pages_for(2048, 3), 3);
    // The ~2.1 KB Bingle DApp needs 1 extra page; reserving 3 locks in the full 4 pages.
    assert_eq!(AlgoOps::extra_pages_for(2201, 3), 3);
}

#[test]
fn required_wins_when_it_exceeds_the_reservation() {
    // Program needs 2 extra pages; a reservation of only 1 must not shrink it below what fits.
    assert_eq!(AlgoOps::extra_pages_for(6144, 1), 2);
}

#[test]
fn clamped_to_algorand_maximum() {
    // Neither a huge program nor an over-large reservation can exceed 3 extra pages.
    assert_eq!(AlgoOps::extra_pages_for(usize::MAX, 0), 3);
    assert_eq!(AlgoOps::extra_pages_for(2048, 99), 3);
}
