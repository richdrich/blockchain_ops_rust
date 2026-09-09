//! Unit tests for `AlgoOps::required_extra_pages`, the create-time extra-program-page count for a
//! combined approval+clear program that has grown past one 2048-byte page. Pure arithmetic, no node.

use algo_ops::AlgoOps;

#[test]
fn no_extra_pages_up_to_one_full_page() {
    assert_eq!(AlgoOps::required_extra_pages(0), 0);
    assert_eq!(AlgoOps::required_extra_pages(1), 0);
    assert_eq!(AlgoOps::required_extra_pages(2047), 0);
    assert_eq!(AlgoOps::required_extra_pages(2048), 0);
}

#[test]
fn one_extra_page_into_the_second_page() {
    assert_eq!(AlgoOps::required_extra_pages(2049), 1);
    assert_eq!(AlgoOps::required_extra_pages(4096), 1);
    // The Bingle DApp is ~2.1 KB, i.e. just into the second page => exactly one extra page.
    assert_eq!(AlgoOps::required_extra_pages(2078), 1);
}

#[test]
fn additional_pages_scale_with_size() {
    assert_eq!(AlgoOps::required_extra_pages(4097), 2);
    assert_eq!(AlgoOps::required_extra_pages(6144), 2);
    assert_eq!(AlgoOps::required_extra_pages(6145), 3);
}
