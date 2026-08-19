//! Granular blockchain test accounts matching the roles in the dapp endpoint spec.
//! Generated via py-algorand-sdk; fund via `ensure_funded` below. Ported from
//! bingle_core's `tests/integration/blockchain/blockchain_users.rs` (import paths
//! adjusted for the algo_ops test tree).

use algo_ops::AlgoChainConfig;

pub const ALL_ADDRESSES: &[&str] = &[
    ADDRESS_ASSET_CREATOR,
    ADDRESS_ASSET_MANAGER,
    ADDRESS_ASSET_RESERVE,
    ADDRESS_ASSET_CLAWBACK,
    ADDRESS_ASSET_FREEZE,
    ADDRESS_APP_CREATOR,
    ADDRESS_APP_ADMIN,
    ADDRESS_APP_WITHDRAWER,
    ADDRESS_USER,
    ADDRESS_USER_STATIC,
];

pub fn ensure_funded(cfg: &AlgoChainConfig) -> Result<(), String> {
    super::setup_localnet::ensure_localnet_accounts_funded(cfg, ALL_ADDRESSES)
}

// Asset accounts
pub const ADDRESS_ASSET_CREATOR: &str =
    "TETZ5CZVNJRMKBY63RFJGJKH6JNLTXX6TS5EHYAZTBY7TX76VWW6UXMAG4";
pub const PASSPHRASE_ASSET_CREATOR: &str = "eyebrow bleak multiply material flush host panel column rubber maximum clean episode plate trim excess dignity barrel beyond minute rebuild cliff divert planet absent spray";

pub const ADDRESS_ASSET_MANAGER: &str =
    "PPVIJ3JCZ34DUE3Q3CKTY2ZSKTJV5A32C35A62G7DX462WRPZBE45DOA5Q";
pub const PASSPHRASE_ASSET_MANAGER: &str = "narrow tuition slot toddler slim copper pool permit subject elegant favorite cigar legal nurse muscle jewel rifle broom canoe eagle hint uncover unfair about similar";

pub const ADDRESS_ASSET_RESERVE: &str =
    "ZKPYCKDPCF75XTMJPCTJY5OG32BQDIPJUFFBRGAFATCYUUWPSYCDLXCQKA";
pub const PASSPHRASE_ASSET_RESERVE: &str = "weasel open guide until scale stove pull keep truly push tongue anxiety throw acoustic hamster total rare door cost response promote grain adapt ability muffin";

pub const ADDRESS_ASSET_CLAWBACK: &str =
    "6HQIHZWTWMLYC2ANOES35PJ4VIRQFEVYG4XZ34AK6B4TTSHQXF4WHJVXGQ";
pub const PASSPHRASE_ASSET_CLAWBACK: &str = "green hold found smart between transfer congress coil runway keen purse exhaust robot pool task accuse fiber meadow blossom wrong false recycle organ ability news";

pub const ADDRESS_ASSET_FREEZE: &str = "JSR33VO7TGVWZAHULWH4QNBI4APJFEPUBA3563C5FBO3Q2PNCMS4UVASGM";
pub const PASSPHRASE_ASSET_FREEZE: &str = "loan warfare heart chat giraffe skirt radio interest tiger sentence episode cross concert dream under fuel avoid good border congress hope stadium permit about sunset";

// DApp lifecycle accounts
pub const ADDRESS_APP_CREATOR: &str = "L4IOKR5LM7Q7UIYB5Y735HV3H4JPKWKHTONM5Z6WHLE6RQWHRGRUVPRGKE";
pub const PASSPHRASE_APP_CREATOR: &str = "prize local popular life bronze require amused beef opinion shock gaze utility state hunt raccoon inform junior express zebra find crash blame tide about palace";

// DApp admin / permission accounts
pub const ADDRESS_APP_ADMIN: &str = "TA2XNGWKWXXSWNHVVK23PW6A5JVYGC3WL2IFAILU4MOMCRJHHD46PCAIL4";
pub const PASSPHRASE_APP_ADMIN: &str = "sunset fuel problem limit share same dilemma cool member real satoshi capable brush during body wool kiss parade smooth fan rude assume clever absorb across";

pub const ADDRESS_APP_WITHDRAWER: &str =
    "5FMPY3U5XCCDUOROVX34JYCRXHOZTPDSXDEZ576PXRHOTD4OSWNXXDEA74";
pub const PASSPHRASE_APP_WITHDRAWER: &str = "post all tuition hero axis erupt profit same dizzy stage like fly inquiry betray electric glue just space gentle jacket annual hello betray abstract way";

// End-user accounts
pub const ADDRESS_USER: &str = "DPDMLLK2TS2PHKVFNXVMGOBZ5MGR7KK53CTXU2NCC6WTB7UKJB2CXVQZGE";
pub const PASSPHRASE_USER: &str = "snack multiply autumn spare sketch engine cross hurdle stadium below broken shoulder wise run pride piece find market movie night toddler churn myth absorb love";

pub const ADDRESS_USER_STATIC: &str = "Q3E73S7XSHR72NTBKR3MS2EYLUAUUK2EFH7N2OQI24GN4FTEB2KAH4KJ2A";
pub const PASSPHRASE_USER_STATIC: &str = "hospital case gap cancel zone dutch review manual cute price title price result try pioneer mother advance crew hire sniff buzz peanut cupboard abandon guide";
