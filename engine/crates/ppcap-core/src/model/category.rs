//! The traffic taxonomy. Fully implemented contract type.
//!
//! The Rust enum is canonical. `serde` emits **kebab-case** in JSON (`file-transfer`);
//! [`Category::as_str`] emits **snake_case** for the Parquet `category` column and the
//! DuckDB `category_t` enum (`file_transfer`). The undecided value is `unknown`
//! everywhere (never `unclassified`).

/// Traffic taxonomy (PROJECT-SPEC §3.3). 13-value closed set; `Unknown` is the default.
///
/// `NetworkService` is appended LAST (after `Unknown`) so every pre-existing variant keeps its
/// histogram index — see [`ALL`] / `stats::category_index`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Web,
    Dns,
    Email,
    FileTransfer,
    RemoteAccess,
    Voip,
    IotOt,
    TunnelVpn,
    Scan,
    C2,
    Anomalous,
    #[default]
    Unknown,
    /// Benign network-infrastructure / management services (NTP, DHCP, SNMP, syslog). Recognized
    /// so they classify as low-risk instead of falling to `Unknown` and being shape-uplifted to
    /// `C2`. Appended last to keep existing category indices stable.
    NetworkService,
}

/// Fixed display/iteration order for histograms — must stay stable (the
/// `category_breakdown` covers this order). `NetworkService` is appended last so existing indices
/// (`Web`=0 .. `Unknown`=11) are unchanged.
const ALL: [Category; 13] = [
    Category::Web,
    Category::Dns,
    Category::Email,
    Category::FileTransfer,
    Category::RemoteAccess,
    Category::Voip,
    Category::IotOt,
    Category::TunnelVpn,
    Category::Scan,
    Category::C2,
    Category::Anomalous,
    Category::Unknown,
    Category::NetworkService,
];

impl Category {
    /// Stable snake_case wire token used in Parquet/DuckDB column values.
    ///
    /// `"web","dns","email","file_transfer","remote_access","voip","iot_ot",
    /// "tunnel_vpn","scan","c2","anomalous","unknown","network_service"`. These exactly match the
    /// `category_t` DuckDB enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Web => "web",
            Category::Dns => "dns",
            Category::Email => "email",
            Category::FileTransfer => "file_transfer",
            Category::RemoteAccess => "remote_access",
            Category::Voip => "voip",
            Category::IotOt => "iot_ot",
            Category::TunnelVpn => "tunnel_vpn",
            Category::Scan => "scan",
            Category::C2 => "c2",
            Category::Anomalous => "anomalous",
            Category::Unknown => "unknown",
            Category::NetworkService => "network_service",
        }
    }

    /// All variants in fixed histogram order.
    pub fn all() -> &'static [Category] {
        &ALL
    }

    /// Parse a snake_case wire token back into a [`Category`]. Returns `None` for any
    /// unrecognized token.
    pub fn from_str_opt(s: &str) -> Option<Category> {
        Some(match s {
            "web" => Category::Web,
            "dns" => Category::Dns,
            "email" => Category::Email,
            "file_transfer" => Category::FileTransfer,
            "remote_access" => Category::RemoteAccess,
            "voip" => Category::Voip,
            "iot_ot" => Category::IotOt,
            "tunnel_vpn" => Category::TunnelVpn,
            "scan" => Category::Scan,
            "c2" => Category::C2,
            "anomalous" => Category::Anomalous,
            "unknown" => Category::Unknown,
            "network_service" => Category::NetworkService,
            _ => return None,
        })
    }
}
