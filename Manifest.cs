using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SharedSecret
{
    public class Manifest
    {
        [JsonPropertyName("encrypted")]
        public bool Encrypted { get; set; }

        [JsonPropertyName("first_run")]
        public bool FirstRun { get; set; } = true;

        [JsonPropertyName("entries")]
        public List<ManifestEntry> Entries { get; set; }

        [JsonPropertyName("periodic_checking")]
        public bool PeriodicChecking { get; set; } = false;

        [JsonPropertyName("periodic_checking_interval")]
        public int PeriodicCheckingInterval { get; set; } = 5;

        [JsonPropertyName("periodic_checking_checkall")]
        public bool CheckAllAccounts { get; set; } = false;

        [JsonPropertyName("auto_confirm_market_transactions")]
        public bool AutoConfirmMarketTransactions { get; set; } = false;

        [JsonPropertyName("auto_confirm_trades")]
        public bool AutoConfirmTrades { get; set; } = false;
    }

    public class ManifestEntry
    {
        [JsonPropertyName("encryption_iv")]
        public string IV { get; set; }

        [JsonPropertyName("encryption_salt")]
        public string Salt { get; set; }

        [JsonPropertyName("filename")]
        public string Filename { get; set; }

        [JsonPropertyName("steamid")]
        public ulong SteamID { get; set; }
    }
}
