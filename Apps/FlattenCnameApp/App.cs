/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace FlattenCname
{
    public sealed class App : IDnsApplication, IDnsPostProcessor, IDnsApplicationPreference
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableFlattenCname;
        bool _flattenA;
        bool _flattenAaaa;
        uint _defaultTtl;
        int _queryTimeout;
        int _maxDepth;
        bool _bypassLocalZones;
        NetworkAddress[] _bypassNetworks;
        string[] _bypassDomains;
        string[] _filterDomains;
        byte _appPreference;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableFlattenCname = jsonConfig.GetPropertyValue("enableFlattenCname", false);
            _flattenA = jsonConfig.GetPropertyValue("flattenA", true);
            _flattenAaaa = jsonConfig.GetPropertyValue("flattenAaaa", true);
            _bypassLocalZones = jsonConfig.GetPropertyValue("bypassLocalZones", false);

            if (jsonConfig.TryGetProperty("defaultTtl", out JsonElement jsonValue) && jsonValue.TryGetUInt32(out uint defaultTtl))
                _defaultTtl = defaultTtl;
            else
                _defaultTtl = 30u;

            if (jsonConfig.TryGetProperty("queryTimeout", out jsonValue) && jsonValue.TryGetInt32(out int queryTimeout))
                _queryTimeout = Math.Max(250, queryTimeout);
            else
                _queryTimeout = 2000;

            if (jsonConfig.TryGetProperty("maxDepth", out jsonValue) && jsonValue.TryGetInt32(out int maxDepth))
                _maxDepth = Math.Max(1, Math.Min(64, maxDepth));
            else
                _maxDepth = 16;

            if (jsonConfig.TryGetProperty("appPreference", out jsonValue) && jsonValue.TryGetByte(out byte appPreference))
                _appPreference = appPreference;
            else
                _appPreference = 100;

            if (jsonConfig.TryReadArray("bypassNetworks", NetworkAddress.Parse, out NetworkAddress[] bypassNetworks))
                _bypassNetworks = bypassNetworks;
            else
                _bypassNetworks = [];

            if (jsonConfig.TryReadArray("bypassDomains", out string[] bypassDomains))
                _bypassDomains = NormalizeDomains(bypassDomains);
            else
                _bypassDomains = [];

            if (jsonConfig.TryReadArray("filterDomains", out string[] filterDomains))
                _filterDomains = NormalizeDomains(filterDomains);
            else
                _filterDomains = [];

            if (!jsonConfig.TryGetProperty("flattenA", out _) || !jsonConfig.TryGetProperty("flattenAaaa", out _) || !jsonConfig.TryGetProperty("appPreference", out _))
            {
                string updatedConfig = config.TrimEnd('\r', '\n', ' ');

                if (!jsonConfig.TryGetProperty("flattenA", out _))
                    updatedConfig = updatedConfig.TrimEnd('}') + ",\r\n  \"flattenA\": true\r\n}";

                if (!jsonConfig.TryGetProperty("flattenAaaa", out _))
                    updatedConfig = updatedConfig.TrimEnd('}') + ",\r\n  \"flattenAaaa\": true\r\n}";

                if (!jsonConfig.TryGetProperty("appPreference", out _))
                    updatedConfig = updatedConfig.TrimEnd('}') + ",\r\n  \"appPreference\": 100\r\n}";

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), updatedConfig);
            }
        }

        public async Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableFlattenCname)
                return response;

            if (response is null)
                return response;

            if (_bypassLocalZones && response.AuthoritativeAnswer)
                return response;

            if ((response.RCODE != DnsResponseCode.NoError) || response.Truncation)
                return response;

            DnsQuestionRecord question = request.Question[0];
            if (!ShouldProcessType(question.Type))
                return response;

            if (HasDnssecData(request, response))
                return response;

            string qname = NormalizeDomain(question.Name);
            if (string.IsNullOrWhiteSpace(qname))
                return response;

            if (IsBypassed(remoteEP.Address, qname))
                return response;

            RewriteResult rewriteResult = await RewriteAnswerAsync(qname, question.Type, response.Answer);
            if ((rewriteResult is null) || !rewriteResult.Changed)
                return response;

            List<DnsResourceRecord> authority = response.Authority is null ? null : new List<DnsResourceRecord>(response.Authority);

            return new DnsDatagram(
                response.Identifier,
                true,
                response.OPCODE,
                response.AuthoritativeAnswer,
                false,
                response.RecursionDesired,
                response.RecursionAvailable,
                false,
                false,
                DnsResponseCode.NoError,
                response.Question,
                rewriteResult.Answer,
                authority
            );
        }

        #endregion

        #region private

        private bool ShouldProcessType(DnsResourceRecordType qtype)
        {
            return ((qtype == DnsResourceRecordType.A) && _flattenA) || ((qtype == DnsResourceRecordType.AAAA) && _flattenAaaa);
        }

        private bool HasDnssecData(DnsDatagram request, DnsDatagram response)
        {
            if (request.DnssecOk || response.AuthenticData)
                return true;

            return ContainsRrsig(response.Answer) || ContainsRrsig(response.Authority) || ContainsRrsig(response.Additional);
        }

        private static bool ContainsRrsig(IReadOnlyList<DnsResourceRecord> records)
        {
            if (records is null)
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.RRSIG)
                    return true;
            }

            return false;
        }

        private bool IsBypassed(IPAddress remoteIP, string qname)
        {
            foreach (NetworkAddress network in _bypassNetworks)
            {
                if (network.Contains(remoteIP))
                    return true;
            }

            return IsBypassedDomain(qname);
        }

        private bool IsBypassedDomain(string name)
        {
            foreach (string bypassDomain in _bypassDomains)
            {
                if (DomainMatches(name, bypassDomain))
                    return true;
            }

            return false;
        }

        private bool IsFilteredDomain(string name)
        {
            if (_filterDomains.Length == 0)
                return true;

            foreach (string filterDomain in _filterDomains)
            {
                if (DomainMatches(name, filterDomain))
                    return true;
            }

            return false;
        }

        private bool ShouldFlattenName(string name)
        {
            return !IsBypassedDomain(name) && IsFilteredDomain(name);
        }

        private static bool DomainMatches(string name, string domain)
        {
            name = NormalizeDomain(name);
            domain = NormalizeDomain(domain);

            if (name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                return true;

            return name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
        }

        private async Task<RewriteResult> RewriteAnswerAsync(string qname, DnsResourceRecordType qtype, IReadOnlyList<DnsResourceRecord> answer)
        {
            if ((answer is null) || (answer.Count == 0))
                return null;

            List<DnsResourceRecord> rewrittenAnswer = new List<DnsResourceRecord>();
            HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string currentName = NormalizeDomain(qname);
            bool changed = false;

            for (int depth = 0; depth < _maxDepth; depth++)
            {
                if (!visited.Add(currentName))
                    return null;

                if (TryGetExistingAddressRecords(answer, currentName, qtype, out List<DnsResourceRecord> directAddressRecords, out _))
                {
                    rewrittenAnswer.AddRange(directAddressRecords);
                    return new RewriteResult(rewrittenAnswer, changed);
                }

                if (!TryGetAliasRecord(answer, currentName, out DnsResourceRecord aliasRecord, out string aliasTarget, out _))
                    return null;

                if (ShouldFlattenName(currentName))
                {
                    FlattenResult flattened = await ResolveFlattenedAsync(currentName, qtype, answer);
                    if ((flattened is not null) && (flattened.Addresses.Count > 0))
                    {
                        rewrittenAnswer.AddRange(CreateAddressRecords(currentName, qtype, flattened.Addresses, flattened.Ttl ?? _defaultTtl));
                        changed = true;
                        return new RewriteResult(rewrittenAnswer, changed);
                    }
                }

                rewrittenAnswer.Add(aliasRecord);
                currentName = aliasTarget;
            }

            return null;
        }

        private async Task<FlattenResult> ResolveFlattenedAsync(string startName, DnsResourceRecordType qtype, IReadOnlyList<DnsResourceRecord> seedAnswer)
        {
            string currentName = NormalizeDomain(startName);
            IReadOnlyList<DnsResourceRecord> currentAnswer = seedAnswer;
            HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            uint? minTtl = null;

            for (int depth = 0; depth < _maxDepth; depth++)
            {
                if (!visited.Add(currentName))
                    return null;

                if (TryGetAddresses(currentAnswer, currentName, qtype, out List<IPAddress> addresses, out uint? addressTtl))
                    return new FlattenResult(addresses, MinTtl(minTtl, addressTtl));

                if (TryGetAliasRecord(currentAnswer, currentName, out _, out string aliasTarget, out uint aliasTtl))
                {
                    minTtl = MinTtl(minTtl, aliasTtl);
                    currentName = aliasTarget;
                    continue;
                }

                DnsDatagram nextResponse;

                try
                {
                    nextResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(currentName, qtype, DnsClass.IN), _queryTimeout);
                }
                catch (TimeoutException)
                {
                    return null;
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                    return null;
                }

                if ((nextResponse is null) || (nextResponse.RCODE != DnsResponseCode.NoError) || nextResponse.Truncation)
                    return null;

                if (nextResponse.AuthenticData || ContainsRrsig(nextResponse.Answer) || ContainsRrsig(nextResponse.Authority) || ContainsRrsig(nextResponse.Additional))
                    return null;

                currentAnswer = nextResponse.Answer;
            }

            return null;
        }

        private static bool TryGetAliasRecord(IReadOnlyList<DnsResourceRecord> records, string ownerName, out DnsResourceRecord aliasRecord, out string aliasTarget, out uint aliasTtl)
        {
            if (records is not null)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (!DomainEquals(record.Name, ownerName))
                        continue;

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.CNAME:
                            aliasRecord = record;
                            aliasTarget = NormalizeDomain((record.RDATA as DnsCNAMERecordData).Domain);
                            aliasTtl = record.TTL;
                            return !string.IsNullOrWhiteSpace(aliasTarget);

                        case DnsResourceRecordType.ANAME:
                            aliasRecord = record;
                            aliasTarget = NormalizeDomain((record.RDATA as DnsANAMERecordData).Domain);
                            aliasTtl = record.TTL;
                            return !string.IsNullOrWhiteSpace(aliasTarget);
                    }
                }
            }

            aliasRecord = null;
            aliasTarget = null;
            aliasTtl = 0;
            return false;
        }

        private static bool TryGetExistingAddressRecords(IReadOnlyList<DnsResourceRecord> records, string ownerName, DnsResourceRecordType qtype, out List<DnsResourceRecord> addressRecords, out uint? minTtl)
        {
            addressRecords = new List<DnsResourceRecord>();
            minTtl = null;

            if (records is not null)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (!DomainEquals(record.Name, ownerName))
                        continue;

                    if (record.Type != qtype)
                        continue;

                    addressRecords.Add(record);
                    minTtl = MinTtl(minTtl, record.TTL);
                }
            }

            return addressRecords.Count > 0;
        }

        private static bool TryGetAddresses(IReadOnlyList<DnsResourceRecord> records, string ownerName, DnsResourceRecordType qtype, out List<IPAddress> addresses, out uint? minTtl)
        {
            addresses = new List<IPAddress>();
            minTtl = null;
            HashSet<string> uniqueAddresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (records is not null)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (!DomainEquals(record.Name, ownerName))
                        continue;

                    if (record.Type != qtype)
                        continue;

                    IPAddress address = null;

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                            address = (record.RDATA as DnsARecordData).Address;
                            break;

                        case DnsResourceRecordType.AAAA:
                            address = (record.RDATA as DnsAAAARecordData).Address;
                            break;
                    }

                    if (address is null)
                        continue;

                    string addressText = address.ToString();
                    if (uniqueAddresses.Add(addressText))
                    {
                        addresses.Add(address);
                        minTtl = MinTtl(minTtl, record.TTL);
                    }
                }
            }

            return addresses.Count > 0;
        }

        private static List<DnsResourceRecord> CreateAddressRecords(string ownerName, DnsResourceRecordType qtype, IReadOnlyList<IPAddress> addresses, uint ttl)
        {
            List<DnsResourceRecord> answer = new List<DnsResourceRecord>(addresses.Count);

            foreach (IPAddress address in addresses)
            {
                DnsResourceRecordData rdata = qtype switch
                {
                    DnsResourceRecordType.A => new DnsARecordData(address),
                    DnsResourceRecordType.AAAA => new DnsAAAARecordData(address),
                    _ => throw new NotSupportedException("Unsupported record type.")
                };

                answer.Add(new DnsResourceRecord(ownerName, qtype, DnsClass.IN, ttl, rdata));
            }

            return answer;
        }

        private static string[] NormalizeDomains(string[] domains)
        {
            if ((domains is null) || (domains.Length == 0))
                return [];

            string[] normalized = new string[domains.Length];

            for (int i = 0; i < domains.Length; i++)
                normalized[i] = NormalizeDomain(domains[i]);

            return normalized;
        }

        private static string NormalizeDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return string.Empty;

            return domain.Trim().TrimEnd('.').ToLowerInvariant();
        }

        private static bool DomainEquals(string left, string right)
        {
            return NormalizeDomain(left).Equals(NormalizeDomain(right), StringComparison.OrdinalIgnoreCase);
        }

        private static uint? MinTtl(uint? first, uint? second)
        {
            if (first.HasValue)
            {
                if (second.HasValue)
                    return Math.Min(first.Value, second.Value);

                return first.Value;
            }

            return second;
        }

        #endregion

        #region properties

        public string Description
        {
            get { return "Flattens CNAME and ANAME responses for selected domain names by rewriting the final answer section and returning synthesized A/AAAA records to the client."; }
        }

        public byte Preference
        {
            get { return _appPreference; }
        }

        #endregion

        #region nested types

        private sealed class FlattenResult
        {
            public FlattenResult(List<IPAddress> addresses, uint? ttl)
            {
                Addresses = addresses;
                Ttl = ttl;
            }

            public List<IPAddress> Addresses { get; }

            public uint? Ttl { get; }
        }

        private sealed class RewriteResult
        {
            public RewriteResult(List<DnsResourceRecord> answer, bool changed)
            {
                Answer = answer;
                Changed = changed;
            }

            public List<DnsResourceRecord> Answer { get; }

            public bool Changed { get; }
        }

        #endregion
    }
}
