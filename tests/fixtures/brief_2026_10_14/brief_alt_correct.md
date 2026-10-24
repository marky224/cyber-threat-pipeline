# Weekly OTX Brief — 2026-10-14

## Headline

Thirty-five new pulses arrived in the last 7 days, led by a 301-indicator report on Android phones that ship with malicious firmware.

## Emerging threats

- **Pre-infected Android phones.** "Midnight Mimosa" covers devices in seven countries, among them the United States, Brazil and Mexico, running ad-fraud and click-fraud modules with system privileges. (id=6accbe14102992eb5a52b063)
- **Mass exploitation.** The ClingSTUN backdoor report tags 31 CVEs across routers and IoT devices, and the Langflow report tags another 12. NetScaler's two zero-days, CVE-2026-88771 and CVE-2026-88772, are being exploited in production. (id=6ac4285a7c6e1cd492e8b2cf, id=6ac5f1632c72bc95740deede, id=6ac9eef4bcc05a59cd402770)
- **Stealers and fake installers.** Warden Stealer (77 indicators) goes after AI agent data, and a fake WatchGuard VPN site hands out a genuine signed client while stealing credentials. (id=6ac89a6e10be1d80cdf57417, id=6acec272f01b1f0cac6ecb2a)
- **State-linked activity.** Kimsuky shows up in 2 pulses, one aimed at Ukrainian experts and one spreading Funhouse ransomware. Seven governments issued warnings about PRC tools tied to Flax Typhoon. (id=6ace37f3bfe7f0829254f7bf, id=6accdd88406e67c287aa23a5, id=6ac84a155bb626a3710179b9)
- **Supply chain.** NEBULA's seven fake AI SDK packages on npm install a Windows RAT, and a compromised TensorLake SDK carries the Shai-Hulud worm. (id=6ac8a46214e2077a0bfe7409, id=6ac7415f2754c1b2193c9737)

## Contrast with the corpus

- Ukraine is targeted by three of the new pulses yet is absent from the corpus top-5 countries, which the United States leads with 81 pulses.
- This week's new indicators are mostly file hashes: 285 MD5, 222 SHA256 and 129 SHA1, against 228 new domains and 108 IPv4 addresses.
- Active indicators make up about 96% of the corpus — roughly 24,000 of about 25,000.

## Analyst caveats

- Indicator counts per pulse range from 2 to 301, so pulse size says more about the reporter than about the threat.
- Victim impact and dwell time are not in the data.
