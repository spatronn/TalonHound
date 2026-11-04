# Historical replay difference ledger

Read-only comparison of stored Indicator membership with a deterministic replay of each stored document, generated 2026-11-04 against production f17c452 data (690 finalized reports). Nothing here changed a stored row: no report was refreshed and no membership or analyst decision was altered.

"Replay" runs what a Refresh extraction would compute, with analyst decisions preserved, using the contract in this change.

## Summary

| Class | Reports |
|---|---|
| intended improvement | 6 |
| uncertain | 6 |
| legacy behavior | 15 |
| confirmed regression, fixed | 3 |
| **Total** | **30** |

## Matrix

| Report | Title | Stored | Replay | + | − | Rules | Class |
|---|---|---|---|---|---|---|---|
| 10 | PurpleBravo’s Targeting of the IT Software Supply Ch | 243 | 244 | 1 | 0 | R41 | legacy behavior |
| 15 | Illegal Gambling Sites Reveal Three Types of Cybercr | 24 | 25 | 1 | 0 | R41 | uncertain |
| 18646 | How Fake OpenClaw Installers Spread GhostSocks Malwa | 32 | 35 | 3 | 0 | R40 | uncertain |
| 24456 | ChainDrop: Inside a Self-Propagating npm Worm | 10 | 10 | 0 | 0 | fixed | confirmed regression, fixed |
| 30278 | Breaking the Seal: Static Deobfuscation of JSCeal’s  | 120 | 119 | 0 | 1 | R33 | intended improvement |
| 30305 | Learn more about the DEV#POPPER remote access trojan | 3 | 4 | 1 | 0 | R41 | legacy behavior |
| 30328 | Remote Monitoring and Management (RMM) Tooling Incre | 19 | 19 | 1 | 1 | R10, not | intended improvement |
| 30330 | QuickFox Supply Chain Attack Used to Deploy FDMTP Im | 145 | 144 | 0 | 1 | R20 | uncertain |
| 31339 | #StopRansomware: RansomHub Ransomware \| CISA | 123 | 122 | 0 | 1 | not | intended improvement |
| 31388 | Amazon-Themed ClickFix Campaign Serves Up Finger-Lic | 23 | 24 | 1 | 0 | R41 | legacy behavior |
| 33340 | Post-DEF CON Phishing Uses Malicious Google Doc to D | 30 | 31 | 1 | 0 | R41 | uncertain |
| 33342 | Wallet-Depleting macOS Malware Wants Your Crypto | 8 | 9 | 1 | 0 | R41 | uncertain |
| 34343 | Tracking Iranian APT Screening Serpens’ 2026 Espiona | 37 | 37 | 1 | 1 | R10, not | uncertain |
| 35418 | The npm Threat Landscape: Attack Surface and Mitigat | 32 | 33 | 1 | 0 | R10 | intended improvement |
| 35456 | Supply Chain Attack Against Chrome Browser Extension | 80 | 82 | 2 | 0 | R42 | legacy behavior |
| 35477 | Weaponized in China, Deployed in India: The SyncFutu | 21 | 22 | 1 | 0 | R41 | legacy behavior |
| 35484 | Russian State-Supported Cyber Actors Conduct Phishin | 22 | 31 | 9 | 0 | R10 | intended improvement |
| 35550 | NIK C2: The new AI-enabled command-and-control frame | 0 | 1 | 1 | 0 | R41 | legacy behavior |
| 35554 | ClearFake WebDAV infection chain delivers Amatera st | 0 | 14 | 14 | 0 | R41, R42, R40 | legacy behavior |
| 35559 | UAT-10147: Chinese-speaking adversary integrates age | 0 | 1 | 1 | 0 | R41 | legacy behavior |
| 35560 | UAT-11795 deploys novel Starland RAT and bespoke WLD | 0 | 1 | 1 | 0 | R41 | legacy behavior |
| 35563 | ARToken: Inside an EvilTokens affiliate panel target | 2 | 3 | 1 | 0 | R42 | legacy behavior |
| 35564 | CloudZ RAT potentially steals OTP messages using Phe | 0 | 1 | 1 | 0 | R41 | legacy behavior |
| 35572 | Knife Cutting the Edge: Disclosing a China-nexus gat | 0 | 6 | 6 | 0 | R40, R41, R42 | legacy behavior |
| 35613 | ErrTraffic: A Growing ClickFix Malware Distribution  | 0 | 2 | 2 | 0 | R41 | legacy behavior |
| 35627 | xlabs_v1 DDoS-for-Hire Operation Exposed | 12 | 12 | 0 | 0 | fixed | confirmed regression, fixed |
| 35665 | Pluribus and the Path to Domain Compromise: A Modelo | 15 | 20 | 5 | 0 | R42, R41 | legacy behavior |
| 35675 | RATatouille: Today's Special | 6 | 6 | 0 | 0 | fixed | confirmed regression, fixed |
| 35690 | False Protection, Emptied Accounts: The Seven Androi | 117 | 118 | 1 | 0 | R10 | intended improvement |
| 35709 | Mind the (Patch) Gap: Multiple Chinese Threat Actors | 21 | 22 | 1 | 0 | R41 | legacy behavior |

## Detail

### 10: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `md5:bb167fc8cdca3b8c009dab3ec460be7c`: R41_operational_statement, stored review approved, IOC linked, section "HTTP Channel"

### 15: uncertain

Analyst approved and linked; the independent label says not an Indicator (url:js.cache-mcp.com/layer.js). Rule R41.

**Recommendation:** Analyst re-check against the source. The stored approval stands.

- Replay adds `url:js.cache-mcp.com/layer.js`: R41_operational_statement, stored review approved, IOC linked, label false, section "Type 3: PeckBirdy Malware C2 Domains Embedded into Chinese-l"

### 18646: uncertain

Analyst approved and linked; the independent label says not an Indicator (sha256:249058ce8dc6e74cff9fb84d4d32c82e3, sha256:0b6ed577b993fd81e14f9abbef710e881, sha256:b73bd2e4cb16e9036aa7125587c5b3289). Rule R40.

**Recommendation:** Analyst re-check against the source. The stored approval stands.

- Replay adds `sha256:249058ce8dc6e74cff9fb84d4d32c82e371265b40d02bb70b7955dceea008139`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, label false, section "Figure 9: moltworker code comparison to OpenClaw-Installer s"
- Replay adds `sha256:0b6ed577b993fd81e14f9abbef710e881629b8521580f3a127b2184685af7e05`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, label false, section "Figure 9: moltworker code comparison to OpenClaw-Installer s"
- Replay adds `sha256:b73bd2e4cb16e9036aa7125587c5b3289e17e62f8831de1f9709896797435b82`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, label false, section "Figure 9: moltworker code comparison to OpenClaw-Installer s"

### 24456: confirmed regression, fixed

SHA-256 typed as a similarity digest because its row says "based on TLSH pivot". Replay now returns it as `sha256`, R10.

**Recommendation:** None.

Values: sha256:b27b82af…c678


### 30278: intended improvement

Analyst ignored `iapi.kraken.com`, a legitimate service named in decoded code. The legacy reading still counts the row; the replay does not.

**Recommendation:** None.

- Replay removes `domain:iapi.kraken.com`: R33_mention_needs_review, stored review ignored, IOC linked, section "Cryptocurrency account and balance collection"

### 30305: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `ip:23.27.20.143`: R41_operational_statement, stored review approved, IOC linked, section "Stage 2 Analysis"

### 30328: intended improvement

Identity repair: the stored URL keeps a trailing `\` from the publisher cell. The replay reads the URL without it. On a refresh the IOC link would need to follow the new identity.

**Recommendation:** Leave as stored unless the report is refreshed; the refresh guard would surface it.

- Replay adds `url:https://online.invoicesing.es/Bin/Statement.ClientSetup.exe?e=Access&y=Guest&c=Black_Cat&c=&c=&c=&c=&c=&c=`: R10_publisher_assertion, stored review no row, section "Example IOCs"
- Replay removes `url:https://online.invoicesing.es/Bin/Statement.ClientSetup.exe?e=Access&y=Guest&c=Black_Cat&c=&c=&c=&c=&c=&c=`: not_extracted, stored review approved, IOC linked

### 30330: uncertain

The publisher row calls this URL the download of a legitimate Google Firebase script, in a Network Indicators table about a supply-chain attack. Stance now wins over the row; the analyst approved it.

**Recommendation:** Analyst re-check. The stored approval stands.

- Replay removes `url:cdns3.51quickfox.cn/script/firebase-analytics-compat.js`: R20_publisher_stance, stored review approved, IOC linked, section "Network Indicators"

### 31339: intended improvement

Identity repair: the stored URL ends in a literal `&nbsp` from the publisher HTML. The replay already holds the clean URL as a member. The committed label copies the artifact, which is why it shows as the one absent FN.

**Recommendation:** Correct the label by hand; merge the stored identity on any later refresh.

- Replay removes `url:https://samuelelena.co/npm/module.external/jquery.min.js&nbsp`: not_extracted, stored review approved, IOC linked, label true

### 31388: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `domain:kiriosyka.com`: R41_operational_statement, stored review approved, IOC linked, section "Command processors like PowerShell"

### 33340: uncertain

Analyst approved and linked; the independent label says not an Indicator (domain:1foqo.lat). Rule R41.

**Recommendation:** Analyst re-check against the source. The stored approval stands.

- Replay adds `domain:1foqo.lat`: R41_operational_statement, stored review approved, IOC linked, label false, section "Creates a PowerShell file at %TEMP%\sys.ps1"

### 33342: uncertain

Analyst approved and linked; the independent label says not an Indicator (sha256:b43a909a01e954d6549558f2f7e9bb58e). Rule R41.

**Recommendation:** Analyst re-check against the source. The stored approval stands.

- Replay adds `sha256:b43a909a01e954d6549558f2f7e9bb58e34959a0ae229f340d61091ab726bbd3`: R41_operational_statement, stored review approved, IOC linked, label false, section "chmod +x com.apple.verified: Flags the downloaded file as an"

### 34343: uncertain

The publisher redacted the file name: `?filename=remote.[REDACTED].zip`. The stored URL stops at `remote` and the replay at `remote.[REDACTED`. Neither is a usable identity.

**Recommendation:** Analyst decides on any later refresh. Consider a rule treating a redacted URL as non-actionable.

- Replay adds `url:https://docspace-twpf0e.onlyoffice.com/storage/files/root/folder_3765000/file_3764519/v1/content.zip?filen`: R10_publisher_assertion, stored review no row, section "URLs:"
- Replay removes `url:https://docspace-twpf0e.onlyoffice.com/storage/files/root/folder_3765000/file_3764519/v1/content.zip?filen`: not_extracted, stored review approved, IOC linked

### 35418: intended improvement

A typed table row now asserts the IP. The stored row was left pending.

**Recommendation:** Analyst review on the report; no automatic change.

- Replay adds `ip:85.137.53.71`: R10_publisher_assertion, stored review pending, IOC linked, section "Indicators From July 14, 2026 Miasma Activity"

### 35456: legacy behavior

Analyst approved and linked 2 value(s) outside the curated inventory (R42). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `sha256:b0827dc54349b10098a7370ada4ea44ba668b264ccca2db5676be1c32e6cc154`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Extensions’ malicious code"
- Replay adds `sha256:d303047205dabec8e2d34431e920ebe3478ca80a18f57bf454da094aca0e10aa`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Extensions’ malicious code"

### 35477: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `ip:8.217.152.225`: R41_operational_statement, stored review approved, IOC linked, section "Figure 9 – Time Retrieval function with hardcoded Domain nam"

### 35484: intended improvement

Nine approved rows are now recognised as publisher assertions (R10). The legacy reading did not count them.

**Recommendation:** None.

- Replay adds `domain:i.zmailanalytics.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.zimbra-metadata.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.analyticemailmeter.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.emailanalytics.com.ua`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.mailnalysis.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.zimbrastat.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.zimbrasoft.com.ua`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.synacorzimbra.nl`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"
- Replay adds `domain:i.istc-cloud.com`: R10_publisher_assertion, stored review approved, IOC linked, section "Table 8: Flowerbed X.509 certificate SHA-1 hashes"

### 35550: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `ip:87.120.196.120`: R41_operational_statement, stored review approved, IOC linked, section "Active NIK C2 server seen in the wild"

### 35554: legacy behavior

Analyst approved and linked 14 value(s) outside the curated inventory (R41, R42, R40). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `url:https://telegra.ph/Functions-04-03`: R41_operational_statement, stored review approved, IOC linked, section ""pf.ch" loaded Amatera resolves its C2 through a Telegraph p"
- Replay adds `url:https://kr.cedar2glanz.ru/jewel.js`: R41_operational_statement, stored review approved, IOC linked, section "PowerShell in the "verification.google" branch installs NetS"
- Replay adds `ip:145.249.109.147`: R41_operational_statement, stored review approved, IOC linked, section ""pf.ch" loaded Amatera resolves its C2 through a Telegraph p"
- Replay adds `sha256:279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92`: R42_grounded_model_assessment, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `sha256:643ef35536ff9273fb84b8504467b1a5645cd3ffd5476d64b99244b02131b205`: R41_operational_statement, stored review approved, IOC linked, section "Go payload turns the host into a reverse TCP proxy"
- Replay adds `sha256:1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Go payload turns the host into a reverse TCP proxy"
- Replay adds `sha256:bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b`: R42_grounded_model_assessment, stored review approved, IOC linked, section "PowerShell in the "verification.google" branch installs NetS"
- Replay adds `domain:fd.gstats-api-contact.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:pkg.vogueatelier.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:kffd3.vogueatelier.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:kffd3.vexlatech.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:static.quorashift.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:lb.propertyfind.cc`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "NativeAOT chain runs ZigCryptoStealer"
- Replay adds `domain:update.dubbedmuch.cc`: R41_operational_statement, stored review approved, IOC linked, section "Go payload turns the host into a reverse TCP proxy"

### 35559: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `ip:139.180.197.150`: R41_operational_statement, stored review approved, IOC linked, section "UAT-10147 OPSEC failure"

### 35560: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `domain:aipythondevs.com`: R41_operational_statement, stored review approved, IOC linked, section "Threat actor infrastructure"

### 35563: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R42). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `domain:dashboard-bl.pamconj.com`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Discovery: The ARToken Panel"

### 35564: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `ip:185.196.10.136`: R41_operational_statement, stored review approved, IOC linked, section "Modular CloudZ RAT delivered as payload"

### 35572: legacy behavior

Analyst approved and linked 6 value(s) outside the curated inventory (R40, R41, R42). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `url:http://43.132.205.118:81/app/minibrowser11_rpl.zip`: R40_structured_rows_uncertain_section, stored review approved, IOC linked, section "Link between DKnife and WizardNet campaigns"
- Replay adds `url:http://47.93.54.134:8005/`: R41_operational_statement, stored review approved, IOC linked, section "The DKnife downloader"
- Replay adds `url:http://117.175.185.81:8003/`: R41_operational_statement, stored review approved, IOC linked, section "Dkupdate.bin"
- Replay adds `sha256:2550aa4c4bc0a020ec4b16973df271b81118a7abea77f77fec2f575a32dc3444`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Shadowpad and DarkNimbus backdoors"
- Replay adds `sha256:43891d3898a54a132d198be47a44a8d4856201fa7a87f3f850432ba9e038893a`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Shadowpad and DarkNimbus backdoors"
- Replay adds `sha256:17a2dd45f9f57161b4cc40924296c4deab65beea447efb46d3178a9e76815d06`: R42_grounded_model_assessment, stored review approved, IOC linked, section "The DKnife downloader"

### 35613: legacy behavior

Analyst approved and linked 2 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `domain:webanalytics-cdn.sbs`: R41_operational_statement, stored review approved, IOC linked, section "Among other actions, the attacker modified the following fil"
- Replay adds `domain:chatgpt-web.vip`: R41_operational_statement, stored review approved, IOC linked, section "ChatGPT themed"

### 35627: confirmed regression, fixed

A benign host inside a behaviour sentence in an Indicator | Meaning table was asserted. It is now row context, R20.

**Recommendation:** None.

Values: domain:speedtest.net


### 35665: legacy behavior

Analyst approved and linked 5 value(s) outside the curated inventory (R42, R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `sha256:930263c0843744e269b615fb2ec79f83d7bd8b2cbf75e31fd5ea6c1aaa4e48fd`: R42_grounded_model_assessment, stored review approved, IOC linked, section "The HTTP shell – internal.py"
- Replay adds `sha256:b00c1cbcfb98d2618a5c2ccb311da94f3c57709a397be6c8de29839f4e943976`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Stage 3: Privilege escalation via CVE-2023-36036"
- Replay adds `sha256:d84245f3a374dd5eff8ecfdfad39077d76331fde799e5306430d0fc788db7f1d`: R41_operational_statement, stored review approved, IOC linked, section "Stage 3: Privilege escalation via CVE-2023-36036"
- Replay adds `sha256:30e5a6c982396cdf3157195b540f75096869baa8570f66fab88c07c161be27f0`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Stage 5: The lock screen that wasn't"
- Replay adds `sha256:f5b2dbd8ec9671c0261f093ebc5f3d35920b592458a3b800cc946265111e67d0`: R42_grounded_model_assessment, stored review approved, IOC linked, section "Stage 5: The lock screen that wasn't"

### 35675: confirmed regression, fixed

The publisher writes `chumchuru.Com`, `chumchurum.Org`. A title-cased TLD read as a code identifier, so all five approved domains dropped out of extraction. They were not lost silently (disposition `incidental_identifier`), but they were not candidates.

**Recommendation:** None. Five values remain analyst-approved and linked.

Values: chumchuru.com, chumchurum.org, chumchurum.xyz, chumchurumc.com, chumchurumcc.com


### 35690: intended improvement

A `ws://` endpoint in the C2 section is now its own URL. The IP is already approved.

**Recommendation:** No action until a refresh.

- Replay adds `url:ws://64.89.163.3:8082/`: R10_publisher_assertion, stored review no row, section "C2-addresses:"

### 35709: legacy behavior

Analyst approved and linked 1 value(s) outside the curated inventory (R41). Rows without a stored outcome keep the legacy reading, which does not count them; the current reading counts an approved review as a member.

**Recommendation:** None. Stored rows stay as they are; the IOC links already exist.

- Replay adds `domain:photos.msbenefit.com`: R41_operational_statement, stored review approved, IOC linked, section "Chrome and Windows Exploit Chain"
