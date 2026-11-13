# Ground-truth labeling notes

Publisher-source-only Evidence-First review. No TalonHound data, first-pass captures, or extraction output was opened.

| Report | Indicators | Context only | Ambiguous | Linked packages | Residual uncertainty |
|---|---:|---:|---:|---:|---|
| unseen-google-tag-apt42 | 43 | 0 | 0 | 0 | No residual uncertainty in the printed IOC section. |
| unseen-unit42-cairn | 2 | 0 | 0 | 0 | Thin but complete: only two IP IOCs. |
| unseen-groupib-ghost-stadium | 55 | 3 | 0 | 1 | Publisher says the blog is partial and labels the core-domain list a representative sample of 79, but only 32 core domains are rendered; customer-only identities remain unavailable. |
| unseen-unit42-falcon-c2 | 26 | 0 | 0 | 0 | Extension ID is unsupported; duplicate cross-browser hashes were deduplicated. |
| unseen-trend-teampcp | 1 | 1 | 0 | 1 | Thin in HTML: most identities are only in an unretained linked TXT package. |
| unseen-trend-kongtuke | 8 | 2 | 0 | 1 | Linked TXT package unretained; two direct-IP endpoints are described as likely C2, while Telegram and Dropbox are treated as legitimate context. |
| unseen-trend-installfix | 6 | 1 | 4 | 1 | Linked TXT package unretained; two outbound IPs, one dynamic C2 pattern, and get-version.com remain ambiguous. |
| unseen-rf-markirat | 68 | 0 | 0 | 0 | Appendix is complete; per-domain operational function is not specified. |
| unseen-huntress-sckit | 24 | 0 | 0 | 0 | Hash utility is weak by publisher warning because builds vary per host. |
| unseen-msft-gsocket | 8 | 3 | 0 | 0 | Intrusion-specific IOC table; legitimate GSocket project/CDN hosts labeled context_only. |

## Thin or blocked reports

- **unseen-unit42-cairn** is source-thin but fully labelable (two IPs).
- **unseen-trend-teampcp** is source-thin in retained HTML because the main IOC roster is a linked TXT file.
- **unseen-groupib-ghost-stadium** is partially blocked by a customer-only full report; all identities visible in the publisher HTML were labeled.
- **unseen-trend-kongtuke** and **unseen-trend-installfix** link IOC TXT files that were not retained with the experiment, so package identities remain unverified.
- No retained publisher HTML was unreadable or otherwise fully blocked.
