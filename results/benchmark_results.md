# Benchmark Results

This table compares LINDEF against common IDS approaches using project results and literature-based ranges summarized in the AZSEF poster.

|Method|Detection Task|Detection Accuracy|False Positive Rate|Average Latency (ms)|RAM Usage (MB)|Model Size / Resource Notes|Source / Basis|Key Takeaway|
|---|---|---|---|---|---|---|---|---|
|LINDEF Binary Random Forest|Normal vs Attack|99.83%|0.21%|54.18|18.52|Lightweight local model|Project testing results from AZSEF poster|Highest detection accuracy and very low FPR, with latency slightly higher than some traditional IDS methods.|
|LINDEF Attack Classification Random Forest|Attack type classification|94.15%|0.37%|53.79|8.32|Lightweight local model|Project testing results from AZSEF poster|Classifies attack types with strong accuracy while keeping memory usage low.|
|Signature-Based IDS|Known attack signature matching|94%–98%|<1%|<5|50–200|Requires frequent signature updates|Literature-based range summarized in AZSEF poster|Very fast and strong for known attacks, but weaker against new or modified attacks.|
|Anomaly-Based IDS|Detects deviations from normal traffic|85%–95%|3%–5%|10–50|1,000–4,000|Can require large baseline training data|Literature-based range summarized in AZSEF poster|Useful for unusual traffic, but tends to have higher false positives and heavier memory use.|
|Cloud-Based Endpoint Detection|Device and endpoint behavior monitoring|96%–99%|2%|50–200|Varies; often reported as <5% of host resources|Cloud/vendor dependent; may raise privacy and alert fatigue concerns|Literature/vendor-based range summarized in AZSEF poster|Strong detection range, but may require vendor infrastructure and has variable local resource impact.|
|Rule-Based IDS|Manually written detection rules|90%–95%|1%–2%|5–15|200–500|Requires constant rule maintenance|Literature-based range summarized in AZSEF poster|Efficient and understandable, but depends heavily on manually maintained rules.|
