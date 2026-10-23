# TREMOR Detection Engine

TREMOR processes continuously growing log files in real time. It uses asynchronous tailing, structured log mining, and dynamic statistical baselining to detect anomalies within milliseconds of a log being written to disk.

## 1. Real-Time Log Tailing

TREMOR continuously monitors the log file using an asynchronous `Tailer` (`app/pipeline/tailer.py`).
- **Asynchronous Polling:** The system seeks to the end of the file, reads all available chunks, and yields them instantly. When it reaches EOF, it non-blockingly sleeps for `0.1s` before checking again. This is functionally identical to Linux `tail -f`.
- **Handling Truncation & Rotation:** If a log file is rotated or overwritten (causing the file size to suddenly decrease), the `Tailer` detects this via `os.stat` and automatically resets its cursor to byte `0`, ensuring uninterrupted ingestion.
- **Latency:** Because the tailer yields lines to an `asyncio.Queue` instantly, the ingestion latency from disk write to processing is typically **< 10ms**.

## 2. Dynamic Baseline Calculation (EWMA)

TREMOR does not rely on static thresholds (e.g., "Alert if error rate > 5%"). Instead, it learns what is "normal" for your application over time using an **Exponentially Weighted Moving Average (EWMA)**.

The `ErrorRateDetector` runs a strict loop every 1 second, analyzing a rolling 30-second arrival window.

### Phase 1: Warm-up (Learning)
When TREMOR starts, it needs to establish a baseline.
- It observes the error rate ($r = \text{errors} / n$) every tick.
- If traffic is sufficient ($n \ge \text{min\_events}$), it records the rate.
- It intentionally ignores ticks that breach the `rate_ceiling` or have active incidents to prevent learning "bad" behavior.
- Once `warmup_ticks` are collected, it seeds the initial baseline mean ($\mu$) and standard deviation ($\sigma$).

### Phase 2: Active Detection
Once warmed up, TREMOR evaluates every subsequent tick against the established baseline.
1. **Calculate Effective Sigma ($\sigma_{eff}$):** 
   TREMOR uses a binomial noise floor to prevent false positives during low-traffic periods.
   $$\sigma_{eff} = \max\left(\sigma, \sqrt{\frac{\mu(1-\mu)}{n}}, \sigma_{min}\right)$$
2. **Calculate Z-Score:**
   The Z-score represents how many standard deviations the current error rate is from the baseline.
   $$Z = \frac{r - \mu}{\sigma_{eff}}$$
3. **Severity Scoring:**
   The system triggers alerts based on the Z-score. Higher Z-scores map to higher severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). 
   *Note: If $r > \text{rate\_ceiling}$ (e.g., 25% errors), it immediately triggers a CRITICAL alert regardless of the Z-score.*

### Phase 3: Gated EWMA Updates
To adapt to slow, gradual changes in traffic (e.g., peak vs. off-peak hours), TREMOR continuously updates the baseline using an exponential decay factor ($\alpha$).

$$\mu_{new} = (1 - \alpha)\mu_{old} + \alpha r$$

**The Gating Mechanism:**
TREMOR will *only* update its baseline if the traffic is considered normal. 
If an incident is currently open, or if the Z-score is too high ($Z > \text{baseline\_update\_max\_z}$), the EWMA update is **gated (skipped)**. This is a critical feature: it prevents massive anomalies or prolonged outages from dragging the baseline upwards and "blinding" the system.

## 3. End-to-End Latency

The entire pipeline—from tailing the disk, mining the template via Drain3 (an $O(\text{depth})$ prefix-tree operation), updating the EWMA window, calculating the Z-score, and pushing the alert payload to the WebSocket—typically executes in **under 100 to 200 milliseconds**. 

This allows the frontend dashboard to reflect system state changes the exact moment they occur.
