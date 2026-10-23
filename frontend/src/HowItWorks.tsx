import { Link } from "react-router-dom";
import "./HowItWorks.css";

function HowItWorks() {
  const steps = [
    {
      number: "01",
      title: "Logs Enter TREMOR",
      description:
        "TREMOR continuously receives application and service logs through its ingestion layer. Incoming events are normalized so they can be analyzed consistently.",
      icon: "↓",
    },
    {
      number: "02",
      title: "Log Patterns Are Learned",
      description:
        "The system groups similar log messages into templates and learns the normal behavior of each service over time.",
      icon: "◈",
    },
    {
      number: "03",
      title: "Anomalies Are Detected",
      description:
        "TREMOR compares the current behavior of a service against its learned baseline to identify unusual error rates, bursts, and rare patterns.",
      icon: "⌁",
    },
    {
      number: "04",
      title: "Severity Is Determined",
      description:
        "Detected anomalies are evaluated using their deviation from the baseline and the characteristics of the event to determine an appropriate severity.",
      icon: "⚠",
    },
    {
      number: "05",
      title: "Alerts Are Created",
      description:
        "When an anomaly crosses the detection threshold, TREMOR creates an alert with context about the affected service and the reason it was triggered.",
      icon: "!",
    },
    {
      number: "06",
      title: "You Investigate",
      description:
        "The dashboard gives you a live view of metrics and alerts so you can understand what happened and investigate the affected service.",
      icon: "→",
    },
  ];

  return (
    <div className="how-page">
      <main>
        <section className="how-hero">
          <div className="how-eyebrow">UNDER THE HOOD</div>

          <h1>
            From raw logs to
            <br />
            <span>actionable alerts.</span>
          </h1>

          <p>
            TREMOR continuously learns what normal looks like for your
            services, detects deviations in real time, and turns them into
            alerts you can investigate.
          </p>
        </section>

        <section className="pipeline">
          <div className="section-label">THE PIPELINE</div>

          <div className="steps">
            {steps.map((step, index) => (
              <div className="step" key={step.number}>
                <div className="step-number">{step.number}</div>

                <div className="step-line">
                  <div className="step-icon">{step.icon}</div>
                  {index !== steps.length - 1 && (
                    <div className="connector" />
                  )}
                </div>

                <div className="step-content">
                  <h2>{step.title}</h2>
                  <p>{step.description}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="detection-section">
          <div className="detection-copy">
            <div className="section-label">WHAT TREMOR LOOKS FOR</div>

            <h2>
              Not every unusual
              <br />
              event is the same.
            </h2>

            <p>
              TREMOR evaluates different signals from your services instead
              of relying on a single threshold. This allows the system to
              distinguish normal variation from behavior that deserves
              attention.
            </p>
          </div>

          <div className="signal-grid">
            <div className="signal-card">
              <div className="signal-icon">↑</div>
              <h3>Error bursts</h3>
              <p>
                Detect sudden increases in error activity compared with normal
                service behavior.
              </p>
            </div>

            <div className="signal-card">
              <div className="signal-icon">◌</div>
              <h3>Rare templates</h3>
              <p>
                Surface log patterns that appear infrequently within the
                learned service behavior.
              </p>
            </div>

            <div className="signal-card">
              <div className="signal-icon">≈</div>
              <h3>Baseline deviation</h3>
              <p>
                Identify current behavior that significantly differs from the
                established baseline.
              </p>
            </div>

            <div className="signal-card">
              <div className="signal-icon">!</div>
              <h3>Severity</h3>
              <p>
                Give detected events context so the most significant anomalies
                can receive appropriate attention.
              </p>
            </div>
          </div>
        </section>

        <section className="how-cta">
          <div>
            <div className="section-label">SEE IT IN ACTION</div>
            <h2>Watch your services in real time.</h2>
            <p>
              Explore the TREMOR dashboard to see metrics, active alerts, and
              service activity in one place.
            </p>
          </div>

          <Link to="/dashboard" className="cta-button">
            Open Dashboard <span>→</span>
          </Link>
        </section>
      </main>
    </div>
  );
}

export default HowItWorks;