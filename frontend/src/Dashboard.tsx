import { useEffect, useState, useCallback } from "react";
import "./App.css";
import { useWebSocket } from "./useWebSocket";
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';
import { 
  Activity, AlertTriangle, ShieldCheck, Zap, Server, Database, Bell, X, CheckCircle2,
  FileText, Cpu, Search, BrainCircuit, Send, ArrowRight
} from "lucide-react";

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type Alert = {
  id: string;
  incident_id: string;
  severity: Severity;
  signal_type: string;
  value: number;
  baseline: number;
  z_score: number;
  reason: string;
  status: "OPEN" | "ACKED" | "SILENCED" | "RESOLVED";
  created_at: string;
};

type Point = {
  time: string;
  value: number;
  baseline: number;
};

const MAX_POINTS = 60;

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <p className="tooltip-label">{label}</p>
        <p className="tooltip-val current">Current: {payload[0]?.value?.toFixed(2) ?? 0}%</p>
        <p className="tooltip-val baseline">Baseline: {payload[1]?.value?.toFixed(2) ?? 0}%</p>
      </div>
    );
  }
  return null;
};

function Dashboard() {
  const [history, setHistory] = useState<Point[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [incidentActive, setIncidentActive] = useState(false);
  const [currentValue, setCurrentValue] = useState(0);
  const [baseline, setBaseline] = useState(0);
  const [, setZScore] = useState(0);
  const [linesProcessed, setLinesProcessed] = useState(0);
  const [severity, setSeverity] = useState<Severity>("LOW");

  useEffect(() => {
    if (!selectedAlert) return;
    const live = alerts.find((a) => a.id === selectedAlert.id);
    if (live && live.status !== selectedAlert.status) {
      setSelectedAlert(live);
    }
  }, [alerts, selectedAlert]);

  const handleWSMessage = useCallback((message: any) => {
    if (message.type === "snapshot") {
      setAlerts(message.data.alerts || []);
    } else if (message.type === "alert") {
      const alert = message.data;
      setAlerts((previous) => {
        const existing = previous.findIndex(a => a.id === alert.id);
        if (existing !== -1) {
          const next = [...previous];
          next[existing] = alert;
          return next;
        }
        return [alert, ...previous].slice(0, 10);
      });
      if (alert.status === "OPEN") {
         setSelectedAlert(alert);
         setIncidentActive(true);
      } else if (alert.status === "RESOLVED") {
         setIncidentActive(false);
      }
    } else if (message.type === "metric") {
      const tick = message.data;
      
      setCurrentValue(tick.error_rate ?? 0);
      setBaseline(tick.baseline ?? 0);
      setZScore(tick.z ?? 0);
      setLinesProcessed(tick.lines ?? 0);
      setSeverity((tick.severity as Severity) || "LOW");

      setHistory((prev) => {
         const val = tick.error_rate ?? 0;
         const base = tick.baseline ?? 0;
         const timeLabel = new Date(tick.ts * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second:'2-digit' });
         return [...prev.slice(-(MAX_POINTS - 1)), { time: timeLabel, value: val, baseline: base }];
      });
    }
  }, []);

  useWebSocket<any>("ws://localhost:8000/ws/alerts", handleWSMessage, {
    onOpen: () => console.info("[TREMOR] WS connected"),
    onError: (e) => console.warn("[TREMOR] WS error", e),
  });

  const acknowledgeAlert = () => {
    if (!selectedAlert) return;
    const updated = { ...selectedAlert, status: "ACKED" as const };
    setSelectedAlert(updated);
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  };

  const silenceAlert = () => {
    if (!selectedAlert) return;
    const updated = { ...selectedAlert, status: "SILENCED" as const };
    setSelectedAlert(updated);
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  };

  const isAnomaly = incidentActive;

  return (
    <div className="app">
      <div className="glow-bg"></div>
      
      <main className="dashboard">
        
        {/* PIPELINE VISUALIZATION */}
        <section className="pipeline-section animate-fade-in">
          <div className="panel-header borderless">
            <h2>Data Pipeline</h2>
            <span>Real-time ingestion and detection flow</span>
          </div>
          
          <div className="pipeline-container">
            <div className="pipeline-node active">
              <div className="node-icon"><FileText size={20} /></div>
              <div className="node-info">
                <strong>Tailer</strong>
                <span>{linesProcessed} msgs/s</span>
              </div>
            </div>
            
            <div className="pipeline-edge">
              <div className="edge-line"><div className="moving-light"></div></div>
            </div>

            <div className="pipeline-node active">
              <div className="node-icon"><Cpu size={20} /></div>
              <div className="node-info">
                <strong>Parser</strong>
                <span>Regex</span>
              </div>
            </div>

            <div className="pipeline-edge">
              <div className="edge-line"><div className="moving-light"></div></div>
            </div>

            <div className="pipeline-node active">
              <div className="node-icon"><Search size={20} /></div>
              <div className="node-info">
                <strong>Miner</strong>
                <span>Drain3</span>
              </div>
            </div>

            <div className="pipeline-edge">
              <div className="edge-line"><div className="moving-light"></div></div>
            </div>

            <div className={`pipeline-node ${isAnomaly ? 'anomaly-pulse' : 'active'}`}>
              <div className="node-icon"><BrainCircuit size={20} /></div>
              <div className="node-info">
                <strong>Engine</strong>
                <span className={isAnomaly ? "text-critical" : "text-safe"}>
                  {isAnomaly ? "ANOMALY" : "Normal"}
                </span>
              </div>
            </div>

            <div className="pipeline-edge">
              <div className="edge-line"><div className="moving-light"></div></div>
            </div>

            <div className="pipeline-node active">
              <div className="node-icon"><Send size={20} /></div>
              <div className="node-info">
                <strong>Sinks</strong>
                <span>WS/CloudWatch</span>
              </div>
            </div>
          </div>
        </section>

        {/* METRICS */}
        <section className="overview animate-slide-up">
          <div className="metric-card">
            <div className="metric-header">
              <span className="metric-label">LIVE ERROR RATE</span>
              <Activity className="metric-icon" size={16} />
            </div>
            <strong className="metric-value">{currentValue.toFixed(2)}<span className="unit">%</span></strong>
            <div className="metric-change">
              {isAnomaly ? (
                <span className="status-badge critical"><AlertTriangle size={12} /> HIGH ANOMALY</span>
              ) : (
                <span className="status-badge safe"><ShieldCheck size={12} /> Normal bounds</span>
              )}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span className="metric-label">DYNAMIC BASELINE</span>
              <Database className="metric-icon" size={16} />
            </div>
            <strong className="metric-value">{baseline.toFixed(2)}<span className="unit">%</span></strong>
            <div className="metric-change">
              <span className="status-badge neutral">EWMA Learning</span>
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span className="metric-label">INGESTION THROUGHPUT</span>
              <Server className="metric-icon" size={16} />
            </div>
            <strong className="metric-value">{linesProcessed}<span className="unit">/s</span></strong>
            <div className="metric-change">
              <span className="status-badge neutral">Logs processed</span>
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span className="metric-label">INCIDENT STATE</span>
              <Zap className="metric-icon" size={16} />
            </div>
            <strong className={`metric-value text-${severity.toLowerCase()}`}>
              {isAnomaly ? severity : "HEALTHY"}
            </strong>
            <div className="metric-change">
              <span className="status-badge plain">{isAnomaly ? alerts[0]?.incident_id : "No active incidents"}</span>
            </div>
          </div>
        </section>

        <div className="grid-layout animate-slide-up-delayed">
          {/* CHART */}
          <section className="panel chart-panel">
            <div className="panel-header">
              <div>
                <h2>Anomaly Detection Chart</h2>
                <span>Real-time deviation from baseline</span>
              </div>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#B05130" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#B05130" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorValueAnomaly" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#9A3E25" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#9A3E25" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.06)" vertical={false} />
                  <XAxis dataKey="time" stroke="rgba(0,0,0,0.38)" tick={{fontSize: 11, fill: 'rgba(0,0,0,0.54)'}} tickLine={false} axisLine={false} minTickGap={30} />
                  <YAxis stroke="rgba(0,0,0,0.38)" tick={{fontSize: 11, fill: 'rgba(0,0,0,0.54)'}} tickLine={false} axisLine={false} />
                  <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(0,0,0,0.2)', strokeWidth: 1, strokeDasharray: '4 4' }} />
                  <Area type="monotone" dataKey="baseline" stroke="rgba(0,0,0,0.38)" strokeDasharray="5 5" fill="none" strokeWidth={2} />
                  <Area 
                    type="monotone" 
                    dataKey="value" 
                    stroke={isAnomaly ? "#9A3E25" : "#B05130"} 
                    fillOpacity={1} 
                    fill={isAnomaly ? "url(#colorValueAnomaly)" : "url(#colorValue)"} 
                    strokeWidth={2} 
                    activeDot={{ r: 6, fill: isAnomaly ? "#9A3E25" : "#B05130", stroke: '#FFF', strokeWidth: 2 }} 
                    animationDuration={300}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* ALERTS LIST */}
          <section className="panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Incident Feed</h2>
                <span>Recent anomalies</span>
              </div>
              {alerts.length > 0 && (
                <span className="alert-count pulse-soft">
                  {alerts.length} ALERT{alerts.length !== 1 ? "S" : ""}
                </span>
              )}
            </div>

            <div className="alert-list">
              {alerts.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon-wrapper">
                    <CheckCircle2 size={32} />
                  </div>
                  <strong>System is stable</strong>
                  <span>No anomalies detected.</span>
                </div>
              ) : (
                alerts.map((alert) => (
                  <button
                    className={`alert-row severity-${alert.severity.toLowerCase()}`}
                    key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <div className="alert-indicator"></div>
                    <div className="alert-content">
                      <div className="alert-header">
                        <span className={`severity-tag severity-${alert.severity.toLowerCase()}`}>
                          {alert.severity}
                        </span>
                        <span className="alert-time">{alert.created_at || new Date().toLocaleTimeString()}</span>
                      </div>
                      <strong>{alert.signal_type}</strong>
                      <span className="alert-reason">{alert.reason}</span>
                    </div>
                    <ArrowRight className="alert-arrow" size={16} />
                  </button>
                ))
              )}
            </div>
          </section>
        </div>
      </main>

      {/* ALERT DRAWER */}
      {selectedAlert && (
        <div className="drawer-backdrop animate-fade-in" onClick={() => setSelectedAlert(null)}>
          <aside className="alert-drawer animate-slide-left" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <span className="metric-label">INCIDENT</span>
                <h2>{selectedAlert.incident_id || "INC-UNKNOWN"}</h2>
              </div>
              <button className="close-button" onClick={() => setSelectedAlert(null)}>
                <X size={20} />
              </button>
            </div>

            <div className={`drawer-severity bg-${selectedAlert.severity.toLowerCase()}`}>
              {selectedAlert.severity} SEVERITY
            </div>

            <div className="drawer-section">
              <span className="metric-label">SIGNAL SOURCE</span>
              <strong>{selectedAlert.signal_type}</strong>
            </div>

            <div className="drawer-grid">
              <div className="grid-box">
                <span className="metric-label">CURRENT</span>
                <strong>{selectedAlert.value}%</strong>
              </div>
              <div className="grid-box">
                <span className="metric-label">BASELINE</span>
                <strong>{selectedAlert.baseline}%</strong>
              </div>
              <div className="grid-box">
                <span className="metric-label">Z-SCORE</span>
                <strong>{selectedAlert.z_score}</strong>
              </div>
              <div className="grid-box">
                <span className="metric-label">STATUS</span>
                <strong className={`status-${selectedAlert.status.toLowerCase()}`}>{selectedAlert.status}</strong>
              </div>
            </div>

            <div className="drawer-section">
              <span className="metric-label">EXPLANATION</span>
              <div className="explanation-box">
                <p>{selectedAlert.reason}</p>
              </div>
            </div>

            <div className="drawer-actions">
              <button className="btn-primary" onClick={acknowledgeAlert}>
                <CheckCircle2 size={16} /> Acknowledge
              </button>
              <button className="btn-secondary" onClick={silenceAlert}>
                <Bell size={16} /> Silence
              </button>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
