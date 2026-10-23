import { Link, useLocation } from "react-router-dom";
import { Zap } from "lucide-react";
import "./Navbar.css";

export function Navbar() {
  const location = useLocation();

  return (
    <nav className="global-nav">
      <div className="nav-brand">
        <Link to="/" className="brand-link">
          <Zap size={24} className="brand-icon" />
          TREMOR
        </Link>
      </div>

      <div className="nav-links">
        <Link to="/how-it-works" className={location.pathname === "/how-it-works" ? "active" : ""}>
          How it works
        </Link>
        <Link to="/dashboard" className={location.pathname === "/dashboard" ? "active" : ""}>
          Dashboard
        </Link>
        <a href="https://github.com/VaradSinghal/TREMOR" target="_blank" rel="noreferrer">
          GitHub
        </a>
      </div>

      <div className="nav-actions">
        {location.pathname === "/dashboard" ? (
          <div className="system-status">
            <span className="status-dot pulse" />
            WS LIVE
          </div>
        ) : (
          <Link to="/dashboard" className="nav-button">
            Launch Dashboard
          </Link>
        )}
      </div>
    </nav>
  );
}
