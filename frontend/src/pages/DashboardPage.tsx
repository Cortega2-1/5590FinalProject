import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import "./DashboardPage.css";

const MODELS = ["ChatGPT", "Claude", "Gemini"];

const STATS = [
    { label: "Models Evaluated", value: "0 / 4" },
    { label: "Vulnerabilities Seeded", value: "0" },
    { label: "Detections Logged", value: "0" },
    { label: "Tests Run", value: "0" },
];

export default function DashboardPage() {
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleLogout = () => {
        logout();
        navigate("/login");
    };

    return (
        <div className="dash-root">
            {/* Sidebar */}
            <aside className="sidebar">
                <div className="sidebar-logo">
                    SECURE<span>EVAL</span>
                </div>
                <nav className="sidebar-nav">
                    <a href="#" className="nav-item active">
                        <span className="nav-icon">◈</span> Overview
                    </a>
                    <a href="#" className="nav-item">
                        <span className="nav-icon">◎</span> Idea 1 — Generate
                    </a>
                    <a href="#" className="nav-item">
                        <span className="nav-icon">◉</span> Idea 2 — Audit
                    </a>
                    <a href="#" className="nav-item">
                        <span className="nav-icon">◇</span> Results
                    </a>
                    <a href="#" className="nav-item">
                        <span className="nav-icon">◻</span> Reports
                    </a>
                </nav>
                <button className="sidebar-logout" onClick={handleLogout}>
                    ⏻ LOGOUT
                </button>
            </aside>

            {/* Main content */}
            <main className="dash-main">
                <header className="dash-header">
                    <div>
                        <h2>Research Dashboard</h2>
                        <p className="dash-subheading">5590 Final Project · Ortega &amp; Kahn</p>
                    </div>
                    <div className="dash-user">
                        <span className="user-dot" />
                        {user}
                    </div>
                </header>

                {/* Stats row */}
                <section className="stats-row">
                    {STATS.map((s) => (
                        <div className="stat-card" key={s.label}>
                            <span className="stat-value">{s.value}</span>
                            <span className="stat-label">{s.label}</span>
                        </div>
                    ))}
                </section>

                {/* Two panels */}
                <section className="panels-row">
                    {/* Idea 1 */}
                    <div className="panel">
                        <div className="panel-header">
                            <h3>Idea 1 — LLM as Developer</h3>
                            <span className="badge pending">Pending</span>
                        </div>
                        <p className="panel-desc">
                            Prompt each LLM to generate a secure login/signup system.
                            Evaluate output via static analysis and OWASP Top 10 pen testing.
                        </p>
                        <div className="model-list">
                            {MODELS.map((m) => (
                                <div className="model-row" key={m}>
                                    <span className="model-name">{m}</span>
                                    <span className="model-status">—</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Idea 2 */}
                    <div className="panel">
                        <div className="panel-header">
                            <h3>Idea 2 — LLM as Auditor</h3>
                            <span className="badge pending">Pending</span>
                        </div>
                        <p className="panel-desc">
                            Provide LLMs with a seeded vulnerable codebase. Measure detection
                            rate and false positive rate per model.
                        </p>
                        <div className="model-list">
                            {MODELS.map((m) => (
                                <div className="model-row" key={m}>
                                    <span className="model-name">{m}</span>
                                    <span className="model-status">—</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* Vuln checklist */}
                <section className="panel vuln-panel">
                    <div className="panel-header">
                        <h3>Seeded Vulnerability Checklist</h3>
                    </div>
                    <div className="vuln-grid">
                        {[
                            "Buffer Overflow (strcpy / gets)",
                            "SQL Injection",
                            "Cross-Site Scripting (XSS)",
                            "Cross-Site Request Forgery (CSRF)",
                            "Auth Bypass — Logic Error",
                            "Insecure Direct Object Reference (IDOR)",
                            "Hardcoded Credentials",
                        ].map((v) => (
                            <div className="vuln-item" key={v}>
                                <span className="vuln-check">☐</span>
                                <span>{v}</span>
                            </div>
                        ))}
                    </div>
                </section>
            </main>
        </div>
    );
}