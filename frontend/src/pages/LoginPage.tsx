import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import "./LoginPage.css";

export default function LoginPage() {
    const { login } = useAuth();
    const navigate = useNavigate();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError("");
        setLoading(true);

        const result = await login(username, password);
        if (result.success) {
            navigate("/dashboard");
        } else {
            setError(result.error ?? "Invalid credentials. Try again.");
        }
        setLoading(false);
    };

    return (
        <div className="login-root">
            <div className="login-bg">
                <div className="grid-overlay" />
            </div>

            <div className="login-card">
                <div className="login-header">
                    <div className="lock-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <rect x="3" y="11" width="18" height="11" rx="2" />
                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                    </div>
                    <h1>SECURE<span>EVAL</span></h1>
                    <p className="login-subtitle">LLM Security Research Platform</p>
                </div>

                <form onSubmit={handleSubmit} className="login-form">
                    <div className="field-group">
                        <label htmlFor="username">USERNAME</label>
                        <input
                            id="username"
                            type="text"
                            autoComplete="username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="enter username"
                            required
                        />
                    </div>

                    <div className="field-group">
                        <label htmlFor="password">PASSWORD</label>
                        <input
                            id="password"
                            type="password"
                            autoComplete="current-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="enter password"
                            required
                        />
                    </div>

                    {error && <p className="error-msg">⚠ {error}</p>}

                    <button type="submit" className="login-btn" disabled={loading}>
                        {loading ? (
                            <span className="btn-loading">
                <span />
                <span />
                <span />
              </span>
                        ) : (
                            "AUTHENTICATE"
                        )}
                    </button>
                </form>

                <p className="login-footer">
                    5590 Final Project · Ortega &amp; Kahn
                </p>
            </div>
        </div>
    );
}