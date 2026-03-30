import { useState } from "react";

const SESSION_KEY = "auth_token";
const USER_KEY = "auth_user";
const API_URL = "http://localhost:8000";

export function useAuth() {
    const [user, setUser] = useState<string | null>(() =>
        sessionStorage.getItem(USER_KEY)
    );

    const login = async (
        username: string,
        password: string
    ): Promise<{ success: boolean; error?: string }> => {
        try {
            const res = await fetch(`${API_URL}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            const data = await res.json();

            if (!res.ok) {
                return { success: false, error: data.detail ?? "Login failed." };
            }

            sessionStorage.setItem(SESSION_KEY, data.access_token);
            sessionStorage.setItem(USER_KEY, username);
            setUser(username);
            return { success: true };
        } catch {
            return { success: false, error: "Cannot reach server. Is the backend running?" };
        }
    };

    const logout = () => {
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(USER_KEY);
        setUser(null);
    };

    const getToken = () => sessionStorage.getItem(SESSION_KEY);

    return { user, login, logout, getToken, isAuthenticated: !!user };
}