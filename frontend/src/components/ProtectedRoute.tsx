import { Navigate } from "react-router-dom";
import { type ReactNode } from "react";

interface Props {
    children: ReactNode;
}

export default function ProtectedRoute({ children }: Props) {
    const isAuthenticated = !!sessionStorage.getItem("auth_user");
    return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}