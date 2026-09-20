import { Gear } from "@phosphor-icons/react/Gear";
import { SignOut } from "@phosphor-icons/react/SignOut";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { signOut } from "../../api/authActions";
import { useAuthRefresh } from "../../features/auth/hooks/useCurrentUser";
import { ThemeControl } from "../../features/theme/ThemeControl";
import { InlineNotice } from "../ui/InlineNotice";

export function PanelAccountControls({ user }) {
  const navigate = useNavigate();
  const refresh = useAuthRefresh();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function logout() {
    setBusy(true);
    setError("");

    try {
      await signOut();
      await refresh();
      navigate("/login");
    } catch {
      setError("Could not sign out. Try again.");
      setBusy(false);
    }
  }

  return (
    <div className="panel-account-controls">
      <div className="workspace-account">
        <span className="account-initial" aria-hidden="true">
          {user?.email?.[0]?.toUpperCase() ?? "W"}
        </span>
        <div>
          <strong>{user?.email}</strong>
          <small>{user?.tier ?? "free"} workspace</small>
        </div>
      </div>

      <div className="panel-account-actions">
        <Link className="workspace-link panel-account-action" to="/settings">
          <Gear size={16} aria-hidden="true" />
          <span>Settings</span>
        </Link>
        <div className="panel-appearance">
          <span>Appearance</span>
          <ThemeControl />
        </div>
        <button
          className="workspace-link panel-account-action signout"
          disabled={busy}
          onClick={logout}
          type="button"
        >
          <SignOut size={16} aria-hidden="true" />
          <span>{busy ? "Signing out…" : "Sign out"}</span>
        </button>
      </div>

      {error && <InlineNotice tone="danger">{error}</InlineNotice>}
    </div>
  );
}
