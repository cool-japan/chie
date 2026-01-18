import { Outlet, NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Wallet,
  HardDrive,
  Users,
  Settings,
} from "lucide-react";

function Layout() {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">C</div>
          <span className="sidebar-title">CHIE Node</span>
        </div>

        <nav className="sidebar-nav">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `nav-link ${isActive ? "active" : ""}`
            }
            end
          >
            <LayoutDashboard />
            <span>Dashboard</span>
          </NavLink>

          <NavLink
            to="/earnings"
            className={({ isActive }) =>
              `nav-link ${isActive ? "active" : ""}`
            }
          >
            <Wallet />
            <span>Earnings</span>
          </NavLink>

          <NavLink
            to="/content"
            className={({ isActive }) =>
              `nav-link ${isActive ? "active" : ""}`
            }
          >
            <HardDrive />
            <span>Content</span>
          </NavLink>

          <NavLink
            to="/peers"
            className={({ isActive }) =>
              `nav-link ${isActive ? "active" : ""}`
            }
          >
            <Users />
            <span>Peers</span>
          </NavLink>

          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `nav-link ${isActive ? "active" : ""}`
            }
          >
            <Settings />
            <span>Settings</span>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <div className="text-muted" style={{ fontSize: "12px", padding: "8px 16px" }}>
            v0.1.0 - CHIE Protocol
          </div>
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}

export default Layout;
