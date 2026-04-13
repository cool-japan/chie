import { useState, useEffect } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Earnings from "./pages/Earnings";
import Content from "./pages/Content";
import Peers from "./pages/Peers";
import Settings from "./pages/Settings";
import Gamification from "./pages/Gamification";
import Transfers from "./pages/Transfers";
import Onboarding from "./pages/Onboarding";
import { onboardingApi } from "./lib/api";

function App() {
  const navigate = useNavigate();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    onboardingApi.isComplete().then((complete) => {
      if (!complete) {
        navigate("/onboarding");
      }
    }).catch(() => {
      // Ignore errors — e.g. during dev outside of Tauri context
    }).finally(() => {
      setChecked(true);
    });
  }, [navigate]);

  // Avoid rendering the main routes before we know whether to redirect.
  // The blank frame during this check is imperceptible in practice.
  if (!checked) {
    return null;
  }

  return (
    <Routes>
      <Route path="/onboarding" element={<Onboarding />} />
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="earnings" element={<Earnings />} />
        <Route path="content" element={<Content />} />
        <Route path="transfers" element={<Transfers />} />
        <Route path="peers" element={<Peers />} />
        <Route path="settings" element={<Settings />} />
        <Route path="gamification" element={<Gamification />} />
      </Route>
    </Routes>
  );
}

export default App;
