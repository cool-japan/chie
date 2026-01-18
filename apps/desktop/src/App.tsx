import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Earnings from "./pages/Earnings";
import Content from "./pages/Content";
import Peers from "./pages/Peers";
import Settings from "./pages/Settings";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="earnings" element={<Earnings />} />
        <Route path="content" element={<Content />} />
        <Route path="peers" element={<Peers />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}

export default App;
