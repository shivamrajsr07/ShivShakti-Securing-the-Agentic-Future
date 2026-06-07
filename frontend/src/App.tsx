import { useState } from "react";
import { Dashboard } from "./components/Dashboard";
import { Landing } from "./components/Landing";

export default function App() {
  const [view, setView] = useState<"landing" | "dashboard">("landing");
  return view === "landing" ? (
    <Landing onEnter={() => setView("dashboard")} />
  ) : (
    <Dashboard onBack={() => setView("landing")} />
  );
}
