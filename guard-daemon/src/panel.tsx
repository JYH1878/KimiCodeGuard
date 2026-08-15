// 审计面板入口（M6）
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import PanelApp from "./PanelApp";
import "./i18n";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <PanelApp />
  </StrictMode>
);
