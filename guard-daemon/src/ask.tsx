// ask 弹窗入口
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import AskApp from "./AskApp";
import "./i18n";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AskApp />
  </StrictMode>
);
