import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  // 防止 Vite 清屏时把 Tauri 的 Rust 编译输出一并清掉
  clearScreen: false,

  // Tauri dev 要求固定端口
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // 不监听 src-tauri 的 Rust 构建产物
      ignored: ["**/src-tauri/**"],
    },
  },

  build: {
    outDir: "dist",
    // 单窗口入口：ask.html = ask 弹窗（托盘应用无主面板）
    rollupOptions: {
      input: {
        ask: fileURLToPath(new URL("./ask.html", import.meta.url)),
        panel: fileURLToPath(new URL("./panel.html", import.meta.url)),
      },
    },
  },
});
