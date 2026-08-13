// 前端 i18n 框架：i18next + react-i18next。
// zh/en 双资源，fallback 中文（产品差异化：中文优先）。

import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zh from "./zh.json";
import en from "./en.json";

// init 携带内联资源时同步完成，模块被 import 即就绪
void i18n.use(initReactI18next).init({
  resources: {
    zh: { translation: zh },
    en: { translation: en },
  },
  // ask 弹窗固定中文优先；系统语言非中文时给英文
  lng: navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en",
  fallbackLng: "zh",
  interpolation: {
    escapeValue: false, // React 已做 XSS 转义
  },
});

export default i18n;
