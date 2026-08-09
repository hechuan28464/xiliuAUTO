import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import App from "./App.vue";
import TasksView from "./views/TasksView.vue";
import CreateView from "./views/CreateView.vue";
import BoardView from "./views/BoardView.vue";
import SettingsView from "./views/SettingsView.vue";
import HardTargetsView from "./views/HardTargetsView.vue";
import IntelView from "./views/IntelView.vue";
import VulnsView from "./views/VulnsView.vue";
import RuntimeLogsView from "./views/RuntimeLogsView.vue";
import AssetsView from "./views/AssetsView.vue";
import VulnDashboardView from "./views/VulnDashboardView.vue";
import UserManageView from "./views/UserManageView.vue";
import AuditLogView from "./views/AuditLogView.vue";
import NotifySettingsView from "./views/NotifySettingsView.vue";
import HitlApprovalView from "./views/HitlApprovalView.vue";
import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import "./style.css";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", component: TasksView },
    { path: "/create", component: CreateView },
    { path: "/hard-targets", component: HardTargetsView },
    { path: "/intel", component: IntelView },
    { path: "/vulns", component: VulnsView },
    { path: "/vuln-dashboard", component: VulnDashboardView },
    { path: "/assets", component: AssetsView },
    { path: "/users", component: UserManageView },
    { path: "/audit", component: AuditLogView },
    { path: "/notify", component: NotifySettingsView },
    { path: "/hitl", component: HitlApprovalView },
    { path: "/runtime-logs", component: RuntimeLogsView },
    { path: "/settings", component: SettingsView },
    { path: "/task/:id", component: BoardView, props: true },
  ],
});

router.beforeEach(async (to) => {
  if (!authReadyRef.value) await loadAuthRole();
  if (authRoleRef.value === "observer" && ["/create", "/settings", "/intel", "/vulns", "/vuln-dashboard", "/users", "/audit", "/notify", "/hitl", "/runtime-logs"].includes(to.path)) {
    return "/";
  }
  return true;
});

createApp(App).use(router).mount("#app");
