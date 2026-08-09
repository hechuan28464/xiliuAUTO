<script setup>
import { ref, onMounted } from "vue";
import { fmtLocalTime } from "../format.js";

const loading = ref(true);
const refreshing = ref(false);
const rows = ref([]);
const creating = ref(false);
const savingId = ref(null);

const newUser = ref({ username: "", password: "", role: "viewer" });

const ROLE_LABELS = {
  admin: "管理员",
  operator: "操作员",
  reviewer: "审核员",
  viewer: "查看者",
};

const ROLE_OPTIONS = [
  { value: "admin", label: "管理员" },
  { value: "operator", label: "操作员" },
  { value: "reviewer", label: "审核员" },
  { value: "viewer", label: "查看者" },
];

function authHeaders(extra = {}) {
  const token = localStorage.getItem("ah-api-token") || "";
  return { Authorization: `Bearer ${token}`, ...extra };
}

async function apiFetch(url, opts = {}) {
  const headers = authHeaders(opts.headers);
  const res = await fetch(url, { ...opts, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${text}`);
  }
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try { return JSON.parse(text); }
  catch { return text; }
}

async function loadList() {
  if (!rows.value.length) loading.value = true;
  else refreshing.value = true;
  try {
    const res = await apiFetch("/api/users");
    rows.value = Array.isArray(res) ? res : (res?.items || []);
  } catch (e) {
    alert(`加载用户列表失败：${e?.message || e}`);
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function createUser() {
  if (!newUser.value.username || !newUser.value.password) {
    alert("用户名和密码不能为空");
    return;
  }
  creating.value = true;
  try {
    await apiFetch("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newUser.value),
    });
    newUser.value = { username: "", password: "", role: "viewer" };
    await loadList();
  } catch (e) {
    alert(`创建用户失败：${e?.message || e}`);
  } finally {
    creating.value = false;
  }
}

async function updateRole(row) {
  savingId.value = row.id;
  try {
    await apiFetch(`/api/users/${row.id}/role`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: row.role }),
    });
  } catch (e) {
    alert(`修改角色失败：${e?.message || e}`);
    await loadList();
  } finally {
    savingId.value = null;
  }
}

const fmtTime = fmtLocalTime;

onMounted(loadList);
</script>

<template>
  <section class="view user-manage-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>用户管理 <span class="intel-chip">USER</span></h2>
        <p class="page-sub">管理系统用户账号——创建用户、分配角色、控制访问权限。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="create-form">
      <h3>创建用户</h3>
      <div class="form-row">
        <input v-model="newUser.username" placeholder="用户名" />
        <input v-model="newUser.password" type="password" placeholder="密码" />
        <select v-model="newUser.role">
          <option v-for="r in ROLE_OPTIONS" :key="r.value" :value="r.value">{{ r.label }}</option>
        </select>
        <button class="primary" @click="createUser" :disabled="creating">{{ creating ? "创建中…" : "创建" }}</button>
      </div>
    </div>

    <div class="intel-toolbar">
      <span class="um-list-title">用户列表</span>
      <button class="btn-ghost" @click="loadList" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 4" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无用户
      <span class="hint">使用上方表单创建第一个用户</span>
    </div>
    <div v-else class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>用户名</th>
            <th>角色</th>
            <th>状态</th>
            <th>创建时间</th>
            <th>最后登录</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id">
            <td>{{ row.username || "-" }}</td>
            <td>
              <select v-model="row.role" class="role-select" :disabled="savingId === row.id">
                <option v-for="r in ROLE_OPTIONS" :key="r.value" :value="r.value">{{ r.label }}</option>
              </select>
            </td>
            <td>
              <span class="active-badge" :class="row.is_active ? 'on' : 'off'">
                {{ row.is_active ? "活跃" : "禁用" }}
              </span>
            </td>
            <td class="mono">{{ fmtTime(row.created_at) }}</td>
            <td class="mono">{{ fmtTime(row.last_login) }}</td>
            <td>
              <button class="primary um-save-btn" @click="updateRole(row)" :disabled="savingId === row.id">
                {{ savingId === row.id ? "保存中…" : "修改角色" }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.create-form {
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
  padding: 18px;
  margin-bottom: 20px;
}
.create-form h3 {
  margin: 0 0 14px;
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
}
.form-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}
.form-row input { flex: 1; min-width: 160px; }
.form-row select { width: auto; min-width: 120px; }
.um-list-title {
  font-weight: 600;
  color: var(--ink);
}
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-soft);
  border-radius: 10px;
  background: var(--surface);
}
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.data-table th {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 2px solid var(--border);
  color: var(--muted);
  font-weight: 600;
  white-space: nowrap;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: .04em;
}
.data-table td {
  padding: 9px 12px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: middle;
}
.data-table tr:hover td {
  background: var(--surface-2);
}
.mono {
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
  white-space: nowrap;
}
.role-select {
  width: auto;
  min-width: 100px;
  padding: 5px 8px;
  font-size: 12.5px;
}
.active-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.active-badge.on { background: color-mix(in oklch, var(--ok) 15%, transparent); color: var(--ok); }
.active-badge.off { background: var(--danger-bg); color: var(--danger); }
.um-save-btn { padding: 5px 12px; font-size: 12px; }
@media (max-width: 768px) {
  .form-row { flex-direction: column; }
  .form-row input, .form-row select { width: 100%; }
}
</style>
