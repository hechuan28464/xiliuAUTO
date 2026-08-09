<script setup>
import { ref, onMounted } from "vue";
import { fmtLocalTime } from "../format.js";

const loading = ref(true);
const refreshing = ref(false);
const rows = ref([]);
const resolvingId = ref(null);

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
    const res = await apiFetch("/api/hitl/pending");
    rows.value = Array.isArray(res) ? res : (res?.items || []);
  } catch (e) {
    alert(`加载待审批列表失败：${e?.message || e}`);
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function resolve(row, decision) {
  if (!confirm(`${decision === "approve" ? "批准" : "拒绝"}该请求？\n工具：${row.tool}`)) return;
  resolvingId.value = row.id;
  try {
    await apiFetch(`/api/hitl/${row.id}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision }),
    });
    await loadList();
  } catch (e) {
    alert(`操作失败：${e?.message || e}`);
  } finally {
    resolvingId.value = null;
  }
}

function argsText(args) {
  if (!args) return "-";
  if (typeof args === "string") return args;
  try { return JSON.stringify(args); }
  catch { return String(args); }
}

const fmtTime = fmtLocalTime;

onMounted(loadList);
</script>

<template>
  <section class="view hitl-approval-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !loading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="page-head split">
      <div>
        <h2>HITL 审批 <span class="intel-chip">HITL</span></h2>
        <p class="page-sub">Human-in-the-Loop 人工审批——工具执行前的关键操作需人工确认或拒绝。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <div class="intel-toolbar">
      <span class="hitl-count">待审批 {{ rows.length }} 项</span>
      <button class="btn-ghost" @click="loadList" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <div v-if="loading" class="intel-grid">
      <div v-for="n in 4" :key="n" class="intel-row skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      暂无待审批请求
      <span class="hint">工具执行需人工确认时，请求会出现在这里</span>
    </div>
    <div v-else class="hitl-list">
      <article v-for="row in rows" :key="row.id" class="hitl-card">
        <div class="hitl-main">
          <div class="hitl-head">
            <span class="hitl-tool">{{ row.tool || "-" }}</span>
            <time class="hitl-time">{{ fmtTime(row.created_at) }}</time>
          </div>
          <div class="hitl-args">
            <span class="hitl-label">参数</span>
            <code>{{ argsText(row.args) }}</code>
          </div>
          <div v-if="row.reason" class="hitl-reason">
            <span class="hitl-label">理由</span>
            <span>{{ row.reason }}</span>
          </div>
        </div>
        <div class="hitl-actions">
          <button class="primary" @click="resolve(row, 'approve')" :disabled="resolvingId === row.id">
            {{ resolvingId === row.id ? "处理中…" : "批准" }}
          </button>
          <button class="btn-danger" @click="resolve(row, 'reject')" :disabled="resolvingId === row.id">
            拒绝
          </button>
        </div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.hitl-count {
  font-weight: 600;
  color: var(--ink);
  flex: 1;
}
.hitl-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.hitl-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  border: 1px solid var(--border-soft);
  border-left: 3px solid var(--warn);
  border-radius: 10px;
  background: var(--surface);
  padding: 16px 18px;
}
.hitl-card:hover {
  border-left-color: var(--accent);
  background: var(--surface-2);
}
.hitl-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-width: 0;
}
.hitl-head {
  display: flex;
  align-items: center;
  gap: 12px;
}
.hitl-tool {
  font-weight: 700;
  font-size: 14px;
  color: var(--ink);
  font-family: "IBM Plex Mono", monospace;
}
.hitl-time {
  font-size: 12px;
  color: var(--muted);
}
.hitl-args,
.hitl-reason {
  display: flex;
  gap: 8px;
  font-size: 13px;
}
.hitl-label {
  color: var(--muted);
  flex-shrink: 0;
  min-width: 36px;
}
.hitl-args code {
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
  word-break: break-all;
  background: var(--nav);
  padding: 2px 6px;
  border-radius: 4px;
}
.hitl-actions {
  display: flex;
  flex-direction: column;
  gap: 8px;
  flex-shrink: 0;
}
.hitl-actions button {
  min-width: 80px;
  text-align: center;
}
.btn-danger {
  color: var(--danger);
  border-color: color-mix(in oklch, var(--danger) 35%, var(--border));
  background: var(--surface-2);
  border-radius: var(--radius-sm);
  padding: 8px 14px;
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color .15s ease, border-color .15s ease;
}
.btn-danger:hover {
  background: var(--danger-bg);
}
.btn-danger:disabled {
  opacity: .4;
  cursor: not-allowed;
}
@media (max-width: 768px) {
  .hitl-card { flex-direction: column; }
  .hitl-actions { flex-direction: row; }
}
</style>
