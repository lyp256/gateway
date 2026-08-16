import { computed, createApp, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import {
  Activity,
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ArrowUpRight,
  Cable,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Database,
  Globe2,
  Layers3,
  Link2,
  LoaderCircle,
  Network,
  Pencil,
  Plus,
  Radio,
  RefreshCw,
  Route,
  Search,
  SearchX,
  Server,
  Shield,
  Trash2,
  X,
} from 'lucide-vue-next'
import './style.css'

const apiRoot = '/api/v1'

const unwrap = (value) => value && typeof value === 'object' && 'body' in value ? value.body : value

async function api(path, options = {}) {
  const response = await fetch(`${apiRoot}${path}`, {
    headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    ...options,
  })
  if (response.status === 204) return null
  const payload = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(payload?.detail || payload?.title || `请求失败 (${response.status})`)
  }
  const value = unwrap(payload)
  if (Array.isArray(value)) {
    const total = response.headers.get('X-Total-Count')
    if (total !== null) {
      Object.defineProperty(value, 'total', { value: Number(total), configurable: true })
      Object.defineProperty(value, 'page', { value: Number(response.headers.get('X-Page') || 1), configurable: true })
      Object.defineProperty(value, 'perPage', { value: Number(response.headers.get('X-Per-Page') || 20), configurable: true })
    }
  }
  return value
}

function hexMark(value) {
  const mark = Number(value)
  return Number.isFinite(mark) ? `0x${(mark >>> 0).toString(16).padStart(4, '0')}` : '-'
}

function egressDesc(egress) {
  if (!egress) return '-'
  if (egress.type === 'tproxy') {
    const port = Number(egress.tproxy?.port) || 0
    return `${egress.tproxy?.addr || '0.0.0.0'}:${port}`
  }
  return hexMark(egress.fwmark)
}

function emptyEgress() {
  return { name: '', type: 'manual', fwmark: '', tunnel: { url: '', token: '' }, tproxy: { addr: '0.0.0.0', port: '' } }
}

function emptyDomain() {
  return { match: 'domain', domain: '', egress: '' }
}

function emptyCidr() {
  return { cidr: '', egress: '' }
}

function emptyHost() {
  return { name: '', ip: '' }
}

function emptyWhitelist() {
  return { cidr: '' }
}

function emptyDNSServer() {
  return { name: '', type: 'doh', server: '', ip: '', insecure: false }
}

function emptyDNSTest() {
  return { source: '', type: 'doh', server: '', ip: '', insecure: false, qname: 'example.com' }
}

function dnsTypeLabel(type) {
  return ({ udp: 'UDP', dot: 'DoT', doh: 'DoH' })[type] || 'UDP'
}

const viewIds = new Set(['overview', 'nics', 'egresses', 'domains', 'cidrs', 'hosts', 'dns-servers', 'whitelist', 'routes', 'dns-cache'])

function viewFromHash(hash = window.location.hash) {
  const view = hash.replace(/^#\/?/, '').split(/[/?]/, 1)[0]
  return viewIds.has(view) ? view : 'overview'
}

function hashForView(view) {
  return `#/${view}`
}

// SortIcon 渲染表头排序指示：未排序 ↕、升序 ↑、降序 ↓。
const SortIcon = {
  name: 'SortIcon',
  props: {
    state: { type: Object, required: true },
    field: { type: String, required: true },
  },
  components: { ArrowDown, ArrowUp, ArrowUpDown },
  computed: {
    active() { return this.state.sort === this.field },
    order() { return this.state.order },
  },
  template: `<ArrowUpDown v-if="!active" :size="14" class="sort-icon idle" /><ArrowUp v-else-if="order === 'asc'" :size="14" class="sort-icon" /><ArrowDown v-else :size="14" class="sort-icon" />`,
}

// ListControls 是列表页通用的搜索框（带搜索按钮）+ 排序 + 每页条数 + 分页器。
const ListControls = {
  name: 'ListControls',
  props: {
    list: { type: Object, required: true },
    placeholder: { type: String, default: '搜索…' },
    sortFields: { type: Array, default: () => [] },
  },
  emits: ['change'],
  components: { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, LoaderCircle, Search, X },
  computed: {
    totalPages() {
      const perPage = Number(this.list.perPage) || 20
      return Math.max(1, Math.ceil((Number(this.list.total) || 0) / perPage))
    },
  },
  methods: {
    apply() { this.$emit('change', 1) },
    clear() {
      const hadText = !!this.list.search
      this.list.search = ''
      if (hadText) this.$emit('change', 1)
    },
    resize() { this.$emit('change', 1) },
    go(page) { this.$emit('change', page) },
    sortChanged() { this.$emit('change', 1) },
    toggleDirection() {
      this.list.order = this.list.order === 'asc' ? 'desc' : 'asc'
      this.$emit('change', 1)
    },
  },
  template: `
    <div class="list-controls">
      <div class="list-search">
        <Search :size="16" class="list-search-icon" />
        <div class="list-search-field">
          <input v-model="list.search" :disabled="list.loading" :placeholder="placeholder" @keyup.enter="apply" @keyup.esc="clear" />
          <button v-if="list.search" type="button" class="list-search-clear" title="清除搜索" :disabled="list.loading" @click="clear"><X :size="14" /></button>
        </div>
        <button type="button" class="search-button" :disabled="list.loading" @click="apply"><Search :size="15" />搜索</button>
      </div>
      <div class="list-pager">
        <select v-model="list.sort" class="sort-select" title="排序字段" :disabled="list.loading" @change="sortChanged">
          <option value="">默认排序</option>
          <option v-for="option in sortFields" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select>
        <button type="button" class="direction-button" :disabled="list.loading || !list.sort" :title="list.order === 'asc' ? '切换为降序' : '切换为升序'" @click="toggleDirection">
          <ArrowUp v-if="list.order === 'asc'" :size="15" />
          <ArrowDown v-else :size="15" />
        </button>
        <span class="list-total" :class="{ 'list-loading': list.loading }">
          <LoaderCircle v-if="list.loading" :size="13" class="spinning" />
          <template v-else>共 {{ list.total }} 项</template>
        </span>
        <select v-model.number="list.perPage" title="每页条数" :disabled="list.loading" @change="resize">
          <option :value="20">20 条/页</option>
          <option :value="50">50 条/页</option>
          <option :value="100">100 条/页</option>
          <option :value="200">200 条/页</option>
        </select>
        <button type="button" class="page-button" :disabled="list.loading || list.page <= 1" title="上一页" @click="go(list.page - 1)"><ChevronLeft :size="16" /></button>
        <span class="list-page">{{ list.page }} / {{ totalPages }}</span>
        <button type="button" class="page-button" :disabled="list.loading || list.page >= totalPages" title="下一页" @click="go(list.page + 1)"><ChevronRight :size="16" /></button>
      </div>
    </div>
  `,
}

const App = {
  components: {
    Activity,
    AlertCircle,
    ArrowDown,
    ArrowUp,
    ArrowUpDown,
    ArrowUpRight,
    Cable,
    Check,
    ChevronLeft,
    ChevronRight,
    CircleHelp,
    Database,
    Globe2,
    Layers3,
    Link2,
    LoaderCircle,
    Network,
    Pencil,
    Plus,
    Radio,
    RefreshCw,
    Route,
    Search,
    SearchX,
    Server,
    Shield,
    Trash2,
    X,
    ListControls,
    SortIcon,
  },
  setup() {
    const currentView = ref(viewFromHash())
    const loading = ref(true)
    const saving = ref(false)
    const error = ref('')
    const notice = ref('')
    const lastUpdated = ref(null)
    const nics = ref([])
    const nicsLoading = ref(false)
    const nicBusy = ref('')
    const bpfStatus = ref(null)
    const bpfSettings = ref(null)
    const modal = ref('')
    const editing = ref(null)
    const egressForm = reactive(emptyEgress())
    const domainForm = reactive(emptyDomain())
    const cidrForm = reactive(emptyCidr())
    const hostForm = reactive(emptyHost())
    const whitelistForm = reactive(emptyWhitelist())
    const dnsServerForm = reactive(emptyDNSServer())
    const dnsServerTest = reactive({})
    const modalTesting = ref(false)
    const modalTestResult = ref(null)
    const dnsTestForm = reactive(emptyDNSTest())
    const dnsTesting = ref(false)
    const dnsTestResult = ref(null)
    // lookups 保存完整参考数据（出口/上游 DNS），供下拉框与路由索引映射使用，
    // 与表格的分页数据分离，避免分页导致关联信息缺失。
    const lookups = reactive({ egresses: [], dnsServers: [] })

    function newListState() {
      return { items: [], total: 0, page: 1, perPage: 20, sort: '', order: 'asc', search: '', loading: false }
    }

    const sortOptions = {
      egresses: [
        { value: 'name', label: '名称' },
        { value: 'type', label: '类型' },
        { value: 'fwmark', label: 'fwmark' },
        { value: 'index', label: '索引' },
      ],
      domains: [
        { value: 'domain', label: '域名' },
        { value: 'match', label: '匹配方式' },
        { value: 'egress', label: '出口' },
      ],
      cidrs: [
        { value: 'cidr', label: 'CIDR' },
        { value: 'egress', label: '出口' },
      ],
      hosts: [
        { value: 'name', label: '主机名' },
        { value: 'ip', label: 'IP 地址' },
      ],
      dnsServers: [
        { value: 'name', label: '名称' },
        { value: 'type', label: '类型' },
        { value: 'server', label: '服务器' },
        { value: 'ip', label: '直连 IP' },
      ],
      whitelist: [
        { value: 'cidr', label: 'CIDR' },
      ],
      routes: [
        { value: 'cidr', label: 'CIDR' },
        { value: 'value', label: 'egress 索引' },
      ],
      dnsCache: [
        { value: 'name', label: '域名' },
        { value: 'type', label: '类型' },
        { value: 'ttl', label: '剩余 TTL' },
        { value: 'lastAccessAt', label: '最近访问' },
        { value: 'expiresAt', label: '过期时间' },
      ],
    }

    const listPaths = {
      egresses: 'egresses',
      domains: 'domains',
      cidrs: 'cidrs',
      hosts: 'hosts',
      dnsServers: 'dns/servers',
      whitelist: 'whitelist',
      routes: 'routes',
      dnsCache: 'dns/cache',
    }
    const listState = reactive({
      egresses: newListState(),
      domains: newListState(),
      cidrs: newListState(),
      hosts: newListState(),
      dnsServers: newListState(),
      whitelist: newListState(),
      routes: newListState(),
      dnsCache: newListState(),
    })

    const navItems = [
      { id: 'overview', label: '总览', icon: 'Activity' },
      { id: 'nics', label: '网卡', icon: 'Cable' },
      { id: 'egresses', label: '出口', icon: 'Network' },
      { id: 'domains', label: '域名规则', icon: 'Globe2' },
      { id: 'cidrs', label: 'IP 规则', icon: 'Network' },
      { id: 'hosts', label: '静态 Hosts', icon: 'Server' },
      { id: 'dns-servers', label: '上游 DNS', icon: 'Radio' },
      { id: 'routes', label: '生效路由', icon: 'Route' },
      { id: 'dns-cache', label: 'DNS 缓存', icon: 'Database' },
      { id: 'whitelist', label: '白名单', icon: 'Shield' },
    ]

    const stats = computed(() => [
      { label: '出口配置', value: listState.egresses.total, icon: Network, tone: 'teal' },
      { label: '域名规则', value: listState.domains.total, icon: Globe2, tone: 'lime' },
      { label: 'IP 规则', value: listState.cidrs.total, icon: Network, tone: 'indigo' },
      { label: '静态 Hosts', value: listState.hosts.total, icon: Server, tone: 'amber' },
      { label: 'IPv4 路由', value: listState.routes.total, icon: Route, tone: 'rose' },
      { label: 'eBPF 网卡', value: bpfStatus.value?.interfaces ?? 0, icon: Cable, tone: 'cyan' },
    ])

    const egressByName = computed(() => new Map(lookups.egresses.map((item) => [item.name, item])))
    const egressByIndex = computed(() => new Map(lookups.egresses.map((item) => [Number(item.index), item])))
    const selectedDomainEgress = computed(() => egressByName.value.get(domainForm.egress))
    const selectedCidrEgress = computed(() => egressByName.value.get(cidrForm.egress))
    const modalTitle = computed(() => ({
      egress: editing.value ? '编辑出口' : '新建出口',
      domain: editing.value ? '编辑域名规则' : '新建域名规则',
      cidr: editing.value ? '编辑 IP 规则' : '新建 IP 规则',
      host: editing.value ? '编辑静态 Hosts' : '新建静态 Hosts',
      'dns-server': editing.value ? '编辑上游 DNS' : '新建上游 DNS',
      'dns-test': 'DNS 连通性测试',
      whitelist: editing.value ? '编辑白名单' : '新增白名单',
    })[modal.value] || '')

    function clearMessage() {
      error.value = ''
      notice.value = ''
    }

    function syncViewFromHash() {
      const view = viewFromHash()
      currentView.value = view

      const expectedHash = hashForView(view)
      if (window.location.hash !== expectedHash) {
        window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${expectedHash}`)
      }
    }

    function navigate(view) {
      if (!viewIds.has(view)) return

      currentView.value = view
      const nextHash = hashForView(view)
      if (window.location.hash !== nextHash) window.location.hash = nextHash
    }

    // loadList 按列表当前的分页/排序/搜索状态拉取一页数据；
    // 服务端把分页元信息放在 X-Total-Count / X-Page / X-Per-Page 响应头中。
    async function loadList(key, page = listState[key].page) {
      const state = listState[key]
      state.page = page
      state.loading = true
      try {
        const query = new URLSearchParams({ page: String(state.page), per_page: String(state.perPage) })
        if (state.sort) query.set('sort', state.sort)
        if (state.order) query.set('order', state.order)
        if (state.search.trim()) query.set('search', state.search.trim())
        const items = await api(`/${listPaths[key]}?${query}`)
        state.items = Array.isArray(items) ? items : []
        state.total = items?.total ?? state.items.length
        state.page = items?.page ?? state.page
        state.perPage = items?.perPage ?? state.perPage
        // 删除/搜索后当前页可能越界，自动回退到最后一页。
        if (!state.items.length && state.total > 0 && state.page > 1) {
          await loadList(key, state.page - 1)
        }
      } finally {
        state.loading = false
      }
    }

    async function loadLookups() {
      const [egresses, dnsServers] = await Promise.all([
        api('/egresses?per_page=1000'),
        api('/dns/servers?per_page=1000'),
      ])
      lookups.egresses = Array.isArray(egresses) ? egresses : []
      lookups.dnsServers = Array.isArray(dnsServers) ? dnsServers : []
    }

    function toggleSort(key, field) {
      const state = listState[key]
      if (state.sort === field) {
        state.order = state.order === 'asc' ? 'desc' : 'asc'
      } else {
        state.sort = field
        state.order = 'asc'
      }
      loadList(key, 1)
    }

    function clearSearch(key) {
      listState[key].search = ''
      loadList(key, 1)
    }

    async function refresh() {
      clearMessage()
      loading.value = true
      try {
        await Promise.all([
          loadList('egresses'), loadList('domains'), loadList('cidrs'), loadList('hosts'),
          loadList('dnsServers'), loadList('whitelist'), loadList('routes'), loadList('dnsCache'),
          loadLookups(), loadNics(), loadBPFStatus(), loadBPFSettings(),
        ])
        Object.keys(dnsServerTest).forEach((name) => delete dnsServerTest[name])
        lastUpdated.value = new Date()
      } catch (cause) {
        error.value = cause.message
      } finally {
        loading.value = false
      }
    }

    async function loadNics() {
      nicsLoading.value = true
      try {
        const items = await api('/nics?per_page=1000')
        nics.value = Array.isArray(items) ? items : []
      } finally {
        nicsLoading.value = false
      }
    }

    async function loadBPFStatus() {
      bpfStatus.value = await api('/bpf/status').catch(() => null)
    }

    async function loadBPFSettings() {
      bpfSettings.value = await api('/bpf/settings').catch(() => null)
    }

    async function toggleNic(nic) {
      nicBusy.value = nic.name
      clearMessage()
      try {
        await api(`/nics/${encodeURIComponent(nic.name)}/attach`, { method: nic.attached ? 'DELETE' : 'POST' })
        notice.value = nic.attached ? `已解除 ${nic.name} 的 eBPF 挂载。` : `eBPF 已挂载到 ${nic.name}。`
        await Promise.all([loadNics(), loadBPFStatus()])
      } catch (cause) {
        error.value = cause.message
      } finally {
        nicBusy.value = ''
      }
    }

    async function toggleAutoMount(nic) {
      nicBusy.value = `auto:${nic.name}`
      clearMessage()
      try {
        await api(`/nics/${encodeURIComponent(nic.name)}/auto-mount`, {
          method: 'PUT',
          body: JSON.stringify({ auto_mount: !nic.auto_mount }),
        })
        notice.value = nic.auto_mount
          ? `已关闭 ${nic.name} 的自动挂载。`
          : `${nic.name} 将在下次启动时自动挂载 eBPF。`
        await Promise.all([loadNics(), loadBPFSettings()])
      } catch (cause) {
        error.value = cause.message
      } finally {
        nicBusy.value = ''
      }
    }

    async function toggleMountAll() {
      const next = !bpfSettings.value?.mount_all
      nicBusy.value = 'mount-all'
      clearMessage()
      try {
        await api('/bpf/settings', { method: 'PUT', body: JSON.stringify({ mount_all: next }) })
        notice.value = next ? '已启用全部挂载：下次启动将挂载所有可挂载网卡。' : '已关闭全部挂载。'
        await Promise.all([loadNics(), loadBPFSettings()])
      } catch (cause) {
        error.value = cause.message
      } finally {
        nicBusy.value = ''
      }
    }

    function resetForm(target, source) {
      Object.assign(target, source)
    }

    function openEgress(item) {
      editing.value = item || null
      resetForm(egressForm, item ? {
        name: item.name,
        type: item.type || 'manual',
        fwmark: item.type === 'tproxy' ? '' : item.fwmark,
        tunnel: { url: item.tunnel?.url || '', token: item.tunnel?.token || '' },
        tproxy: { addr: item.tproxy?.addr || '0.0.0.0', port: item.tproxy?.port || '' },
      } : emptyEgress())
      modal.value = 'egress'
    }

    function openDomain(item) {
      editing.value = item || null
      resetForm(domainForm, item ? {
        match: item.match || 'domain', domain: item.domain, egress: item.egress,
      } : emptyDomain())
      modal.value = 'domain'
    }

    function createDomainFromCache(item) {
      editing.value = null
      resetForm(domainForm, {
        match: 'domain',
        domain: item.name.replace(/\.+$/, ''),
        egress: '',
      })
      modal.value = 'domain'
    }

    function openCidr(item) {
      editing.value = item || null
      resetForm(cidrForm, item ? {
        cidr: item.cidr, egress: item.egress,
      } : emptyCidr())
      modal.value = 'cidr'
    }

    function openHost(item) {
      editing.value = item || null
      resetForm(hostForm, item ? { name: item.name, ip: item.ip } : emptyHost())
      modal.value = 'host'
    }

    function openWhitelist(item) {
      editing.value = item || null
      resetForm(whitelistForm, item ? { cidr: item.cidr } : emptyWhitelist())
      modal.value = 'whitelist'
    }

    function openDNSServer(item) {
      editing.value = item || null
      modalTestResult.value = null
      resetForm(dnsServerForm, item ? {
        name: item.name, type: item.type || 'udp', server: item.server || '', ip: item.ip || '', insecure: !!item.insecure,
      } : emptyDNSServer())
      modal.value = 'dns-server'
    }

    function openDNSTest() {
      resetForm(dnsTestForm, emptyDNSTest())
      dnsTestResult.value = null
      modal.value = 'dns-test'
    }

    function useDNSTestSource() {
      const item = lookups.dnsServers.find((candidate) => candidate.name === dnsTestForm.source)
      if (!item) return
      dnsTestForm.type = item.type || 'udp'
      dnsTestForm.server = item.server || ''
      dnsTestForm.ip = item.ip || ''
      dnsTestForm.insecure = !!item.insecure
    }

    async function runDNSTest() {
      const type = dnsTestForm.type
      const server = dnsTestForm.server.trim()
      const ip = dnsTestForm.ip.trim()
      const qname = dnsTestForm.qname.trim()
      if (type === 'udp' && !ip) {
        error.value = 'UDP 类型需要填写上游 IP 地址。'
        return
      }
      if ((type === 'dot' && !server && !ip) || (type === 'doh' && !server)) {
        error.value = type === 'doh' ? 'DoH 类型需要填写服务器域名。' : 'DoT 类型需要填写服务器域名或 IP 地址。'
        return
      }
      if (!qname) {
        error.value = '请填写测试域名。'
        return
      }
      dnsTesting.value = true
      dnsTestResult.value = null
      clearMessage()
      try {
        const result = await api('/dns/servers/test', {
          method: 'POST',
          body: JSON.stringify({
            type,
            server,
            ip: ip || null,
            insecure: dnsTestForm.insecure,
            qname,
          }),
        })
        dnsTestResult.value = result
      } catch (cause) {
        dnsTestResult.value = { ok: false, message: cause.message }
      } finally {
        dnsTesting.value = false
      }
    }

    function closeModal() {
      modal.value = ''
      editing.value = null
      modalTestResult.value = null
      dnsTestResult.value = null
    }

    async function saveEgress() {
      const name = egressForm.name.trim()
      if (!name) {
        error.value = '请填写出口名称。'
        return
      }
      if (egressForm.type !== 'tproxy' && (egressForm.fwmark === '' || Number(egressForm.fwmark) < 0)) {
        error.value = '请填写有效的 fwmark。'
        return
      }
      const originalName = editing.value?.name
      const conflict = lookups.egresses.find((item) => item.name !== originalName
        && (item.name === name || (egressForm.type !== 'tproxy' && Number(item.fwmark) === Number(egressForm.fwmark))))
      if (conflict) {
        error.value = conflict.name === name ? '出口名称已存在。' : 'fwmark 已被其他出口使用。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api(originalName ? `/egresses/${encodeURIComponent(originalName)}` : '/egresses', {
          method: originalName ? 'PUT' : 'POST',
          body: JSON.stringify({
            name,
            type: egressForm.type,
            fwmark: egressForm.type === 'tproxy' ? 0 : Number(egressForm.fwmark),
            tunnel: egressForm.type === 'http_tunnel'
              ? { url: egressForm.tunnel.url.trim(), token: egressForm.tunnel.token }
              : null,
            tproxy: egressForm.type === 'tproxy'
              ? { addr: egressForm.tproxy.addr.trim(), port: Number(egressForm.tproxy.port) || 0 }
              : null,
          }),
        })
        closeModal()
        notice.value = '出口配置已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveDomain() {
      const domain = domainForm.domain.trim().toLowerCase().replace(/\.+$/, '')
      const egress = selectedDomainEgress.value
      if (!domain || !egress) {
        error.value = '请填写域名并选择已有出口。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/domains', {
          method: 'PUT',
          body: JSON.stringify({ match: domainForm.match, domain, egress: domainForm.egress }),
        })
        closeModal()
        notice.value = '域名规则已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveCidr() {
      const cidr = cidrForm.cidr.trim()
      const egress = selectedCidrEgress.value
      if (!cidr || !egress) {
        error.value = '请填写 CIDR 网段并选择已有出口。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/cidrs', {
          method: 'PUT',
          body: JSON.stringify({ cidr, egress: cidrForm.egress }),
        })
        closeModal()
        notice.value = 'IP 规则已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveHost() {
      const name = hostForm.name.trim().toLowerCase().replace(/\.+$/, '')
      if (!name || !hostForm.ip.trim()) {
        error.value = '请填写主机名和 IP 地址。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/hosts', {
          method: 'PUT',
          body: JSON.stringify({ name, ip: hostForm.ip.trim() }),
        })
        closeModal()
        notice.value = '静态 Hosts 已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function saveWhitelist() {
      const cidr = whitelistForm.cidr.trim()
      if (!cidr) {
        error.value = '请填写 CIDR 网段或 IP 地址。'
        return
      }
      saving.value = true
      clearMessage()
      try {
        await api('/whitelist', {
          method: 'PUT',
          body: JSON.stringify({ cidr }),
        })
        closeModal()
        notice.value = '白名单已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    function dnsServerConfig() {
      const type = dnsServerForm.type
      const server = dnsServerForm.server.trim()
      const ip = dnsServerForm.ip.trim()
      if (type === 'udp' && !ip) {
        error.value = 'UDP 类型需要填写上游 IP 地址。'
        return null
      }
      if ((type === 'dot' && !server && !ip) || (type === 'doh' && !server)) {
        error.value = type === 'doh' ? 'DoH 类型需要填写服务器域名。' : 'DoT 类型需要填写服务器域名或 IP 地址。'
        return null
      }
      return { type, server, ip: ip || null, insecure: dnsServerForm.insecure }
    }

    async function testDNSServerForm() {
      const config = dnsServerConfig()
      if (!config) return
      modalTesting.value = true
      modalTestResult.value = null
      clearMessage()
      try {
        const result = await api('/dns/servers/test', { method: 'POST', body: JSON.stringify(config) })
        modalTestResult.value = result
      } catch (cause) {
        modalTestResult.value = { ok: false, message: cause.message }
      } finally {
        modalTesting.value = false
      }
    }

    async function testDNSServerRow(item) {
      clearMessage()
      dnsServerTest[item.name] = { testing: true }
      try {
        const result = await api('/dns/servers/test', {
          method: 'POST',
          body: JSON.stringify({ type: item.type, server: item.server || '', ip: item.ip || null, insecure: !!item.insecure }),
        })
        dnsServerTest[item.name] = result
      } catch (cause) {
        dnsServerTest[item.name] = { ok: false, message: cause.message }
      }
    }

    async function saveDNSServer() {
      const name = dnsServerForm.name.trim()
      if (!name) {
        error.value = '请填写上游 DNS 名称。'
        return
      }
      const config = dnsServerConfig()
      if (!config) return
      saving.value = true
      clearMessage()
      try {
        await api('/dns/servers', {
          method: 'PUT',
          body: JSON.stringify({ name, ...config }),
        })
        closeModal()
        notice.value = '上游 DNS 配置已保存。'
        await refresh()
      } catch (cause) {
        error.value = cause.message
      } finally {
        saving.value = false
      }
    }

    async function remove(kind, item) {
      const labels = { egress: '出口', domain: '域名规则', cidr: 'IP 规则', host: '静态 Hosts', 'dns-server': '上游 DNS', whitelist: '白名单', 'dns-cache': 'DNS 缓存条目' }
      const identifier = kind === 'domain' ? item.domain : (kind === 'cidr' || kind === 'whitelist') ? item.cidr : item.name
      if (!window.confirm(`确认删除${labels[kind]}「${identifier}」？`)) return
      clearMessage()
      try {
        const path = kind === 'egress'
          ? `/egresses/${encodeURIComponent(item.name)}`
          : kind === 'dns-cache'
            ? `/dns/cache/${encodeURIComponent(item.name)}`
          : kind === 'dns-server'
            ? `/dns/servers/${encodeURIComponent(item.name)}`
          : kind === 'domain'
            ? `/domains/${encodeURIComponent(`${item.match}:${item.domain}`)}`
            : kind === 'cidr'
              ? `/cidrs/${encodeURIComponent(item.cidr)}`
              : kind === 'whitelist'
                ? `/whitelist/${encodeURIComponent(item.cidr)}`
                : `/hosts/${encodeURIComponent(item.name)}`
        await api(path, { method: 'DELETE' })
        notice.value = `${labels[kind]}已删除。`
        await refresh()
      } catch (cause) {
        error.value = cause.message
      }
    }

    function addForView() {
      if (currentView.value === 'egresses') openEgress()
      if (currentView.value === 'domains') openDomain()
      if (currentView.value === 'cidrs') openCidr()
      if (currentView.value === 'hosts') openHost()
      if (currentView.value === 'dns-servers') openDNSServer()
      if (currentView.value === 'whitelist') openWhitelist()
    }

    const addLabel = computed(() => ({ egresses: '新建出口', domains: '新建规则', cidrs: '新建 IP 规则', hosts: '新建 Hosts', 'dns-servers': '新建上游', whitelists: '新增白名单' })[currentView.value] || '')
    const canAdd = computed(() => ['egresses', 'domains', 'cidrs', 'hosts', 'dns-servers', 'whitelists'].includes(currentView.value))

    onMounted(() => {
      syncViewFromHash()
      window.addEventListener('hashchange', syncViewFromHash)
      refresh()
    })

    onBeforeUnmount(() => window.removeEventListener('hashchange', syncViewFromHash))

    return {
      addForView, addLabel, bpfSettings, bpfStatus, canAdd, cidrForm, clearSearch, closeModal, currentView, dnsServerForm, dnsServerTest, dnsTestForm, dnsTesting, dnsTestResult, dnsTypeLabel, domainForm, egressDesc,
      egressByIndex, egressByName, egressForm, error, hexMark, hostForm, lastUpdated, loading, modal, modalTitle, navItems, notice,
      listState, loadList, loadBPFStatus, loadBPFSettings, loadNics, lookups, modalTestResult, modalTesting, navigate, nics, nicsLoading, nicBusy, openCidr, createDomainFromCache, openDNSServer, openDNSTest, openDomain, openEgress, openHost, openWhitelist, refresh, remove, runDNSTest, saveCidr, saveDNSServer,
      saveDomain, saveEgress, saveHost, saveWhitelist, saving, selectedCidrEgress, selectedDomainEgress, stats, whitelistForm,
      sortOptions, testDNSServerForm, testDNSServerRow, toggleAutoMount, toggleMountAll, toggleNic, toggleSort, useDNSTestSource,
    }
  },
  template: `
    <main class="shell">
      <aside class="sidebar">
        <div class="brand" aria-label="Gateway 控制台">
          <div class="brand-mark"><Layers3 :size="22" /></div>
          <div><strong>Gateway</strong><span>控制台</span></div>
        </div>
        <nav class="nav" aria-label="主导航">
          <button v-for="item in navItems" :key="item.id" class="nav-item" :class="{ active: currentView === item.id }" @click="navigate(item.id)">
            <component :is="item.icon" :size="18" />
            <span>{{ item.label }}</span>
          </button>
        </nav>
        <div class="sidebar-foot">
          <span class="status-dot"></span>
          <span>API 已连接</span>
        </div>
      </aside>

      <section class="workspace">
        <header class="topbar">
          <div>
            <p class="eyebrow">CONTROL PLANE</p>
            <h1>{{ navItems.find(item => item.id === currentView)?.label }}</h1>
          </div>
          <div class="topbar-actions">
            <span v-if="lastUpdated" class="updated">更新于 {{ lastUpdated.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) }}</span>
            <button class="icon-button" title="刷新数据" :disabled="loading" @click="refresh"><RefreshCw :size="18" :class="{ spinning: loading }" /></button>
            <button v-if="currentView === 'dns-servers'" class="secondary-button" @click="openDNSTest"><Activity :size="18" />DNS 测试</button>
            <button v-if="canAdd" class="primary-button" @click="addForView"><Plus :size="18" />{{ addLabel }}</button>
          </div>
        </header>

        <div v-if="notice" class="alert alert-success"><Check :size="18" /><span>{{ notice }}</span><button title="关闭提示" @click="notice = ''"><X :size="17" /></button></div>

        <div v-if="loading && !lastUpdated" class="loading-state"><LoaderCircle :size="24" class="spinning" /><span>正在读取 Gateway 配置</span></div>

        <template v-else>
          <section v-if="currentView === 'overview'" class="view overview">
            <div class="stat-grid">
              <article v-for="stat in stats" :key="stat.label" class="stat-card" :class="stat.tone">
                <div class="stat-icon"><component :is="stat.icon" :size="20" /></div>
                <span>{{ stat.label }}</span>
                <strong>{{ stat.value }}</strong>
              </article>
            </div>
            <div class="overview-grid">
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">EGRESS</p><h2>出口配置</h2></div><button class="text-button" @click="navigate('egresses')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="lookups.egresses.length" class="compact-list">
                  <div v-for="egress in lookups.egresses.slice(0, 4)" :key="egress.name" class="compact-row"><span class="row-name">{{ egress.name }}</span><span class="badge" :class="egress.type === 'http_tunnel' ? 'badge-teal' : egress.type === 'tproxy' ? 'badge-lime' : 'badge-neutral'">{{ egress.type === 'http_tunnel' ? 'HTTP 隧道' : egress.type === 'tproxy' ? '本地 TPROXY' : '手工出口' }}</span><code>{{ egressDesc(egress) }}</code></div>
                </div>
                <div v-else class="empty-inline"><Network :size="19" />尚未配置出口</div>
              </section>
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">ROUTE SNAPSHOT</p><h2>最近生效路由</h2></div><button class="text-button" @click="navigate('routes')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="listState.routes.items.length" class="compact-list">
                  <div v-for="route in listState.routes.items.slice(0, 4)" :key="route.cidr" class="compact-row"><code>{{ route.cidr }}</code><span>egress</span><code>{{ egressByIndex.get(Number(route.value))?.name || '索引 ' + route.value }}</code></div>
                </div>
                <div v-else class="empty-inline"><Route :size="19" />尚无动态 IPv4 路由</div>
              </section>
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">IP ROUTING</p><h2>最近 IP 规则</h2></div><button class="text-button" @click="navigate('cidrs')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="listState.cidrs.items.length" class="compact-list">
                  <div v-for="cidr in listState.cidrs.items.slice(0, 4)" :key="cidr.cidr" class="compact-row"><code>{{ cidr.cidr }}</code><span class="row-name">{{ cidr.egress }}</span></div>
                </div>
                <div v-else class="empty-inline"><Network :size="19" />尚无显式 IP 规则</div>
              </section>
              <section class="panel-list">
                <div class="section-heading"><div><p class="eyebrow">SOURCE WHITELIST</p><h2>源地址白名单</h2></div><button class="text-button" @click="navigate('whitelist')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="listState.whitelist.items.length" class="compact-list">
                  <div v-for="item in listState.whitelist.items.slice(0, 4)" :key="item.cidr" class="compact-row"><code>{{ item.cidr }}</code><span class="row-name">ingress 白名单</span><span class="badge badge-teal">白名单</span></div>
                </div>
                <div v-else class="empty-inline"><Shield :size="19" />尚未配置源地址白名单</div>
              </section>
              <section class="panel-list panel-wide">
                <div class="section-heading"><div><p class="eyebrow">UPSTREAM DNS</p><h2>上游 DNS</h2></div><button class="text-button" @click="navigate('dns-servers')">查看全部 <ArrowUpRight :size="16" /></button></div>
                <div v-if="lookups.dnsServers.length" class="compact-list">
                  <div v-for="server in lookups.dnsServers.slice(0, 4)" :key="server.name" class="compact-row"><span class="row-name">{{ server.name }}</span><span class="badge" :class="server.type === 'doh' ? 'badge-teal' : server.type === 'dot' ? 'badge-lime' : 'badge-neutral'">{{ dnsTypeLabel(server.type) }}</span><code>{{ server.server || server.ip || '-' }}</code></div>
                </div>
                <div v-else class="empty-inline"><Radio :size="19" />尚未配置上游 DNS</div>
              </section>
            </div>
            <section class="guidance">
              <CircleHelp :size="20" />
              <p>域名规则在 DNS 响应命中后写入当前 IPv4 路由快照；IP 规则直接按 CIDR 网段生效，不依赖 DNS 解析。出口配置当前保存 fwmark 与隧道参数，策略路由和隧道生命周期由后端后续接管。</p>
            </section>
          </section>

          <section v-else-if="currentView === 'nics'" class="view">
            <div class="section-heading">
              <div><p class="eyebrow">EBPF ATTACHMENTS</p><h2>网卡与 eBPF 挂载</h2></div>
              <span class="item-count">{{ nics.length }} 项</span>
            </div>
            <div class="nic-settings">
              <label class="mount-all-toggle" :class="{ enabled: bpfSettings?.mount_all }">
                <input type="checkbox" :checked="bpfSettings?.mount_all" :disabled="nicBusy === 'mount-all'" @change="toggleMountAll" />
                <span>启动时全部挂载</span>
              </label>
              <p class="nic-hint">勾选“自动挂载”的网卡会在程序启动时自动挂载 eBPF；未勾选任何网卡且未开启全部挂载时，保持挂载默认路由网卡。</p>
            </div>
            <div v-if="bpfStatus && !bpfStatus.ready" class="alert alert-error"><AlertCircle :size="18" /><span>eBPF 程序尚未就绪，暂时无法挂载新网卡；已有挂载仍可解除。</span></div>
            <div v-if="nicsLoading && !nics.length" class="loading-state"><LoaderCircle :size="24" class="spinning" /><span>正在读取网卡信息</span></div>
            <div v-else-if="nics.length" class="table-wrap"><table><thead><tr>
              <th>网卡</th><th>状态</th><th>类型</th><th>MAC 地址</th><th>IP 地址</th><th>MTU</th><th>自动挂载</th><th>eBPF</th><th></th>
            </tr></thead><tbody><tr v-for="nic in nics" :key="nic.name">
              <td class="row-name">{{ nic.name }}<small class="nic-index">#{{ nic.index }}</small></td>
              <td><span class="badge" :class="nic.state === 'up' ? 'badge-teal' : 'badge-neutral'">{{ nic.state }}</span></td>
              <td class="muted">{{ nic.type }}</td>
              <td><code>{{ nic.mac || '-' }}</code></td>
              <td class="nic-addresses"><code v-for="addr in nic.addresses" :key="addr">{{ addr }}</code><span v-if="!nic.addresses?.length" class="muted">-</span></td>
              <td class="muted">{{ nic.mtu }}</td>
              <td>
                <label class="auto-mount-check" :class="{ checked: nic.auto_mount }" :title="nic.flags?.includes('loopback') ? 'loopback 不支持挂载' : '程序启动时自动挂载 eBPF 到该网卡'">
                  <input type="checkbox" :checked="nic.auto_mount" :disabled="nic.flags?.includes('loopback') || nicBusy === 'auto:' + nic.name" @change="toggleAutoMount(nic)" />
                </label>
              </td>
              <td><span class="badge" :class="nic.attached ? 'badge-lime' : 'badge-neutral'">{{ nic.attached ? '已挂载' : '未挂载' }}</span></td>
              <td class="actions">
                <button v-if="nic.attached" type="button" class="secondary-button" :disabled="nicBusy === nic.name" @click="toggleNic(nic)">
                  <LoaderCircle v-if="nicBusy === nic.name" :size="15" class="spinning" /><X v-else :size="15" />解除挂载
                </button>
                <button v-else type="button" class="primary-button" :disabled="nicBusy === nic.name || !bpfStatus?.ready || nic.flags?.includes('loopback')" :title="nic.flags?.includes('loopback') ? 'loopback 不支持挂载' : '挂载 eBPF 到该网卡'" @click="toggleNic(nic)">
                  <LoaderCircle v-if="nicBusy === nic.name" :size="15" class="spinning" /><Link2 v-else :size="15" />挂载
                </button>
              </td>
            </tr></tbody></table></div>
            <div v-else class="empty-state"><Cable :size="28" /><h2>未发现网卡</h2></div>
          </section>

          <section v-else-if="currentView === 'egresses'" class="view">
            <div class="section-heading"><div><p class="eyebrow">EGRESS TARGETS</p><h2>流量出口</h2></div><span class="item-count">{{ listState.egresses.total }} 项</span></div>
            <ListControls :list="listState.egresses" :sort-fields="sortOptions.egresses" placeholder="搜索名称 / 类型 / fwmark / 地址" @change="loadList('egresses', $event)" />
            <div v-if="listState.egresses.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.egresses.sort === 'name' }" @click="toggleSort('egresses', 'name')">名称 <SortIcon :state="listState.egresses" field="name" /></th><th class="sortable" :class="{ 'sort-active': listState.egresses.sort === 'type' }" @click="toggleSort('egresses', 'type')">类型 <SortIcon :state="listState.egresses" field="type" /></th><th class="sortable" :class="{ 'sort-active': listState.egresses.sort === 'fwmark' }" @click="toggleSort('egresses', 'fwmark')">处理方式 <SortIcon :state="listState.egresses" field="fwmark" /></th><th>隧道地址</th><th></th></tr></thead><tbody><tr v-for="item in listState.egresses.items" :key="item.name"><td class="row-name">{{ item.name }}</td><td><span class="badge" :class="item.type === 'http_tunnel' ? 'badge-teal' : item.type === 'tproxy' ? 'badge-lime' : 'badge-neutral'">{{ item.type === 'http_tunnel' ? 'HTTP 隧道' : item.type === 'tproxy' ? '本地 TPROXY' : '手工出口' }}</span></td><td><code>{{ egressDesc(item) }}</code></td><td class="muted truncate">{{ item.tunnel?.url || '-' }}</td><td class="actions"><button class="icon-button" title="编辑出口" @click="openEgress(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除出口" @click="remove('egress', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.egresses.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的出口</h2><button class="text-button" @click="clearSearch('egresses')">清除搜索</button></div>
            <div v-else class="empty-state"><Network :size="28" /><h2>还没有出口配置</h2><button class="primary-button" @click="openEgress()"><Plus :size="18" />新建出口</button></div>
          </section>

          <section v-else-if="currentView === 'domains'" class="view">
            <div class="section-heading"><div><p class="eyebrow">DNS ROUTING</p><h2>域名规则</h2></div><span class="item-count">{{ listState.domains.total }} 项</span></div>
            <ListControls :list="listState.domains" :sort-fields="sortOptions.domains" placeholder="搜索域名 / 匹配方式 / 出口" @change="loadList('domains', $event)" />
            <div v-if="listState.domains.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.domains.sort === 'domain' }" @click="toggleSort('domains', 'domain')">域名 <SortIcon :state="listState.domains" field="domain" /></th><th class="sortable" :class="{ 'sort-active': listState.domains.sort === 'match' }" @click="toggleSort('domains', 'match')">匹配方式 <SortIcon :state="listState.domains" field="match" /></th><th class="sortable" :class="{ 'sort-active': listState.domains.sort === 'egress' }" @click="toggleSort('domains', 'egress')">出口 <SortIcon :state="listState.domains" field="egress" /></th><th>出口方式</th><th></th></tr></thead><tbody><tr v-for="item in listState.domains.items" :key="item.match + item.domain"><td class="row-name">{{ item.domain }}</td><td><span class="badge badge-lime">{{ item.match === 'full' ? '精确匹配' : '域及子域' }}</span></td><td>{{ item.egress || '-' }}</td><td><code>{{ egressDesc(egressByName.get(item.egress)) }}</code></td><td class="actions"><button class="icon-button" title="编辑规则" @click="openDomain(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除规则" @click="remove('domain', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.domains.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的域名规则</h2><button class="text-button" @click="clearSearch('domains')">清除搜索</button></div>
            <div v-else class="empty-state"><Globe2 :size="28" /><h2>还没有域名规则</h2><button class="primary-button" @click="openDomain()"><Plus :size="18" />新建规则</button></div>
          </section>

          <section v-else-if="currentView === 'cidrs'" class="view">
            <div class="section-heading"><div><p class="eyebrow">IP ROUTING</p><h2>IP 规则</h2></div><span class="item-count">{{ listState.cidrs.total }} 项</span></div>
            <ListControls :list="listState.cidrs" :sort-fields="sortOptions.cidrs" placeholder="搜索 CIDR 网段 / 出口" @change="loadList('cidrs', $event)" />
            <div v-if="listState.cidrs.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.cidrs.sort === 'cidr' }" @click="toggleSort('cidrs', 'cidr')">CIDR 网段 <SortIcon :state="listState.cidrs" field="cidr" /></th><th class="sortable" :class="{ 'sort-active': listState.cidrs.sort === 'egress' }" @click="toggleSort('cidrs', 'egress')">出口 <SortIcon :state="listState.cidrs" field="egress" /></th><th>出口方式</th><th></th></tr></thead><tbody><tr v-for="item in listState.cidrs.items" :key="item.cidr"><td class="row-name"><code>{{ item.cidr }}</code></td><td>{{ item.egress || '-' }}</td><td><code>{{ egressDesc(egressByName.get(item.egress)) }}</code></td><td class="actions"><button class="icon-button" title="编辑规则" @click="openCidr(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除规则" @click="remove('cidr', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.cidrs.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的 IP 规则</h2><button class="text-button" @click="clearSearch('cidrs')">清除搜索</button></div>
            <div v-else class="empty-state"><Network :size="28" /><h2>还没有 IP 规则</h2><button class="primary-button" @click="openCidr()"><Plus :size="18" />新建 IP 规则</button></div>
          </section>

          <section v-else-if="currentView === 'hosts'" class="view">
            <div class="section-heading"><div><p class="eyebrow">STATIC DNS</p><h2>静态 Hosts</h2></div><span class="item-count">{{ listState.hosts.total }} 项</span></div>
            <ListControls :list="listState.hosts" :sort-fields="sortOptions.hosts" placeholder="搜索主机名 / IP 地址" @change="loadList('hosts', $event)" />
            <div v-if="listState.hosts.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.hosts.sort === 'name' }" @click="toggleSort('hosts', 'name')">主机名 <SortIcon :state="listState.hosts" field="name" /></th><th class="sortable" :class="{ 'sort-active': listState.hosts.sort === 'ip' }" @click="toggleSort('hosts', 'ip')">IP 地址 <SortIcon :state="listState.hosts" field="ip" /></th><th></th></tr></thead><tbody><tr v-for="item in listState.hosts.items" :key="item.name"><td class="row-name">{{ item.name }}</td><td><code>{{ item.ip }}</code></td><td class="actions"><button class="icon-button" title="编辑 Hosts" @click="openHost(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除 Hosts" @click="remove('host', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.hosts.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的静态 Hosts</h2><button class="text-button" @click="clearSearch('hosts')">清除搜索</button></div>
            <div v-else class="empty-state"><Server :size="28" /><h2>还没有静态 Hosts</h2><button class="primary-button" @click="openHost()"><Plus :size="18" />新建 Hosts</button></div>
          </section>

          <section v-else-if="currentView === 'dns-servers'" class="view">
            <div class="section-heading"><div><p class="eyebrow">UPSTREAM DNS</p><h2>上游 DNS 服务</h2></div><span class="item-count">{{ listState.dnsServers.total }} 项</span></div>
            <ListControls :list="listState.dnsServers" :sort-fields="sortOptions.dnsServers" placeholder="搜索名称 / 类型 / 服务器 / IP" @change="loadList('dnsServers', $event)" />
            <div v-if="listState.dnsServers.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.dnsServers.sort === 'name' }" @click="toggleSort('dnsServers', 'name')">名称 <SortIcon :state="listState.dnsServers" field="name" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsServers.sort === 'type' }" @click="toggleSort('dnsServers', 'type')">类型 <SortIcon :state="listState.dnsServers" field="type" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsServers.sort === 'server' }" @click="toggleSort('dnsServers', 'server')">服务器 <SortIcon :state="listState.dnsServers" field="server" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsServers.sort === 'ip' }" @click="toggleSort('dnsServers', 'ip')">直连 IP <SortIcon :state="listState.dnsServers" field="ip" /></th><th>证书校验</th><th>连接状态</th><th></th></tr></thead><tbody><tr v-for="item in listState.dnsServers.items" :key="item.name"><td class="row-name">{{ item.name }}</td><td><span class="badge" :class="item.type === 'doh' ? 'badge-teal' : item.type === 'dot' ? 'badge-lime' : 'badge-neutral'">{{ dnsTypeLabel(item.type) }}</span></td><td class="muted truncate">{{ item.server || '-' }}</td><td><code>{{ item.ip || '-' }}</code></td><td class="muted">{{ item.insecure ? '跳过' : '校验' }}</td><td class="dns-test-cell"><span v-if="dnsServerTest[item.name]?.testing" class="dns-testing"><LoaderCircle :size="13" class="spinning" />测试中</span><span v-else-if="dnsServerTest[item.name]" :class="dnsServerTest[item.name].ok ? 'dns-test-ok-text' : 'dns-test-fail-text'">{{ dnsServerTest[item.name].message }}</span><span v-else class="muted">未测试</span></td><td class="actions"><button class="icon-button" title="测试连接" :disabled="dnsServerTest[item.name]?.testing" @click="testDNSServerRow(item)"><Activity :size="17" /></button><button class="icon-button" title="编辑上游" @click="openDNSServer(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除上游" @click="remove('dns-server', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.dnsServers.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的上游 DNS</h2><button class="text-button" @click="clearSearch('dnsServers')">清除搜索</button></div>
            <div v-else class="empty-state"><Radio :size="28" /><h2>还没有上游 DNS 配置</h2><button class="primary-button" @click="openDNSServer()"><Plus :size="18" />新建上游</button></div>
          </section>

          <section v-else-if="currentView === 'whitelist'" class="view">
            <div class="section-heading"><div><p class="eyebrow">SOURCE WHITELIST</p><h2>源地址白名单</h2></div><span class="item-count">{{ listState.whitelist.total }} 项</span></div>
            <ListControls :list="listState.whitelist" :sort-fields="sortOptions.whitelist" placeholder="搜索 CIDR 网段" @change="loadList('whitelist', $event)" />
            <div v-if="listState.whitelist.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.whitelist.sort === 'cidr' }" @click="toggleSort('whitelist', 'cidr')">CIDR 网段 <SortIcon :state="listState.whitelist" field="cidr" /></th><th>说明</th><th></th></tr></thead><tbody><tr v-for="item in listState.whitelist.items" :key="item.cidr"><td class="row-name"><code>{{ item.cidr }}</code></td><td class="muted">该网段源地址的流量执行 ingress 后续处理，其余直接放行</td><td class="actions"><button class="icon-button" title="编辑条目" @click="openWhitelist(item)"><Pencil :size="17" /></button><button class="icon-button danger" title="删除条目" @click="remove('whitelist', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.whitelist.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的白名单条目</h2><button class="text-button" @click="clearSearch('whitelist')">清除搜索</button></div>
            <div v-else class="empty-state"><Shield :size="28" /><h2>还没有白名单条目</h2><button class="primary-button" @click="openWhitelist()"><Plus :size="18" />新增白名单</button></div>
          </section>

          <section v-else-if="currentView === 'routes'" class="view">
            <div class="section-heading"><div><p class="eyebrow">ACTIVE SNAPSHOT</p><h2>当前 IPv4 路由</h2></div><span class="item-count">{{ listState.routes.total }} 项</span></div>
            <ListControls :list="listState.routes" :sort-fields="sortOptions.routes" placeholder="搜索 CIDR / egress 索引" @change="loadList('routes', $event)" />
            <div v-if="listState.routes.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.routes.sort === 'cidr' }" @click="toggleSort('routes', 'cidr')">CIDR <SortIcon :state="listState.routes" field="cidr" /></th><th class="sortable" :class="{ 'sort-active': listState.routes.sort === 'value' }" @click="toggleSort('routes', 'value')">egress 索引 <SortIcon :state="listState.routes" field="value" /></th><th>关联出口</th></tr></thead><tbody><tr v-for="item in listState.routes.items" :key="item.cidr"><td><code>{{ item.cidr }}</code></td><td><code>{{ item.value }}</code></td><td>{{ egressByIndex.get(Number(item.value))?.name || '-' }}</td></tr></tbody></table></div>
            <div v-else-if="listState.routes.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的路由</h2><button class="text-button" @click="clearSearch('routes')">清除搜索</button></div>
            <div v-else class="empty-state"><Route :size="28" /><h2>当前没有动态 IPv4 路由</h2></div>
          </section>

          <section v-else-if="currentView === 'dns-cache'" class="view">
            <div class="section-heading"><div><p class="eyebrow">RESOLVER CACHE</p><h2>DNS 解析缓存</h2></div><span class="item-count">{{ listState.dnsCache.total }} 项</span></div>
            <ListControls :list="listState.dnsCache" :sort-fields="sortOptions.dnsCache" placeholder="搜索域名 / 类型 / 解析结果 / 状态" @change="loadList('dnsCache', $event)" />
            <div v-if="listState.dnsCache.items.length" class="table-wrap"><table><thead><tr><th class="sortable" :class="{ 'sort-active': listState.dnsCache.sort === 'name' }" @click="toggleSort('dnsCache', 'name')">域名 <SortIcon :state="listState.dnsCache" field="name" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsCache.sort === 'type' }" @click="toggleSort('dnsCache', 'type')">类型 <SortIcon :state="listState.dnsCache" field="type" /></th><th>解析结果</th><th class="sortable" :class="{ 'sort-active': listState.dnsCache.sort === 'lastAccessAt' }" @click="toggleSort('dnsCache', 'lastAccessAt')">最近访问 <SortIcon :state="listState.dnsCache" field="lastAccessAt" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsCache.sort === 'ttl' }" @click="toggleSort('dnsCache', 'ttl')">剩余 TTL <SortIcon :state="listState.dnsCache" field="ttl" /></th><th class="sortable" :class="{ 'sort-active': listState.dnsCache.sort === 'expiresAt' }" @click="toggleSort('dnsCache', 'expiresAt')">过期时间 <SortIcon :state="listState.dnsCache" field="expiresAt" /></th><th></th></tr></thead><tbody><tr v-for="item in listState.dnsCache.items" :key="item.name + item.type"><td class="row-name">{{ item.name }}</td><td><span class="badge badge-teal">{{ item.type }}</span></td><td class="dns-answers"><code v-for="answer in item.answers" :key="answer">{{ answer }}</code></td><td class="muted">{{ new Date(item.lastAccessAt).toLocaleString('zh-CN', { hour12: false }) }}</td><td><code :class="{ 'dns-expired': item.expired }">{{ item.expired ? '已过期' : item.ttl + 's' }}</code></td><td class="muted" :class="{ 'dns-expired': item.expired }">{{ new Date(item.expiresAt).toLocaleString('zh-CN', { hour12: false }) }}</td><td class="actions"><button class="icon-button" title="基于该缓存创建域名规则" @click="createDomainFromCache(item)"><Plus :size="17" /></button><button class="icon-button danger" title="删除缓存条目" @click="remove('dns-cache', item)"><Trash2 :size="17" /></button></td></tr></tbody></table></div>
            <div v-else-if="listState.dnsCache.search" class="empty-state"><SearchX :size="28" /><h2>没有匹配的 DNS 缓存记录</h2><button class="text-button" @click="clearSearch('dnsCache')">清除搜索</button></div>
            <div v-else class="empty-state"><Database :size="28" /><h2>暂无 DNS 缓存记录</h2></div>
          </section>
        </template>
      </section>

      <div v-if="modal" class="modal-backdrop" @mousedown.self="closeModal">
        <form class="modal" @submit.prevent="modal === 'egress' ? saveEgress() : modal === 'domain' ? saveDomain() : modal === 'cidr' ? saveCidr() : modal === 'dns-test' ? runDNSTest() : modal === 'dns-server' ? saveDNSServer() : modal === 'whitelist' ? saveWhitelist() : saveHost()">
          <header><div><p class="eyebrow">CONFIGURATION</p><h2>{{ modalTitle }}</h2></div><button type="button" class="icon-button" title="关闭" @click="closeModal"><X :size="18" /></button></header>
          <div v-if="modal === 'egress'" class="form-fields">
            <label><span>名称</span><input v-model="egressForm.name" :disabled="!!editing" required placeholder="proxy-a" /></label>
            <label><span>类型</span><select v-model="egressForm.type"><option value="manual">自定义出口</option><option value="http_tunnel">HTTP 隧道</option><option value="tproxy">本地 TPROXY</option></select></label>
            <label v-if="egressForm.type !== 'tproxy'"><span>fwmark</span><input v-model.number="egressForm.fwmark" type="number" min="0" step="1" required placeholder="4097" /><small v-if="egressForm.fwmark !== ''">{{ hexMark(egressForm.fwmark) }}</small></label>
            <template v-if="egressForm.type === 'http_tunnel'"><label><span>隧道地址</span><input v-model="egressForm.tunnel.url" type="url" placeholder="https://tunnel.example/connect" /></label><label><span>访问令牌</span><input v-model="egressForm.tunnel.token" type="password" autocomplete="new-password" placeholder="token" /></label></template>
            <template v-if="egressForm.type === 'tproxy'"><label><span>监听地址</span><input v-model="egressForm.tproxy.addr" placeholder="0.0.0.0" /><small>留空或 0.0.0.0 表示按包的原目的地址查找透明监听 socket。</small></label><label><span>监听端口</span><input v-model.number="egressForm.tproxy.port" type="number" min="0" max="65535" step="1" placeholder="12345" /><small>0 表示按包的原目的端口匹配。</small></label></template>
          </div>
          <div v-else-if="modal === 'domain'" class="form-fields">
            <label><span>域名</span><input v-model="domainForm.domain" :disabled="!!editing" required placeholder="example.com" /><small v-if="editing">域名与匹配方式共同构成规则标识。</small></label>
            <label><span>匹配方式</span><select v-model="domainForm.match" :disabled="!!editing"><option value="domain">域及其子域</option><option value="full">精确域名</option></select></label>
            <label><span>关联出口</span><select v-model="domainForm.egress" required><option value="">选择出口</option><option v-for="item in lookups.egresses" :key="item.name" :value="item.name">{{ item.name }} · {{ egressDesc(item) }}</option></select><small v-if="selectedDomainEgress">将使用 {{ egressDesc(selectedDomainEgress) }}</small></label>
          </div>
          <div v-else-if="modal === 'cidr'" class="form-fields">
            <label><span>CIDR 网段</span><input v-model="cidrForm.cidr" :disabled="!!editing" required placeholder="203.0.113.0/24" /><small>填写 IPv4 网段，如 203.0.113.0/24，直接按最长前缀匹配，不依赖 DNS 解析。</small></label>
            <label><span>关联出口</span><select v-model="cidrForm.egress" required><option value="">选择出口</option><option v-for="item in lookups.egresses" :key="item.name" :value="item.name">{{ item.name }} · {{ egressDesc(item) }}</option></select><small v-if="selectedCidrEgress">将使用 {{ egressDesc(selectedCidrEgress) }}</small></label>
          </div>
          <div v-else-if="modal === 'dns-test'" class="form-fields">
            <label><span>已有上游（可选）</span><select v-model="dnsTestForm.source" @change="useDNSTestSource"><option value="">自定义输入</option><option v-for="item in lookups.dnsServers" :key="item.name" :value="item.name">{{ item.name }} · {{ dnsTypeLabel(item.type) }} · {{ item.server || item.ip || '-' }}</option></select><small>选择已有上游会自动填充下方配置，仍可手动修改。</small></label>
            <label><span>类型</span><select v-model="dnsTestForm.type"><option value="udp">UDP</option><option value="dot">DoT（DNS over TLS）</option><option value="doh">DoH（DNS over HTTPS）</option></select></label>
            <label v-if="dnsTestForm.type !== 'udp'"><span>服务器地址</span><input v-model="dnsTestForm.server" placeholder="doh.pub" /><small>DoH/DoT 的服务器域名，用于 TLS SNI 与证书校验。</small></label>
            <label><span>上游 IP</span><input v-model="dnsTestForm.ip" placeholder="1.12.12.12" /><small>UDP 类型必填；DoT/DoH 填写后直接连接该 IP，跳过系统 DNS 解析。</small></label>
            <label v-if="dnsTestForm.type !== 'udp'" class="check-field"><span>跳过证书校验</span><input v-model="dnsTestForm.insecure" type="checkbox" /></label>
            <label><span>测试域名</span><input v-model="dnsTestForm.qname" placeholder="example.com" /><small>向该上游发送 A 记录查询，可自行更换域名。</small></label>
            <div v-if="dnsTestResult" class="dns-test-result" :class="dnsTestResult.ok ? 'dns-test-ok' : 'dns-test-fail'">
              <component :is="dnsTestResult.ok ? 'Check' : 'X'" :size="16" />
              <div><strong>{{ dnsTestResult.message }}</strong><span v-if="dnsTestResult.latencyMs != null">耗时 {{ dnsTestResult.latencyMs }}ms</span><code v-for="answer in dnsTestResult.answers" :key="answer">{{ answer }}</code></div>
            </div>
          </div>
          <div v-else-if="modal === 'dns-server'" class="form-fields">
            <label><span>名称</span><input v-model="dnsServerForm.name" :disabled="!!editing" required placeholder="primary" /><small>页面管理标识，保存后不可修改。</small></label>
            <label><span>类型</span><select v-model="dnsServerForm.type"><option value="udp">UDP</option><option value="dot">DoT（DNS over TLS）</option><option value="doh">DoH（DNS over HTTPS）</option></select></label>
            <label v-if="dnsServerForm.type !== 'udp'"><span>服务器地址</span><input v-model="dnsServerForm.server" placeholder="doh.pub" /><small>DoH/DoT 的服务器域名，用于 TLS SNI 与证书校验。</small></label>
            <label><span>上游 IP</span><input v-model="dnsServerForm.ip" placeholder="1.12.12.12" /><small>UDP 类型必填；DoT/DoH 填写后直接连接该 IP，跳过系统 DNS 解析。</small></label>
            <label v-if="dnsServerForm.type !== 'udp'" class="check-field"><span>跳过证书校验</span><input v-model="dnsServerForm.insecure" type="checkbox" /></label>
            <div v-if="modalTestResult" class="dns-test-result" :class="modalTestResult.ok ? 'dns-test-ok' : 'dns-test-fail'">
              <component :is="modalTestResult.ok ? 'Check' : 'X'" :size="16" />
              <div><strong>{{ modalTestResult.message }}</strong><span v-if="modalTestResult.latencyMs != null">耗时 {{ modalTestResult.latencyMs }}ms</span><code v-for="answer in modalTestResult.answers" :key="answer">{{ answer }}</code></div>
            </div>
          </div>
          <div v-else-if="modal === 'whitelist'" class="form-fields"><label><span>CIDR 网段 / IP</span><input v-model="whitelistForm.cidr" required placeholder="10.0.0.0/8 或 192.168.1.1" /><small>仅 IPv4；单 IP 自动按 /32 处理，只有该网段源地址的流量才会执行 ingress 后续处理。</small></label></div>
          <div v-else class="form-fields"><label><span>主机名</span><input v-model="hostForm.name" :disabled="!!editing" required placeholder="internal.example.com" /></label><label><span>IP 地址</span><input v-model="hostForm.ip" required placeholder="192.0.2.10 或 2001:db8::10" /></label></div>
          <footer>
            <template v-if="modal === 'dns-test'"><button type="button" class="primary-button" :disabled="dnsTesting" @click="runDNSTest"><LoaderCircle v-if="dnsTesting" :size="17" class="spinning" /><Activity v-else :size="17" />开始测试</button><button type="button" class="secondary-button" @click="closeModal">关闭</button></template>
            <template v-else><button v-if="modal === 'dns-server'" type="button" class="secondary-button" :disabled="modalTesting" @click="testDNSServerForm"><LoaderCircle v-if="modalTesting" :size="17" class="spinning" /><Activity v-else :size="17" />测试连接</button><button type="button" class="secondary-button" @click="closeModal">取消</button><button type="submit" class="primary-button" :disabled="saving"><LoaderCircle v-if="saving" :size="17" class="spinning" /><Check v-else :size="17" />保存</button></template>
          </footer>
        </form>
      </div>

      <div v-if="error" class="error-dialog-backdrop" @mousedown.self="error = ''">
        <section class="error-dialog" role="alertdialog" aria-modal="true" aria-labelledby="error-dialog-title">
          <header>
            <div class="error-dialog-title"><AlertCircle :size="20" /><h2 id="error-dialog-title">操作失败</h2></div>
            <button type="button" class="icon-button" title="关闭错误提示" @click="error = ''"><X :size="18" /></button>
          </header>
          <p>{{ error }}</p>
          <footer><button type="button" class="primary-button" @click="error = ''">知道了</button></footer>
        </section>
      </div>
    </main>
  `,
}

createApp(App).mount('#app')
