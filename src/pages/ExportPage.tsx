import { memo, useCallback, useEffect, useMemo, useRef, useState, type WheelEvent } from 'react'
import { useLocation } from 'react-router-dom'
import { Virtuoso, type VirtuosoHandle } from 'react-virtuoso'
import { createPortal } from 'react-dom'
import {
  Aperture,
  Calendar,
  Check,
  CheckSquare,
  CircleHelp,
  Copy,
  Database,
  Download,
  ExternalLink,
  FolderOpen,
  Hash,
  Image as ImageIcon,
  Loader2,
  AlertTriangle,
  ClipboardList,
  MessageSquare,
  MessageSquareText,
  Mic,
  RefreshCw,
  Search,
  Square,
  Video,
  WandSparkles,
  X
} from 'lucide-react'
import type { ChatSession as AppChatSession, ContactInfo } from '../types/models'
import type { ExportOptions as ElectronExportOptions, ExportProgress } from '../types/electron'
import * as configService from '../services/config'
import {
  emitExportSessionStatus,
  emitSingleExportDialogStatus,
  onExportSessionStatusRequest,
  onOpenSingleExport
} from '../services/exportBridge'
import { useContactTypeCountsStore } from '../stores/contactTypeCountsStore'
import './ExportPage.scss'

type ConversationTab = 'private' | 'group' | 'official' | 'former_friend'
type TaskStatus = 'queued' | 'running' | 'success' | 'error'
type TaskScope = 'single' | 'multi' | 'content' | 'sns'
type ContentType = 'text' | 'voice' | 'image' | 'video' | 'emoji'
type ContentCardType = ContentType | 'sns'

type SessionLayout = 'shared' | 'per-session'

type DisplayNamePreference = 'group-nickname' | 'remark' | 'nickname'
type DateRangePreset =
  | 'all'
  | 'today'
  | 'yesterday'
  | 'last3days'
  | 'last7days'
  | 'last30days'
  | 'last1year'
  | 'last2years'
  | 'custom'
type CalendarCell = { date: Date; inCurrentMonth: boolean }

type TextExportFormat = 'chatlab' | 'chatlab-jsonl' | 'json' | 'arkme-json' | 'html' | 'txt' | 'excel' | 'weclone' | 'sql'
type SnsTimelineExportFormat = 'json' | 'html' | 'arkmejson'

interface ExportOptions {
  format: TextExportFormat
  dateRange: { start: Date; end: Date } | null
  useAllTime: boolean
  exportAvatars: boolean
  exportMedia: boolean
  exportImages: boolean
  exportVoices: boolean
  exportVideos: boolean
  exportEmojis: boolean
  exportVoiceAsText: boolean
  excelCompactColumns: boolean
  txtColumns: string[]
  displayNamePreference: DisplayNamePreference
  exportConcurrency: number
}

interface SessionRow extends AppChatSession {
  kind: ConversationTab
  wechatId?: string
  hasSession: boolean
}

interface TaskProgress {
  current: number
  total: number
  currentName: string
  phase: ExportProgress['phase'] | ''
  phaseLabel: string
  phaseProgress: number
  phaseTotal: number
}

type TaskPerfStage = 'collect' | 'build' | 'write' | 'other'

interface TaskSessionPerformance {
  sessionId: string
  sessionName: string
  startedAt: number
  finishedAt?: number
  elapsedMs: number
  lastPhase?: ExportProgress['phase']
  lastPhaseStartedAt?: number
}

interface TaskPerformance {
  stages: Record<TaskPerfStage, number>
  sessions: Record<string, TaskSessionPerformance>
}

interface ExportTaskPayload {
  sessionIds: string[]
  outputDir: string
  options?: ElectronExportOptions
  scope: TaskScope
  contentType?: ContentType
  sessionNames: string[]
  snsOptions?: {
    format: SnsTimelineExportFormat
    exportImages?: boolean
    exportLivePhotos?: boolean
    exportVideos?: boolean
    startTime?: number
    endTime?: number
  }
}

interface ExportTask {
  id: string
  title: string
  status: TaskStatus
  settledSessionIds?: string[]
  createdAt: number
  startedAt?: number
  finishedAt?: number
  error?: string
  payload: ExportTaskPayload
  progress: TaskProgress
  performance?: TaskPerformance
}

interface ExportDialogState {
  open: boolean
  scope: TaskScope
  contentType?: ContentType
  sessionIds: string[]
  sessionNames: string[]
  title: string
}

interface TimeRangeDialogDraft {
  preset: DateRangePreset
  useAllTime: boolean
  dateRange: { start: Date; end: Date }
  startPanelMonth: Date
  endPanelMonth: Date
}

const defaultTxtColumns = ['index', 'time', 'senderRole', 'messageType', 'content']
const contentTypeLabels: Record<ContentType, string> = {
  text: '聊天文本',
  voice: '语音',
  image: '图片',
  video: '视频',
  emoji: '表情包'
}

const getContentTypeLabel = (type: ContentType): string => {
  return contentTypeLabels[type] || type
}

const formatOptions: Array<{ value: TextExportFormat; label: string; desc: string }> = [
  { value: 'chatlab', label: 'ChatLab', desc: '标准格式，支持其他软件导入' },
  { value: 'chatlab-jsonl', label: 'ChatLab JSONL', desc: '流式格式，适合大量消息' },
  { value: 'json', label: 'JSON', desc: '详细格式，包含完整消息信息' },
  { value: 'arkme-json', label: 'Arkme JSON', desc: '紧凑 JSON，支持 sender 去重与关系统计' },
  { value: 'html', label: 'HTML', desc: '网页格式，可直接浏览' },
  { value: 'txt', label: 'TXT', desc: '纯文本，通用格式' },
  { value: 'excel', label: 'Excel', desc: '电子表格，适合统计分析' },
  { value: 'weclone', label: 'WeClone CSV', desc: 'WeClone 兼容字段格式（CSV）' },
  { value: 'sql', label: 'PostgreSQL', desc: '数据库脚本，便于导入到数据库' }
]

const displayNameOptions: Array<{ value: DisplayNamePreference; label: string; desc: string }> = [
  { value: 'group-nickname', label: '群昵称优先', desc: '仅群聊有效，私聊显示备注/昵称' },
  { value: 'remark', label: '备注优先', desc: '有备注显示备注，否则显示昵称' },
  { value: 'nickname', label: '微信昵称', desc: '始终显示微信昵称' }
]

const writeLayoutOptions: Array<{ value: configService.ExportWriteLayout; label: string; desc: string }> = [
  {
    value: 'A',
    label: 'A（类型分目录）',
    desc: '聊天文本、语音、视频、表情包、图片分别创建文件夹'
  },
  {
    value: 'B',
    label: 'B（文本根目录+媒体按会话）',
    desc: '聊天文本在根目录；媒体按类型目录后再按会话分目录'
  },
  {
    value: 'C',
    label: 'C（按会话分目录）',
    desc: '每个会话一个目录，目录内包含文本与媒体文件'
  }
]

const createEmptyProgress = (): TaskProgress => ({
  current: 0,
  total: 0,
  currentName: '',
  phase: '',
  phaseLabel: '',
  phaseProgress: 0,
  phaseTotal: 0
})

const createEmptyTaskPerformance = (): TaskPerformance => ({
  stages: {
    collect: 0,
    build: 0,
    write: 0,
    other: 0
  },
  sessions: {}
})

const isTextBatchTask = (task: ExportTask): boolean => (
  task.payload.scope === 'content' && task.payload.contentType === 'text'
)

const resolvePerfStageByPhase = (phase?: ExportProgress['phase']): TaskPerfStage => {
  if (phase === 'preparing') return 'collect'
  if (phase === 'writing') return 'write'
  if (phase === 'exporting' || phase === 'exporting-media' || phase === 'exporting-voice') return 'build'
  return 'other'
}

const cloneTaskPerformance = (performance?: TaskPerformance): TaskPerformance => ({
  stages: {
    collect: performance?.stages.collect || 0,
    build: performance?.stages.build || 0,
    write: performance?.stages.write || 0,
    other: performance?.stages.other || 0
  },
  sessions: Object.fromEntries(
    Object.entries(performance?.sessions || {}).map(([sessionId, session]) => [sessionId, { ...session }])
  )
})

const resolveTaskSessionName = (task: ExportTask, sessionId: string, fallback?: string): string => {
  const idx = task.payload.sessionIds.indexOf(sessionId)
  if (idx >= 0) {
    return task.payload.sessionNames[idx] || fallback || sessionId
  }
  return fallback || sessionId
}

const applyProgressToTaskPerformance = (
  task: ExportTask,
  payload: ExportProgress,
  now: number
): TaskPerformance | undefined => {
  if (!isTextBatchTask(task)) return task.performance
  const sessionId = String(payload.currentSessionId || '').trim()
  if (!sessionId) return task.performance || createEmptyTaskPerformance()

  const performance = cloneTaskPerformance(task.performance)
  const sessionName = resolveTaskSessionName(task, sessionId, payload.currentSession || sessionId)
  const existing = performance.sessions[sessionId]
  const session: TaskSessionPerformance = existing
    ? { ...existing, sessionName: existing.sessionName || sessionName }
    : {
      sessionId,
      sessionName,
      startedAt: now,
      elapsedMs: 0
    }

  if (!session.finishedAt && session.lastPhase && typeof session.lastPhaseStartedAt === 'number') {
    const delta = Math.max(0, now - session.lastPhaseStartedAt)
    performance.stages[resolvePerfStageByPhase(session.lastPhase)] += delta
  }

  session.elapsedMs = Math.max(session.elapsedMs, now - session.startedAt)

  if (payload.phase === 'complete') {
    session.finishedAt = now
    session.lastPhase = undefined
    session.lastPhaseStartedAt = undefined
  } else {
    session.lastPhase = payload.phase
    session.lastPhaseStartedAt = now
  }

  performance.sessions[sessionId] = session
  return performance
}

const finalizeTaskPerformance = (task: ExportTask, now: number): TaskPerformance | undefined => {
  if (!isTextBatchTask(task) || !task.performance) return task.performance
  const performance = cloneTaskPerformance(task.performance)
  for (const session of Object.values(performance.sessions)) {
    if (session.finishedAt) continue
    if (session.lastPhase && typeof session.lastPhaseStartedAt === 'number') {
      const delta = Math.max(0, now - session.lastPhaseStartedAt)
      performance.stages[resolvePerfStageByPhase(session.lastPhase)] += delta
    }
    session.elapsedMs = Math.max(session.elapsedMs, now - session.startedAt)
    session.finishedAt = now
    session.lastPhase = undefined
    session.lastPhaseStartedAt = undefined
  }
  return performance
}

const getTaskPerformanceStageTotals = (
  performance: TaskPerformance | undefined,
  now: number
): Record<TaskPerfStage, number> => {
  const totals: Record<TaskPerfStage, number> = {
    collect: performance?.stages.collect || 0,
    build: performance?.stages.build || 0,
    write: performance?.stages.write || 0,
    other: performance?.stages.other || 0
  }
  if (!performance) return totals
  for (const session of Object.values(performance.sessions)) {
    if (session.finishedAt) continue
    if (!session.lastPhase || typeof session.lastPhaseStartedAt !== 'number') continue
    const delta = Math.max(0, now - session.lastPhaseStartedAt)
    totals[resolvePerfStageByPhase(session.lastPhase)] += delta
  }
  return totals
}

const getTaskPerformanceTopSessions = (
  performance: TaskPerformance | undefined,
  now: number,
  limit = 5
): Array<TaskSessionPerformance & { liveElapsedMs: number }> => {
  if (!performance) return []
  return Object.values(performance.sessions)
    .map((session) => {
      const liveElapsedMs = session.finishedAt
        ? session.elapsedMs
        : Math.max(session.elapsedMs, now - session.startedAt)
      return {
        ...session,
        liveElapsedMs
      }
    })
    .sort((a, b) => b.liveElapsedMs - a.liveElapsedMs)
    .slice(0, limit)
}

const formatDurationMs = (ms: number): string => {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000))
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  if (hours > 0) {
    return `${hours}小时${minutes}分${seconds}秒`
  }
  if (minutes > 0) {
    return `${minutes}分${seconds}秒`
  }
  return `${seconds}秒`
}

const getTaskStatusLabel = (task: ExportTask): string => {
  if (task.status === 'queued') return '排队中'
  if (task.status === 'running') return '进行中'
  if (task.status === 'success') return '已完成'
  return '失败'
}

const formatAbsoluteDate = (timestamp: number): string => {
  const d = new Date(timestamp)
  const y = d.getFullYear()
  const m = `${d.getMonth() + 1}`.padStart(2, '0')
  const day = `${d.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${day}`
}

const formatYmdDateFromSeconds = (timestamp?: number): string => {
  if (!timestamp || !Number.isFinite(timestamp)) return '—'
  const d = new Date(timestamp * 1000)
  const y = d.getFullYear()
  const m = `${d.getMonth() + 1}`.padStart(2, '0')
  const day = `${d.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${day}`
}

const formatYmdHmDateTime = (timestamp?: number): string => {
  if (!timestamp || !Number.isFinite(timestamp)) return '—'
  const d = new Date(timestamp)
  const y = d.getFullYear()
  const m = `${d.getMonth() + 1}`.padStart(2, '0')
  const day = `${d.getDate()}`.padStart(2, '0')
  const h = `${d.getHours()}`.padStart(2, '0')
  const min = `${d.getMinutes()}`.padStart(2, '0')
  return `${y}-${m}-${day} ${h}:${min}`
}

const formatPathBrief = (value: string, maxLength = 52): string => {
  const normalized = String(value || '')
  if (normalized.length <= maxLength) return normalized
  const headLength = Math.max(10, Math.floor(maxLength * 0.55))
  const tailLength = Math.max(8, maxLength - headLength - 1)
  return `${normalized.slice(0, headLength)}…${normalized.slice(-tailLength)}`
}

const formatRecentExportTime = (timestamp?: number, now = Date.now()): string => {
  if (!timestamp) return ''
  const diff = Math.max(0, now - timestamp)
  const minute = 60 * 1000
  const hour = 60 * minute
  const day = 24 * hour
  if (diff < hour) {
    const minutes = Math.max(1, Math.floor(diff / minute))
    return `${minutes} 分钟前`
  }
  if (diff < day) {
    const hours = Math.max(1, Math.floor(diff / hour))
    return `${hours} 小时前`
  }
  return formatAbsoluteDate(timestamp)
}

const startOfDay = (date: Date): Date => {
  const next = new Date(date)
  next.setHours(0, 0, 0, 0)
  return next
}

const endOfDay = (date: Date): Date => {
  const next = new Date(date)
  next.setHours(23, 59, 59, 999)
  return next
}

const createDefaultDateRange = (): { start: Date; end: Date } => {
  const now = new Date()
  return {
    start: startOfDay(now),
    end: now
  }
}

const createDateRangeByPreset = (
  preset: Exclude<DateRangePreset, 'all' | 'custom'>,
  now = new Date()
): { start: Date; end: Date } => {
  const end = new Date(now)
  const baseStart = startOfDay(now)

  if (preset === 'today') {
    return { start: baseStart, end }
  }

  if (preset === 'yesterday') {
    const yesterday = new Date(baseStart)
    yesterday.setDate(yesterday.getDate() - 1)
    return {
      start: yesterday,
      end: endOfDay(yesterday)
    }
  }

  if (preset === 'last1year' || preset === 'last2years') {
    const yearsBack = preset === 'last1year' ? 1 : 2
    const start = new Date(baseStart)
    const expectedMonth = start.getMonth()
    start.setFullYear(start.getFullYear() - yearsBack)
    // Handle leap-year fallback (e.g. Feb 29 -> Feb 28).
    if (start.getMonth() !== expectedMonth) {
      start.setDate(0)
    }
    return { start, end }
  }

  const daysBack = preset === 'last3days' ? 2 : preset === 'last7days' ? 6 : 29
  const start = new Date(baseStart)
  start.setDate(start.getDate() - daysBack)
  return { start, end }
}

const formatDateInputValue = (date: Date): string => {
  const y = date.getFullYear()
  const m = `${date.getMonth() + 1}`.padStart(2, '0')
  const d = `${date.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${d}`
}

const parseDateInputValue = (raw: string): Date | null => {
  const text = String(raw || '').trim()
  const matched = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text)
  if (!matched) return null
  const year = Number(matched[1])
  const month = Number(matched[2])
  const day = Number(matched[3])
  if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) return null
  if (month < 1 || month > 12 || day < 1 || day > 31) return null
  const parsed = new Date(year, month - 1, day)
  if (
    parsed.getFullYear() !== year ||
    parsed.getMonth() !== month - 1 ||
    parsed.getDate() !== day
  ) {
    return null
  }
  return parsed
}

const toMonthStart = (date: Date): Date => new Date(date.getFullYear(), date.getMonth(), 1)

const addMonths = (date: Date, delta: number): Date => {
  const next = new Date(date)
  next.setMonth(next.getMonth() + delta)
  return toMonthStart(next)
}

const isSameDay = (left: Date, right: Date): boolean => (
  left.getFullYear() === right.getFullYear() &&
  left.getMonth() === right.getMonth() &&
  left.getDate() === right.getDate()
)

const buildCalendarCells = (monthStart: Date): CalendarCell[] => {
  const firstDay = new Date(monthStart.getFullYear(), monthStart.getMonth(), 1)
  const startOffset = firstDay.getDay()
  const gridStart = new Date(firstDay)
  gridStart.setDate(gridStart.getDate() - startOffset)
  const cells: CalendarCell[] = []
  for (let index = 0; index < 42; index += 1) {
    const current = new Date(gridStart)
    current.setDate(gridStart.getDate() + index)
    cells.push({
      date: current,
      inCurrentMonth: current.getMonth() === monthStart.getMonth()
    })
  }
  return cells
}

const formatCalendarMonthTitle = (date: Date): string => `${date.getFullYear()}年${date.getMonth() + 1}月`

const WEEKDAY_SHORT_LABELS = ['日', '一', '二', '三', '四', '五', '六']

const toKindByContactType = (session: AppChatSession, contact?: ContactInfo): ConversationTab => {
  if (session.username.endsWith('@chatroom')) return 'group'
  if (session.username.startsWith('gh_')) return 'official'
  if (contact?.type === 'official') return 'official'
  if (contact?.type === 'former_friend') return 'former_friend'
  return 'private'
}

const toKindByContact = (contact: ContactInfo): ConversationTab => {
  if (contact.type === 'group') return 'group'
  if (contact.type === 'official') return 'official'
  if (contact.type === 'former_friend') return 'former_friend'
  return 'private'
}

const isContentScopeSession = (session: SessionRow): boolean => (
  session.kind === 'private' || session.kind === 'group' || session.kind === 'former_friend'
)

const exportKindPriority: Record<ConversationTab, number> = {
  private: 0,
  group: 1,
  former_friend: 2,
  official: 3
}

const getAvatarLetter = (name: string): string => {
  if (!name) return '?'
  return [...name][0] || '?'
}

const matchesContactTab = (contact: ContactInfo, tab: ConversationTab): boolean => {
  if (tab === 'private') return contact.type === 'friend'
  if (tab === 'group') return contact.type === 'group'
  if (tab === 'official') return contact.type === 'official'
  return contact.type === 'former_friend'
}

const createTaskId = (): string => `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const CONTACT_ENRICH_TIMEOUT_MS = 7000
const EXPORT_SNS_STATS_CACHE_STALE_MS = 12 * 60 * 60 * 1000
const EXPORT_AVATAR_ENRICH_BATCH_SIZE = 80
const DEFAULT_CONTACTS_LOAD_TIMEOUT_MS = 3000
const EXPORT_REENTER_SESSION_SOFT_REFRESH_MS = 5 * 60 * 1000
const EXPORT_REENTER_CONTACTS_SOFT_REFRESH_MS = 5 * 60 * 1000
const EXPORT_REENTER_SNS_SOFT_REFRESH_MS = 3 * 60 * 1000
type SessionDataSource = 'cache' | 'network' | null
type ContactsDataSource = 'cache' | 'network' | null

interface ContactsLoadSession {
  requestId: string
  startedAt: number
  attempt: number
  timeoutMs: number
}

interface ContactsLoadIssue {
  kind: 'timeout' | 'error'
  title: string
  message: string
  reason: string
  errorDetail?: string
  occurredAt: number
  elapsedMs: number
}

interface SessionDetail {
  wxid: string
  displayName: string
  remark?: string
  nickName?: string
  alias?: string
  avatarUrl?: string
  messageCount: number
  voiceMessages?: number
  imageMessages?: number
  videoMessages?: number
  emojiMessages?: number
  transferMessages?: number
  redPacketMessages?: number
  callMessages?: number
  privateMutualGroups?: number
  groupMemberCount?: number
  groupMyMessages?: number
  groupActiveSpeakers?: number
  groupMutualFriends?: number
  relationStatsLoaded?: boolean
  statsUpdatedAt?: number
  statsStale?: boolean
  firstMessageTime?: number
  latestMessageTime?: number
  messageTables: { dbName: string; tableName: string; count: number }[]
}

interface SessionExportMetric {
  totalMessages: number
  voiceMessages: number
  imageMessages: number
  videoMessages: number
  emojiMessages: number
  transferMessages: number
  redPacketMessages: number
  callMessages: number
  firstTimestamp?: number
  lastTimestamp?: number
  privateMutualGroups?: number
  groupMemberCount?: number
  groupMyMessages?: number
  groupActiveSpeakers?: number
  groupMutualFriends?: number
}

interface SessionContentMetric {
  totalMessages?: number
  voiceMessages?: number
  imageMessages?: number
  videoMessages?: number
  emojiMessages?: number
  transferMessages?: number
  redPacketMessages?: number
  callMessages?: number
}

interface SessionExportCacheMeta {
  updatedAt: number
  stale: boolean
  includeRelations: boolean
  source: 'memory' | 'disk' | 'fresh'
}

const withTimeout = async <T,>(promise: Promise<T>, timeoutMs: number): Promise<T | null> => {
  let timer: ReturnType<typeof setTimeout> | null = null
  try {
    return await Promise.race([
      promise,
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs)
      })
    ])
  } finally {
    if (timer) {
      clearTimeout(timer)
    }
  }
}

const toContactMapFromCaches = (
  contacts: configService.ContactsListCacheContact[],
  avatarEntries: Record<string, configService.ContactsAvatarCacheEntry>
): Record<string, ContactInfo> => {
  const map: Record<string, ContactInfo> = {}
  for (const contact of contacts || []) {
    if (!contact?.username) continue
    map[contact.username] = {
      ...contact,
      avatarUrl: avatarEntries[contact.username]?.avatarUrl
    }
  }
  return map
}

const mergeAvatarCacheIntoContacts = (
  sourceContacts: ContactInfo[],
  avatarEntries: Record<string, configService.ContactsAvatarCacheEntry>
): ContactInfo[] => {
  if (!sourceContacts.length || Object.keys(avatarEntries).length === 0) {
    return sourceContacts
  }

  let changed = false
  const merged = sourceContacts.map((contact) => {
    const cachedAvatar = avatarEntries[contact.username]?.avatarUrl
    if (!cachedAvatar || contact.avatarUrl) {
      return contact
    }
    changed = true
    return {
      ...contact,
      avatarUrl: cachedAvatar
    }
  })

  return changed ? merged : sourceContacts
}

const upsertAvatarCacheFromContacts = (
  avatarEntries: Record<string, configService.ContactsAvatarCacheEntry>,
  sourceContacts: ContactInfo[],
  options?: { prune?: boolean; markCheckedUsernames?: string[]; now?: number }
): {
  avatarEntries: Record<string, configService.ContactsAvatarCacheEntry>
  changed: boolean
  updatedAt: number | null
} => {
  const nextCache = { ...avatarEntries }
  const now = options?.now || Date.now()
  const markCheckedSet = new Set((options?.markCheckedUsernames || []).filter(Boolean))
  const usernamesInSource = new Set<string>()
  let changed = false

  for (const contact of sourceContacts) {
    const username = String(contact.username || '').trim()
    if (!username) continue
    usernamesInSource.add(username)
    const prev = nextCache[username]
    const avatarUrl = String(contact.avatarUrl || '').trim()
    if (!avatarUrl) continue
    const updatedAt = !prev || prev.avatarUrl !== avatarUrl ? now : prev.updatedAt
    const checkedAt = markCheckedSet.has(username) ? now : (prev?.checkedAt || now)
    if (!prev || prev.avatarUrl !== avatarUrl || prev.updatedAt !== updatedAt || prev.checkedAt !== checkedAt) {
      nextCache[username] = {
        avatarUrl,
        updatedAt,
        checkedAt
      }
      changed = true
    }
  }

  for (const username of markCheckedSet) {
    const prev = nextCache[username]
    if (!prev) continue
    if (prev.checkedAt !== now) {
      nextCache[username] = {
        ...prev,
        checkedAt: now
      }
      changed = true
    }
  }

  if (options?.prune) {
    for (const username of Object.keys(nextCache)) {
      if (usernamesInSource.has(username)) continue
      delete nextCache[username]
      changed = true
    }
  }

  return {
    avatarEntries: nextCache,
    changed,
    updatedAt: changed ? now : null
  }
}

const toSessionRowsWithContacts = (
  sessions: AppChatSession[],
  contactMap: Record<string, ContactInfo>
): SessionRow[] => {
  const sessionMap = new Map<string, AppChatSession>()
  for (const session of sessions || []) {
    sessionMap.set(session.username, session)
  }

  const contacts = Object.values(contactMap)
    .filter((contact) => (
      contact.type === 'friend' ||
      contact.type === 'group' ||
      contact.type === 'official' ||
      contact.type === 'former_friend'
    ))

  if (contacts.length > 0) {
    return contacts
      .map((contact) => {
        const session = sessionMap.get(contact.username)
        const latestTs = session?.sortTimestamp || session?.lastTimestamp || 0
        return {
          ...(session || {
            username: contact.username,
            type: 0,
            unreadCount: 0,
            summary: '',
            sortTimestamp: latestTs,
            lastTimestamp: latestTs,
            lastMsgType: 0
          }),
          username: contact.username,
          kind: toKindByContact(contact),
          wechatId: contact.username,
          displayName: contact.displayName || session?.displayName || contact.username,
          avatarUrl: contact.avatarUrl || session?.avatarUrl,
          hasSession: Boolean(session)
        } as SessionRow
      })
      .sort((a, b) => {
        const latestA = a.sortTimestamp || a.lastTimestamp || 0
        const latestB = b.sortTimestamp || b.lastTimestamp || 0
        if (latestA !== latestB) return latestB - latestA
        return (a.displayName || a.username).localeCompare(b.displayName || b.username, 'zh-Hans-CN')
      })
  }

  return sessions
    .map((session) => {
      const contact = contactMap[session.username]
      return {
        ...session,
        kind: toKindByContactType(session, contact),
        wechatId: contact?.username || session.username,
        displayName: contact?.displayName || session.displayName || session.username,
        avatarUrl: contact?.avatarUrl || session.avatarUrl,
        hasSession: true
      } as SessionRow
    })
    .sort((a, b) => (b.sortTimestamp || b.lastTimestamp || 0) - (a.sortTimestamp || a.lastTimestamp || 0))
}

const normalizeMessageCount = (value: unknown): number | undefined => {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed < 0) return undefined
  return Math.floor(parsed)
}

const WriteLayoutSelector = memo(function WriteLayoutSelector({
  writeLayout,
  onChange,
  sessionNameWithTypePrefix,
  onSessionNameWithTypePrefixChange
}: {
  writeLayout: configService.ExportWriteLayout
  onChange: (value: configService.ExportWriteLayout) => Promise<void>
  sessionNameWithTypePrefix: boolean
  onSessionNameWithTypePrefixChange: (enabled: boolean) => Promise<void>
}) {
  const [isOpen, setIsOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!isOpen) return

    const handleOutsideClick = (event: MouseEvent) => {
      if (containerRef.current?.contains(event.target as Node)) return
      setIsOpen(false)
    }

    document.addEventListener('mousedown', handleOutsideClick)
    return () => document.removeEventListener('mousedown', handleOutsideClick)
  }, [isOpen])

  const writeLayoutLabel = writeLayoutOptions.find(option => option.value === writeLayout)?.label || 'A（类型分目录）'

  return (
    <div className="write-layout-control" ref={containerRef}>
      <span className="control-label">写入目录方式</span>
      <button
        className={`layout-trigger ${isOpen ? 'active' : ''}`}
        type="button"
        onClick={() => setIsOpen(prev => !prev)}
      >
        {writeLayoutLabel}
      </button>
      <div className={`layout-dropdown ${isOpen ? 'open' : ''}`}>
        {writeLayoutOptions.map(option => (
          <button
            key={option.value}
            className={`layout-option ${writeLayout === option.value ? 'active' : ''}`}
            type="button"
            onClick={async () => {
              await onChange(option.value)
              setIsOpen(false)
            }}
          >
            <span className="layout-option-label">{option.label}</span>
            <span className="layout-option-desc">{option.desc}</span>
          </button>
        ))}
        <div className="layout-prefix-toggle">
          <div className="layout-prefix-copy">
            <span className="layout-prefix-label">聊天文本文件和会话文件夹带前缀</span>
            <span className="layout-prefix-desc">开启后使用群聊_、私聊_、公众号_、曾经的好友_前缀</span>
          </div>
          <button
            type="button"
            className={`layout-prefix-switch ${sessionNameWithTypePrefix ? 'on' : ''}`}
            onClick={async () => {
              await onSessionNameWithTypePrefixChange(!sessionNameWithTypePrefix)
            }}
            aria-label="聊天文本文件和会话文件夹带前缀"
            aria-pressed={sessionNameWithTypePrefix}
          >
            <span className="layout-prefix-switch-thumb" />
          </button>
        </div>
      </div>
    </div>
  )
})

const SectionInfoTooltip = memo(function SectionInfoTooltip({
  label,
  heading,
  messages
}: {
  label: string
  heading: string
  messages: string[]
}) {
  const [isOpen, setIsOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!isOpen) return

    const handleOutsideClick = (event: MouseEvent) => {
      if (containerRef.current?.contains(event.target as Node)) return
      setIsOpen(false)
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleOutsideClick)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen])

  return (
    <div className="section-info-tooltip" ref={containerRef}>
      <button
        type="button"
        className={`section-info-trigger ${isOpen ? 'active' : ''}`}
        onClick={() => setIsOpen(prev => !prev)}
        aria-label={`查看${label}说明`}
        aria-expanded={isOpen}
      >
        <CircleHelp size={14} />
      </button>
      {isOpen && (
        <div className="section-info-popover" role="dialog" aria-label={`${label}说明`}>
          <h4>{heading}</h4>
          {messages.map(message => (
            <p key={message}>{message}</p>
          ))}
        </div>
      )}
    </div>
  )
})

interface TaskCenterModalProps {
  isOpen: boolean
  tasks: ExportTask[]
  taskRunningCount: number
  taskQueuedCount: number
  expandedPerfTaskId: string | null
  nowTick: number
  onClose: () => void
  onTogglePerfTask: (taskId: string) => void
}

const TaskCenterModal = memo(function TaskCenterModal({
  isOpen,
  tasks,
  taskRunningCount,
  taskQueuedCount,
  expandedPerfTaskId,
  nowTick,
  onClose,
  onTogglePerfTask
}: TaskCenterModalProps) {
  if (!isOpen) return null

  return (
    <div
      className="task-center-modal-overlay"
      onClick={onClose}
    >
      <div
        className="task-center-modal"
        role="dialog"
        aria-modal="true"
        aria-label="任务中心"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="task-center-modal-header">
          <div className="task-center-modal-title">
            <h3>任务中心</h3>
            <span>进行中 {taskRunningCount} · 排队 {taskQueuedCount} · 总计 {tasks.length}</span>
          </div>
          <button
            className="close-icon-btn"
            type="button"
            onClick={onClose}
            aria-label="关闭任务中心"
          >
            <X size={16} />
          </button>
        </div>
        <div className="task-center-modal-body">
          {tasks.length === 0 ? (
            <div className="task-empty">暂无任务。点击会话导出或卡片导出后会在这里创建任务。</div>
          ) : (
            <div className="task-list">
              {tasks.map(task => {
                const canShowPerfDetail = isTextBatchTask(task) && Boolean(task.performance)
                const isPerfExpanded = expandedPerfTaskId === task.id
                const stageTotals = canShowPerfDetail
                  ? getTaskPerformanceStageTotals(task.performance, nowTick)
                  : null
                const stageTotalMs = stageTotals
                  ? stageTotals.collect + stageTotals.build + stageTotals.write + stageTotals.other
                  : 0
                const topSessions = isPerfExpanded
                  ? getTaskPerformanceTopSessions(task.performance, nowTick, 5)
                  : []
                const normalizedProgressTotal = task.progress.total > 0 ? task.progress.total : 0
                const normalizedProgressCurrent = normalizedProgressTotal > 0
                  ? Math.max(0, Math.min(normalizedProgressTotal, task.progress.current))
                  : 0
                const completedSessionTotal = normalizedProgressTotal > 0
                  ? normalizedProgressTotal
                  : task.payload.sessionIds.length
                const completedSessionCount = Math.min(
                  completedSessionTotal,
                  (task.settledSessionIds || []).length
                )
                const currentSessionRatio = task.progress.phaseTotal > 0
                  ? Math.max(0, Math.min(1, task.progress.phaseProgress / task.progress.phaseTotal))
                  : null
                return (
                  <div key={task.id} className={`task-card ${task.status}`}>
                    <div className="task-main">
                      <div className="task-title">{task.title}</div>
                      <div className="task-meta">
                        <span className={`task-status ${task.status}`}>{getTaskStatusLabel(task)}</span>
                        <span>{new Date(task.createdAt).toLocaleString('zh-CN')}</span>
                      </div>
                      {task.status === 'running' && (
                        <>
                          <div className="task-progress-bar">
                            <div
                              className="task-progress-fill"
                              style={{ width: `${normalizedProgressTotal > 0 ? (normalizedProgressCurrent / normalizedProgressTotal) * 100 : 0}%` }}
                            />
                          </div>
                          <div className="task-progress-text">
                            {completedSessionTotal > 0
                              ? `已完成 ${completedSessionCount} / ${completedSessionTotal}`
                              : '处理中'}
                            {task.status === 'running' && currentSessionRatio !== null
                              ? `（当前会话 ${Math.round(currentSessionRatio * 100)}%）`
                              : ''}
                            {task.progress.phaseLabel ? ` · ${task.progress.phaseLabel}` : ''}
                          </div>
                        </>
                      )}
                      {canShowPerfDetail && stageTotals && (
                        <div className="task-perf-summary">
                          <span>累计耗时 {formatDurationMs(stageTotalMs)}</span>
                          {task.progress.total > 0 && (
                            <span>平均/会话 {formatDurationMs(Math.floor(stageTotalMs / Math.max(1, task.progress.total)))}</span>
                          )}
                        </div>
                      )}
                      {canShowPerfDetail && isPerfExpanded && stageTotals && (
                        <div className="task-perf-panel">
                          <div className="task-perf-title">阶段耗时分布</div>
                          {[
                            { key: 'collect' as const, label: '收集消息' },
                            { key: 'build' as const, label: '构建消息' },
                            { key: 'write' as const, label: '写入文件' },
                            { key: 'other' as const, label: '其他' }
                          ].map(item => {
                            const value = stageTotals[item.key]
                            const ratio = stageTotalMs > 0 ? Math.min(100, (value / stageTotalMs) * 100) : 0
                            return (
                              <div className="task-perf-row" key={item.key}>
                                <div className="task-perf-row-head">
                                  <span>{item.label}</span>
                                  <span>{formatDurationMs(value)}</span>
                                </div>
                                <div className="task-perf-row-track">
                                  <div className="task-perf-row-fill" style={{ width: `${ratio}%` }} />
                                </div>
                              </div>
                            )
                          })}
                          <div className="task-perf-title">最慢会话 Top5</div>
                          {topSessions.length === 0 ? (
                            <div className="task-perf-empty">暂无会话耗时数据</div>
                          ) : (
                            <div className="task-perf-session-list">
                              {topSessions.map((session, index) => (
                                <div className="task-perf-session-item" key={session.sessionId}>
                                  <span className="task-perf-session-rank">
                                    {index + 1}. {session.sessionName || session.sessionId}
                                    {!session.finishedAt ? '（进行中）' : ''}
                                  </span>
                                  <span className="task-perf-session-time">{formatDurationMs(session.liveElapsedMs)}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                      {task.status === 'error' && <div className="task-error">{task.error || '任务失败'}</div>}
                    </div>
                    <div className="task-actions">
                      {canShowPerfDetail && (
                        <button
                          className={`task-action-btn ${isPerfExpanded ? 'primary' : ''}`}
                          type="button"
                          onClick={() => onTogglePerfTask(task.id)}
                        >
                          {isPerfExpanded ? '收起详情' : '性能详情'}
                        </button>
                      )}
                      <button className="task-action-btn" onClick={() => task.payload.outputDir && void window.electronAPI.shell.openPath(task.payload.outputDir)}>
                        <FolderOpen size={14} /> 目录
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
})

function ExportPage() {
  const location = useLocation()
  const isExportRoute = location.pathname === '/export'

  const [isLoading, setIsLoading] = useState(true)
  const [isSessionEnriching, setIsSessionEnriching] = useState(false)
  const [isSnsStatsLoading, setIsSnsStatsLoading] = useState(true)
  const [isBaseConfigLoading, setIsBaseConfigLoading] = useState(true)
  const [isTaskCenterOpen, setIsTaskCenterOpen] = useState(false)
  const [expandedPerfTaskId, setExpandedPerfTaskId] = useState<string | null>(null)
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [sessionDataSource, setSessionDataSource] = useState<SessionDataSource>(null)
  const [sessionContactsUpdatedAt, setSessionContactsUpdatedAt] = useState<number | null>(null)
  const [sessionAvatarUpdatedAt, setSessionAvatarUpdatedAt] = useState<number | null>(null)
  const [searchKeyword, setSearchKeyword] = useState('')
  const [activeTab, setActiveTab] = useState<ConversationTab>('private')
  const [selectedSessions, setSelectedSessions] = useState<Set<string>>(new Set())
  const [contactsList, setContactsList] = useState<ContactInfo[]>([])
  const [isContactsListLoading, setIsContactsListLoading] = useState(true)
  const [, setContactsDataSource] = useState<ContactsDataSource>(null)
  const [contactsUpdatedAt, setContactsUpdatedAt] = useState<number | null>(null)
  const [avatarCacheUpdatedAt, setAvatarCacheUpdatedAt] = useState<number | null>(null)
  const [sessionMessageCounts, setSessionMessageCounts] = useState<Record<string, number>>({})
  const [isLoadingSessionCounts, setIsLoadingSessionCounts] = useState(false)
  const [sessionContentMetrics, setSessionContentMetrics] = useState<Record<string, SessionContentMetric>>({})
  const [contactsLoadTimeoutMs, setContactsLoadTimeoutMs] = useState(DEFAULT_CONTACTS_LOAD_TIMEOUT_MS)
  const [contactsLoadSession, setContactsLoadSession] = useState<ContactsLoadSession | null>(null)
  const [contactsLoadIssue, setContactsLoadIssue] = useState<ContactsLoadIssue | null>(null)
  const [showContactsDiagnostics, setShowContactsDiagnostics] = useState(false)
  const [contactsDiagnosticTick, setContactsDiagnosticTick] = useState(Date.now())
  const [showSessionDetailPanel, setShowSessionDetailPanel] = useState(false)
  const [sessionDetail, setSessionDetail] = useState<SessionDetail | null>(null)
  const [isLoadingSessionDetail, setIsLoadingSessionDetail] = useState(false)
  const [isLoadingSessionDetailExtra, setIsLoadingSessionDetailExtra] = useState(false)
  const [isRefreshingSessionDetailStats, setIsRefreshingSessionDetailStats] = useState(false)
  const [isLoadingSessionRelationStats, setIsLoadingSessionRelationStats] = useState(false)
  const [copiedDetailField, setCopiedDetailField] = useState<string | null>(null)

  const [exportFolder, setExportFolder] = useState('')
  const [writeLayout, setWriteLayout] = useState<configService.ExportWriteLayout>('B')
  const [sessionNameWithTypePrefix, setSessionNameWithTypePrefix] = useState(true)
  const [snsExportFormat, setSnsExportFormat] = useState<SnsTimelineExportFormat>('html')
  const [snsExportImages, setSnsExportImages] = useState(false)
  const [snsExportLivePhotos, setSnsExportLivePhotos] = useState(false)
  const [snsExportVideos, setSnsExportVideos] = useState(false)
  const [isTimeRangeDialogOpen, setIsTimeRangeDialogOpen] = useState(false)
  const [timeRangePreset, setTimeRangePreset] = useState<DateRangePreset>('all')
  const [timeRangeDialogDraft, setTimeRangeDialogDraft] = useState<TimeRangeDialogDraft | null>(null)
  const [timeRangeDateInput, setTimeRangeDateInput] = useState<{ start: string; end: string }>({ start: '', end: '' })
  const [timeRangeDateInputError, setTimeRangeDateInputError] = useState<{ start: boolean; end: boolean }>({ start: false, end: false })

  const [options, setOptions] = useState<ExportOptions>({
    format: 'json',
    dateRange: {
      start: new Date(new Date().setHours(0, 0, 0, 0)),
      end: new Date()
    },
    useAllTime: false,
    exportAvatars: true,
    exportMedia: false,
    exportImages: true,
    exportVoices: true,
    exportVideos: true,
    exportEmojis: true,
    exportVoiceAsText: false,
    excelCompactColumns: true,
    txtColumns: defaultTxtColumns,
    displayNamePreference: 'remark',
    exportConcurrency: 2
  })

  const [exportDialog, setExportDialog] = useState<ExportDialogState>({
    open: false,
    scope: 'single',
    sessionIds: [],
    sessionNames: [],
    title: ''
  })

  const [tasks, setTasks] = useState<ExportTask[]>([])
  const [lastExportBySession, setLastExportBySession] = useState<Record<string, number>>({})
  const [lastExportByContent, setLastExportByContent] = useState<Record<string, number>>({})
  const [exportRecordsBySession, setExportRecordsBySession] = useState<Record<string, configService.ExportSessionRecordEntry[]>>({})
  const [lastSnsExportPostCount, setLastSnsExportPostCount] = useState(0)
  const [snsStats, setSnsStats] = useState<{ totalPosts: number; totalFriends: number }>({
    totalPosts: 0,
    totalFriends: 0
  })
  const [hasSeededSnsStats, setHasSeededSnsStats] = useState(false)
  const [nowTick, setNowTick] = useState(Date.now())
  const [isContactsListAtTop, setIsContactsListAtTop] = useState(true)
  const [isPageScrolled, setIsPageScrolled] = useState(false)
  const tabCounts = useContactTypeCountsStore(state => state.tabCounts)
  const isSharedTabCountsLoading = useContactTypeCountsStore(state => state.isLoading)
  const isSharedTabCountsReady = useContactTypeCountsStore(state => state.isReady)
  const ensureSharedTabCountsLoaded = useContactTypeCountsStore(state => state.ensureLoaded)
  const syncContactTypeCounts = useContactTypeCountsStore(state => state.syncFromContacts)

  const progressUnsubscribeRef = useRef<(() => void) | null>(null)
  const runningTaskIdRef = useRef<string | null>(null)
  const tasksRef = useRef<ExportTask[]>([])
  const hasSeededSnsStatsRef = useRef(false)
  const sessionLoadTokenRef = useRef(0)
  const preselectAppliedRef = useRef(false)
  const exportCacheScopeRef = useRef('default')
  const exportCacheScopeReadyRef = useRef(false)
  const contactsLoadVersionRef = useRef(0)
  const contactsLoadAttemptRef = useRef(0)
  const contactsLoadTimeoutTimerRef = useRef<number | null>(null)
  const contactsLoadTimeoutMsRef = useRef(DEFAULT_CONTACTS_LOAD_TIMEOUT_MS)
  const contactsAvatarCacheRef = useRef<Record<string, configService.ContactsAvatarCacheEntry>>({})
  const contactsVirtuosoRef = useRef<VirtuosoHandle | null>(null)
  const sessionTableSectionRef = useRef<HTMLDivElement | null>(null)
  const detailRequestSeqRef = useRef(0)
  const sessionsRef = useRef<SessionRow[]>([])
  const contactsListSizeRef = useRef(0)
  const contactsUpdatedAtRef = useRef<number | null>(null)
  const sessionsHydratedAtRef = useRef(0)
  const snsStatsHydratedAtRef = useRef(0)
  const inProgressSessionIdsRef = useRef<string[]>([])
  const activeTaskCountRef = useRef(0)
  const hasBaseConfigReadyRef = useRef(false)
  const sessionCountRequestIdRef = useRef(0)
  const activeTabRef = useRef<ConversationTab>('private')

  const ensureExportCacheScope = useCallback(async (): Promise<string> => {
    if (exportCacheScopeReadyRef.current) {
      return exportCacheScopeRef.current
    }
    const [myWxid, dbPath] = await Promise.all([
      configService.getMyWxid(),
      configService.getDbPath()
    ])
    const scopeKey = dbPath || myWxid
      ? `${dbPath || ''}::${myWxid || ''}`
      : 'default'
    exportCacheScopeRef.current = scopeKey
    exportCacheScopeReadyRef.current = true
    return scopeKey
  }, [])

  const loadContactsCaches = useCallback(async (scopeKey: string) => {
    const [contactsItem, avatarItem] = await Promise.all([
      configService.getContactsListCache(scopeKey),
      configService.getContactsAvatarCache(scopeKey)
    ])
    return {
      contactsItem,
      avatarItem
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const value = await configService.getContactsLoadTimeoutMs()
        if (!cancelled) {
          setContactsLoadTimeoutMs(value)
        }
      } catch (error) {
        console.error('读取通讯录超时配置失败:', error)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    contactsLoadTimeoutMsRef.current = contactsLoadTimeoutMs
  }, [contactsLoadTimeoutMs])

  const loadContactsList = useCallback(async (options?: { scopeKey?: string }) => {
    const scopeKey = options?.scopeKey || await ensureExportCacheScope()
    const loadVersion = contactsLoadVersionRef.current + 1
    contactsLoadVersionRef.current = loadVersion
    contactsLoadAttemptRef.current += 1
    const startedAt = Date.now()
    const timeoutMs = contactsLoadTimeoutMsRef.current
    const requestId = `export-contacts-${startedAt}-${contactsLoadAttemptRef.current}`
    setContactsLoadSession({
      requestId,
      startedAt,
      attempt: contactsLoadAttemptRef.current,
      timeoutMs
    })
    setContactsLoadIssue(null)
    setShowContactsDiagnostics(false)
    if (contactsLoadTimeoutTimerRef.current) {
      window.clearTimeout(contactsLoadTimeoutTimerRef.current)
      contactsLoadTimeoutTimerRef.current = null
    }
    const timeoutTimerId = window.setTimeout(() => {
      if (contactsLoadVersionRef.current !== loadVersion) return
      const elapsedMs = Date.now() - startedAt
      setContactsLoadIssue({
        kind: 'timeout',
        title: '联系人列表加载超时',
        message: `等待超过 ${timeoutMs}ms，联系人列表仍未返回。`,
        reason: 'chat.getContacts 长时间未返回，可能是数据库查询繁忙或连接异常。',
        occurredAt: Date.now(),
        elapsedMs
      })
    }, timeoutMs)
    contactsLoadTimeoutTimerRef.current = timeoutTimerId

    setIsContactsListLoading(true)
    try {
      const contactsResult = await window.electronAPI.chat.getContacts()
      if (contactsLoadVersionRef.current !== loadVersion) return

      if (contactsResult.success && contactsResult.contacts) {
        if (contactsLoadTimeoutTimerRef.current === timeoutTimerId) {
          window.clearTimeout(contactsLoadTimeoutTimerRef.current)
          contactsLoadTimeoutTimerRef.current = null
        }
        const contactsWithAvatarCache = mergeAvatarCacheIntoContacts(
          contactsResult.contacts,
          contactsAvatarCacheRef.current
        )
        setContactsList(contactsWithAvatarCache)
        syncContactTypeCounts(contactsWithAvatarCache)
        setContactsDataSource('network')
        setContactsUpdatedAt(Date.now())
        setContactsLoadIssue(null)
        setIsContactsListLoading(false)

        const upsertResult = upsertAvatarCacheFromContacts(
          contactsAvatarCacheRef.current,
          contactsWithAvatarCache,
          { prune: true }
        )
        contactsAvatarCacheRef.current = upsertResult.avatarEntries
        if (upsertResult.updatedAt) {
          setAvatarCacheUpdatedAt(upsertResult.updatedAt)
        }

        void configService.setContactsAvatarCache(scopeKey, contactsAvatarCacheRef.current).catch((error) => {
          console.error('写入导出页头像缓存失败:', error)
        })
        void configService.setContactsListCache(
          scopeKey,
          contactsWithAvatarCache.map(contact => ({
            username: contact.username,
            displayName: contact.displayName,
            remark: contact.remark,
            nickname: contact.nickname,
            type: contact.type
          }))
        ).catch((error) => {
          console.error('写入导出页通讯录缓存失败:', error)
        })
        return
      }

      const elapsedMs = Date.now() - startedAt
      setContactsLoadIssue({
        kind: 'error',
        title: '联系人列表加载失败',
        message: '联系人接口返回失败，未拿到联系人列表。',
        reason: 'chat.getContacts 返回 success=false。',
        errorDetail: contactsResult.error || '未知错误',
        occurredAt: Date.now(),
        elapsedMs
      })
    } catch (error) {
      console.error('加载导出页联系人失败:', error)
      const elapsedMs = Date.now() - startedAt
      setContactsLoadIssue({
        kind: 'error',
        title: '联系人列表加载失败',
        message: '联系人请求执行异常。',
        reason: '调用 chat.getContacts 发生异常。',
        errorDetail: String(error),
        occurredAt: Date.now(),
        elapsedMs
      })
    } finally {
      if (contactsLoadTimeoutTimerRef.current === timeoutTimerId) {
        window.clearTimeout(contactsLoadTimeoutTimerRef.current)
        contactsLoadTimeoutTimerRef.current = null
      }
      if (contactsLoadVersionRef.current === loadVersion) {
        setIsContactsListLoading(false)
      }
    }
  }, [ensureExportCacheScope, syncContactTypeCounts])

  useEffect(() => {
    if (!isExportRoute) return
    let cancelled = false
    void (async () => {
      const scopeKey = await ensureExportCacheScope()
      if (cancelled) return
      let cachedContactsCount = 0
      let cachedContactsUpdatedAt = 0
      try {
        const [cacheItem, avatarCacheItem] = await Promise.all([
          configService.getContactsListCache(scopeKey),
          configService.getContactsAvatarCache(scopeKey)
        ])
        cachedContactsCount = Array.isArray(cacheItem?.contacts) ? cacheItem.contacts.length : 0
        cachedContactsUpdatedAt = Number(cacheItem?.updatedAt || 0)
        const avatarCacheMap = avatarCacheItem?.avatars || {}
        contactsAvatarCacheRef.current = avatarCacheMap
        setAvatarCacheUpdatedAt(avatarCacheItem?.updatedAt || null)
        if (!cancelled && cacheItem && Array.isArray(cacheItem.contacts) && cacheItem.contacts.length > 0) {
          const cachedContacts: ContactInfo[] = cacheItem.contacts.map(contact => ({
            ...contact,
            avatarUrl: avatarCacheMap[contact.username]?.avatarUrl
          }))
          setContactsList(cachedContacts)
          syncContactTypeCounts(cachedContacts)
          setContactsDataSource('cache')
          setContactsUpdatedAt(cacheItem.updatedAt || null)
          setIsContactsListLoading(false)
        }
      } catch (error) {
        console.error('读取导出页联系人缓存失败:', error)
      }

      const latestContactsUpdatedAt = Math.max(
        Number(contactsUpdatedAtRef.current || 0),
        cachedContactsUpdatedAt
      )
      const hasFreshContactSnapshot = (contactsListSizeRef.current > 0 || cachedContactsCount > 0) &&
        latestContactsUpdatedAt > 0 &&
        Date.now() - latestContactsUpdatedAt <= EXPORT_REENTER_CONTACTS_SOFT_REFRESH_MS

      if (!cancelled && !hasFreshContactSnapshot) {
        void loadContactsList({ scopeKey })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [isExportRoute, ensureExportCacheScope, loadContactsList, syncContactTypeCounts])

  useEffect(() => {
    if (isExportRoute) return
    contactsLoadVersionRef.current += 1
  }, [isExportRoute])

  useEffect(() => {
    if (contactsLoadTimeoutTimerRef.current) {
      window.clearTimeout(contactsLoadTimeoutTimerRef.current)
      contactsLoadTimeoutTimerRef.current = null
    }
    return () => {
      if (contactsLoadTimeoutTimerRef.current) {
        window.clearTimeout(contactsLoadTimeoutTimerRef.current)
        contactsLoadTimeoutTimerRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    if (!contactsLoadIssue || contactsList.length > 0) return
    if (!(isContactsListLoading && contactsLoadIssue.kind === 'timeout')) return
    const timer = window.setInterval(() => {
      setContactsDiagnosticTick(Date.now())
    }, 500)
    return () => window.clearInterval(timer)
  }, [contactsList.length, isContactsListLoading, contactsLoadIssue])

  useEffect(() => {
    tasksRef.current = tasks
  }, [tasks])

  useEffect(() => {
    sessionsRef.current = sessions
  }, [sessions])

  useEffect(() => {
    contactsListSizeRef.current = contactsList.length
  }, [contactsList.length])

  useEffect(() => {
    contactsUpdatedAtRef.current = contactsUpdatedAt
  }, [contactsUpdatedAt])

  useEffect(() => {
    if (!expandedPerfTaskId) return
    const target = tasks.find(task => task.id === expandedPerfTaskId)
    if (!target || !isTextBatchTask(target)) {
      setExpandedPerfTaskId(null)
    }
  }, [tasks, expandedPerfTaskId])

  useEffect(() => {
    hasSeededSnsStatsRef.current = hasSeededSnsStats
  }, [hasSeededSnsStats])

  const preselectSessionIds = useMemo(() => {
    const state = location.state as { preselectSessionIds?: unknown; preselectSessionId?: unknown } | null
    const rawList = Array.isArray(state?.preselectSessionIds)
      ? state?.preselectSessionIds
      : (typeof state?.preselectSessionId === 'string' ? [state.preselectSessionId] : [])

    return rawList
      .filter((item): item is string => typeof item === 'string')
      .map(item => item.trim())
      .filter(Boolean)
  }, [location.state])

  useEffect(() => {
    if (!isExportRoute) return
    const timer = setInterval(() => setNowTick(Date.now()), 60 * 1000)
    return () => clearInterval(timer)
  }, [isExportRoute])

  useEffect(() => {
    if (!isExportRoute) {
      setIsPageScrolled(false)
      return
    }
    const onWindowScroll = () => {
      setIsPageScrolled(window.scrollY > 160)
    }
    onWindowScroll()
    window.addEventListener('scroll', onWindowScroll, { passive: true })
    return () => window.removeEventListener('scroll', onWindowScroll)
  }, [isExportRoute])

  useEffect(() => {
    if (!isTaskCenterOpen || !expandedPerfTaskId) return
    const target = tasks.find(task => task.id === expandedPerfTaskId)
    if (!target || target.status !== 'running' || !isTextBatchTask(target)) return
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [isTaskCenterOpen, expandedPerfTaskId, tasks])

  const loadBaseConfig = useCallback(async (): Promise<boolean> => {
    setIsBaseConfigLoading(true)
    let isReady = true
    try {
      const [savedPath, savedMedia, savedVoiceAsText, savedExcelCompactColumns, savedTxtColumns, savedConcurrency, savedSessionMap, savedContentMap, savedSessionRecordMap, savedSnsPostCount, savedWriteLayout, savedSessionNameWithTypePrefix, exportCacheScope] = await Promise.all([
        configService.getExportPath(),
        configService.getExportDefaultMedia(),
        configService.getExportDefaultVoiceAsText(),
        configService.getExportDefaultExcelCompactColumns(),
        configService.getExportDefaultTxtColumns(),
        configService.getExportDefaultConcurrency(),
        configService.getExportLastSessionRunMap(),
        configService.getExportLastContentRunMap(),
        configService.getExportSessionRecordMap(),
        configService.getExportLastSnsPostCount(),
        configService.getExportWriteLayout(),
        configService.getExportSessionNamePrefixEnabled(),
        ensureExportCacheScope()
      ])

      const cachedSnsStats = await configService.getExportSnsStatsCache(exportCacheScope)

      if (savedPath) {
        setExportFolder(savedPath)
      } else {
        const downloadsPath = await window.electronAPI.app.getDownloadsPath()
        setExportFolder(downloadsPath)
      }

      setWriteLayout(savedWriteLayout)
      setSessionNameWithTypePrefix(savedSessionNameWithTypePrefix)
      setLastExportBySession(savedSessionMap)
      setLastExportByContent(savedContentMap)
      setExportRecordsBySession(savedSessionRecordMap)
      setLastSnsExportPostCount(savedSnsPostCount)
      await configService.setExportDefaultFormat('json')

      if (cachedSnsStats && Date.now() - cachedSnsStats.updatedAt <= EXPORT_SNS_STATS_CACHE_STALE_MS) {
        setSnsStats({
          totalPosts: cachedSnsStats.totalPosts || 0,
          totalFriends: cachedSnsStats.totalFriends || 0
        })
        snsStatsHydratedAtRef.current = Date.now()
        hasSeededSnsStatsRef.current = true
        setHasSeededSnsStats(true)
      }

      const txtColumns = savedTxtColumns && savedTxtColumns.length > 0 ? savedTxtColumns : defaultTxtColumns
      setOptions(prev => ({
        ...prev,
        format: 'json',
        exportMedia: savedMedia ?? prev.exportMedia,
        exportVoiceAsText: savedVoiceAsText ?? prev.exportVoiceAsText,
        excelCompactColumns: savedExcelCompactColumns ?? prev.excelCompactColumns,
        txtColumns,
        exportConcurrency: savedConcurrency ?? prev.exportConcurrency
      }))
    } catch (error) {
      isReady = false
      console.error('加载导出配置失败:', error)
    } finally {
      setIsBaseConfigLoading(false)
    }
    if (isReady) {
      hasBaseConfigReadyRef.current = true
    }
    return isReady
  }, [ensureExportCacheScope])

  const loadSnsStats = useCallback(async (options?: { full?: boolean; silent?: boolean }) => {
    if (!options?.silent) {
      setIsSnsStatsLoading(true)
    }

    const applyStats = async (next: { totalPosts: number; totalFriends: number } | null) => {
      if (!next) return
      const normalized = {
        totalPosts: Number.isFinite(next.totalPosts) ? Math.max(0, Math.floor(next.totalPosts)) : 0,
        totalFriends: Number.isFinite(next.totalFriends) ? Math.max(0, Math.floor(next.totalFriends)) : 0
      }
      setSnsStats(normalized)
      snsStatsHydratedAtRef.current = Date.now()
      hasSeededSnsStatsRef.current = true
      setHasSeededSnsStats(true)
      if (exportCacheScopeReadyRef.current) {
        await configService.setExportSnsStatsCache(exportCacheScopeRef.current, normalized)
      }
    }

    try {
      const fastResult = await withTimeout(window.electronAPI.sns.getExportStatsFast(), 2200)
      if (fastResult?.success && fastResult.data) {
        const fastStats = {
          totalPosts: fastResult.data.totalPosts || 0,
          totalFriends: fastResult.data.totalFriends || 0
        }
        if (fastStats.totalPosts > 0 || hasSeededSnsStatsRef.current) {
          await applyStats(fastStats)
        }
      }

      if (options?.full) {
        const result = await withTimeout(window.electronAPI.sns.getExportStats(), 9000)
        if (result?.success && result.data) {
          await applyStats({
            totalPosts: result.data.totalPosts || 0,
            totalFriends: result.data.totalFriends || 0
          })
        }
      }
    } catch (error) {
      console.error('加载朋友圈导出统计失败:', error)
    } finally {
      if (!options?.silent) {
        setIsSnsStatsLoading(false)
      }
    }
  }, [])

  const mergeSessionContentMetrics = useCallback((input: Record<string, SessionExportMetric | SessionContentMetric | undefined>) => {
    const entries = Object.entries(input)
    if (entries.length === 0) return

    const nextMessageCounts: Record<string, number> = {}
    const nextMetrics: Record<string, SessionContentMetric> = {}

    for (const [sessionIdRaw, metricRaw] of entries) {
      const sessionId = String(sessionIdRaw || '').trim()
      if (!sessionId || !metricRaw) continue
      const totalMessages = normalizeMessageCount(metricRaw.totalMessages)
      const voiceMessages = normalizeMessageCount(metricRaw.voiceMessages)
      const imageMessages = normalizeMessageCount(metricRaw.imageMessages)
      const videoMessages = normalizeMessageCount(metricRaw.videoMessages)
      const emojiMessages = normalizeMessageCount(metricRaw.emojiMessages)
      const transferMessages = normalizeMessageCount(metricRaw.transferMessages)
      const redPacketMessages = normalizeMessageCount(metricRaw.redPacketMessages)
      const callMessages = normalizeMessageCount(metricRaw.callMessages)

      if (
        typeof totalMessages !== 'number' &&
        typeof voiceMessages !== 'number' &&
        typeof imageMessages !== 'number' &&
        typeof videoMessages !== 'number' &&
        typeof emojiMessages !== 'number' &&
        typeof transferMessages !== 'number' &&
        typeof redPacketMessages !== 'number' &&
        typeof callMessages !== 'number'
      ) {
        continue
      }

      nextMetrics[sessionId] = {
        totalMessages,
        voiceMessages,
        imageMessages,
        videoMessages,
        emojiMessages,
        transferMessages,
        redPacketMessages,
        callMessages
      }
      if (typeof totalMessages === 'number') {
        nextMessageCounts[sessionId] = totalMessages
      }
    }

    if (Object.keys(nextMessageCounts).length > 0) {
      setSessionMessageCounts(prev => {
        let changed = false
        const merged = { ...prev }
        for (const [sessionId, count] of Object.entries(nextMessageCounts)) {
          if (merged[sessionId] === count) continue
          merged[sessionId] = count
          changed = true
        }
        return changed ? merged : prev
      })
    }

    if (Object.keys(nextMetrics).length > 0) {
      setSessionContentMetrics(prev => {
        let changed = false
        const merged = { ...prev }
        for (const [sessionId, metric] of Object.entries(nextMetrics)) {
          const previous = merged[sessionId] || {}
          const nextMetric: SessionContentMetric = {
            totalMessages: typeof metric.totalMessages === 'number' ? metric.totalMessages : previous.totalMessages,
            voiceMessages: typeof metric.voiceMessages === 'number' ? metric.voiceMessages : previous.voiceMessages,
            imageMessages: typeof metric.imageMessages === 'number' ? metric.imageMessages : previous.imageMessages,
            videoMessages: typeof metric.videoMessages === 'number' ? metric.videoMessages : previous.videoMessages,
            emojiMessages: typeof metric.emojiMessages === 'number' ? metric.emojiMessages : previous.emojiMessages,
            transferMessages: typeof metric.transferMessages === 'number' ? metric.transferMessages : previous.transferMessages,
            redPacketMessages: typeof metric.redPacketMessages === 'number' ? metric.redPacketMessages : previous.redPacketMessages,
            callMessages: typeof metric.callMessages === 'number' ? metric.callMessages : previous.callMessages
          }
          if (
            previous.totalMessages === nextMetric.totalMessages &&
            previous.voiceMessages === nextMetric.voiceMessages &&
            previous.imageMessages === nextMetric.imageMessages &&
            previous.videoMessages === nextMetric.videoMessages &&
            previous.emojiMessages === nextMetric.emojiMessages &&
            previous.transferMessages === nextMetric.transferMessages &&
            previous.redPacketMessages === nextMetric.redPacketMessages &&
            previous.callMessages === nextMetric.callMessages
          ) {
            continue
          }
          merged[sessionId] = nextMetric
          changed = true
        }
        return changed ? merged : prev
      })
    }
  }, [])

  const loadSessionMessageCounts = useCallback(async (
    sourceSessions: SessionRow[],
    priorityTab: ConversationTab,
    options?: {
      scopeKey?: string
      seededCounts?: Record<string, number>
    }
  ): Promise<Record<string, number>> => {
    const requestId = sessionCountRequestIdRef.current + 1
    sessionCountRequestIdRef.current = requestId
    const isStale = () => sessionCountRequestIdRef.current !== requestId

    const exportableSessions = sourceSessions.filter(session => session.hasSession)
    const seededHintCounts = exportableSessions.reduce<Record<string, number>>((acc, session) => {
      const nextCount = normalizeMessageCount(session.messageCountHint)
      if (typeof nextCount === 'number') {
        acc[session.username] = nextCount
      }
      return acc
    }, {})
    const seededPersistentCounts = Object.entries(options?.seededCounts || {}).reduce<Record<string, number>>((acc, [sessionId, countRaw]) => {
      const nextCount = normalizeMessageCount(countRaw)
      if (typeof nextCount === 'number') {
        acc[sessionId] = nextCount
      }
      return acc
    }, {})
    const seededCounts = { ...seededHintCounts, ...seededPersistentCounts }
    const accumulatedCounts: Record<string, number> = { ...seededCounts }
    setSessionMessageCounts(seededCounts)
    if (Object.keys(seededCounts).length > 0) {
      mergeSessionContentMetrics(
        Object.entries(seededCounts).reduce<Record<string, SessionContentMetric>>((acc, [sessionId, count]) => {
          acc[sessionId] = { totalMessages: count }
          return acc
        }, {})
      )
    }

    if (exportableSessions.length === 0) {
      setIsLoadingSessionCounts(false)
      return { ...accumulatedCounts }
    }

    const prioritizedSessionIds = exportableSessions
      .filter(session => session.kind === priorityTab)
      .map(session => session.username)
    const prioritizedSet = new Set(prioritizedSessionIds)
    const remainingSessionIds = exportableSessions
      .filter(session => !prioritizedSet.has(session.username))
      .map(session => session.username)

    const applyCounts = (input: Record<string, number> | undefined) => {
      if (!input || isStale()) return
      const normalized = Object.entries(input).reduce<Record<string, number>>((acc, [sessionId, count]) => {
        const nextCount = normalizeMessageCount(count)
        if (typeof nextCount === 'number') {
          acc[sessionId] = nextCount
        }
        return acc
      }, {})
      if (Object.keys(normalized).length === 0) return
      for (const [sessionId, count] of Object.entries(normalized)) {
        accumulatedCounts[sessionId] = count
      }
      setSessionMessageCounts(prev => ({ ...prev, ...normalized }))
      mergeSessionContentMetrics(
        Object.entries(normalized).reduce<Record<string, SessionContentMetric>>((acc, [sessionId, count]) => {
          acc[sessionId] = { totalMessages: count }
          return acc
        }, {})
      )
    }

    setIsLoadingSessionCounts(true)
    try {
      if (prioritizedSessionIds.length > 0) {
        const priorityResult = await window.electronAPI.chat.getSessionMessageCounts(prioritizedSessionIds)
        if (isStale()) return { ...accumulatedCounts }
        if (priorityResult.success) {
          applyCounts(priorityResult.counts)
        }
      }

      if (remainingSessionIds.length > 0) {
        const remainingResult = await window.electronAPI.chat.getSessionMessageCounts(remainingSessionIds)
        if (isStale()) return { ...accumulatedCounts }
        if (remainingResult.success) {
          applyCounts(remainingResult.counts)
        }
      }
    } catch (error) {
      console.error('导出页加载会话消息总数失败:', error)
    } finally {
      if (!isStale()) {
        setIsLoadingSessionCounts(false)
        if (options?.scopeKey && Object.keys(accumulatedCounts).length > 0) {
          try {
            await configService.setExportSessionMessageCountCache(options.scopeKey, accumulatedCounts)
          } catch (cacheError) {
            console.error('写入导出页会话总消息缓存失败:', cacheError)
          }
        }
      }
    }
    return { ...accumulatedCounts }
  }, [mergeSessionContentMetrics])

  const loadSessions = useCallback(async () => {
    const loadToken = Date.now()
    sessionLoadTokenRef.current = loadToken
    sessionsHydratedAtRef.current = 0
    setIsLoading(true)
    setIsSessionEnriching(false)
    sessionCountRequestIdRef.current += 1
    setSessionMessageCounts({})
    setSessionContentMetrics({})
    setIsLoadingSessionCounts(false)

    const isStale = () => sessionLoadTokenRef.current !== loadToken

    try {
      const scopeKey = await ensureExportCacheScope()
      if (isStale()) return

      const [
        cachedContactsPayload,
        cachedMessageCountsPayload
      ] = await Promise.all([
        loadContactsCaches(scopeKey),
        configService.getExportSessionMessageCountCache(scopeKey)
      ])
      if (isStale()) return

      const {
        contactsItem: cachedContactsItem,
        avatarItem: cachedAvatarItem
      } = cachedContactsPayload

      const cachedContacts = cachedContactsItem?.contacts || []
      const cachedAvatarEntries = cachedAvatarItem?.avatars || {}
      const cachedContactMap = toContactMapFromCaches(cachedContacts, cachedAvatarEntries)
      if (cachedContacts.length > 0) {
        syncContactTypeCounts(Object.values(cachedContactMap))
        setSessions(toSessionRowsWithContacts([], cachedContactMap))
        setSessionDataSource('cache')
        setIsLoading(false)
      }
      setSessionContactsUpdatedAt(cachedContactsItem?.updatedAt || null)
      setSessionAvatarUpdatedAt(cachedAvatarItem?.updatedAt || null)

      const connectResult = await window.electronAPI.chat.connect()
      if (!connectResult.success) {
        console.error('连接失败:', connectResult.error)
        if (!isStale()) setIsLoading(false)
        return
      }

      const sessionsResult = await window.electronAPI.chat.getSessions()
      if (isStale()) return

      if (sessionsResult.success && sessionsResult.sessions) {
        const rawSessions = sessionsResult.sessions
        const baseSessions = toSessionRowsWithContacts(rawSessions, cachedContactMap)
        const exportableSessionIds = baseSessions
          .filter((session) => session.hasSession)
          .map((session) => session.username)
        const exportableSessionIdSet = new Set(exportableSessionIds)

        const cachedMessageCounts = Object.entries(cachedMessageCountsPayload?.counts || {}).reduce<Record<string, number>>((acc, [sessionId, countRaw]) => {
          if (!exportableSessionIdSet.has(sessionId)) return acc
          const nextCount = normalizeMessageCount(countRaw)
          if (typeof nextCount === 'number') {
            acc[sessionId] = nextCount
          }
          return acc
        }, {})

        const cachedCountAsMetrics = Object.entries(cachedMessageCounts).reduce<Record<string, SessionContentMetric>>((acc, [sessionId, count]) => {
          acc[sessionId] = { totalMessages: count }
          return acc
        }, {})

        if (isStale()) return
        if (Object.keys(cachedMessageCounts).length > 0) {
          setSessionMessageCounts(cachedMessageCounts)
        }
        if (Object.keys(cachedCountAsMetrics).length > 0) {
          mergeSessionContentMetrics(cachedCountAsMetrics)
        }
        setSessions(baseSessions)
        sessionsHydratedAtRef.current = Date.now()
        void (async () => {
          await loadSessionMessageCounts(baseSessions, activeTabRef.current, {
            scopeKey,
            seededCounts: cachedMessageCounts
          })
          if (isStale()) return
        })()
        setSessionDataSource(cachedContacts.length > 0 ? 'cache' : 'network')
        if (cachedContacts.length === 0) {
          setSessionContactsUpdatedAt(Date.now())
        }
        setIsLoading(false)

        // 后台补齐联系人字段（昵称、头像、类型），不阻塞首屏会话列表渲染。
        setIsSessionEnriching(true)
        void (async () => {
          try {
            let contactMap = { ...cachedContactMap }
            let avatarEntries = { ...cachedAvatarEntries }
            let hasFreshNetworkData = false
            let hasNetworkContactsSnapshot = false

            if (isStale()) return
            const contactsResult = await withTimeout(window.electronAPI.chat.getContacts(), CONTACT_ENRICH_TIMEOUT_MS)
            if (isStale()) return

            const contactsFromNetwork: ContactInfo[] = contactsResult?.success && contactsResult.contacts ? contactsResult.contacts : []
            if (contactsFromNetwork.length > 0) {
              hasFreshNetworkData = true
              hasNetworkContactsSnapshot = true
              const contactsWithCachedAvatar = mergeAvatarCacheIntoContacts(contactsFromNetwork, avatarEntries)
              const nextContactMap = contactsWithCachedAvatar.reduce<Record<string, ContactInfo>>((map, contact) => {
                map[contact.username] = contact
                return map
              }, {})
              for (const [username, cachedContact] of Object.entries(cachedContactMap)) {
                if (!nextContactMap[username]) {
                  nextContactMap[username] = cachedContact
                }
              }
              contactMap = nextContactMap
              syncContactTypeCounts(Object.values(contactMap))
              const refreshAt = Date.now()
              setSessionContactsUpdatedAt(refreshAt)

              const upsertResult = upsertAvatarCacheFromContacts(avatarEntries, Object.values(contactMap), {
                prune: true,
                now: refreshAt
              })
              avatarEntries = upsertResult.avatarEntries
              if (upsertResult.updatedAt) {
                setSessionAvatarUpdatedAt(upsertResult.updatedAt)
              }
            }

            const sourceContacts = Object.values(contactMap)
            const sourceByUsername = new Map<string, ContactInfo>()
            for (const contact of sourceContacts) {
              if (!contact?.username) continue
              sourceByUsername.set(contact.username, contact)
            }
            const rawSessionMap = rawSessions.reduce<Record<string, AppChatSession>>((map, session) => {
              map[session.username] = session
              return map
            }, {})
            const candidateUsernames = sourceContacts.length > 0
              ? sourceContacts.map(contact => contact.username)
              : baseSessions.map(session => session.username)
            const needsEnrichment = candidateUsernames
              .filter(Boolean)
              .filter((username) => {
                const currentContact = sourceByUsername.get(username)
                const session = rawSessionMap[username]
                const currentAvatarUrl = currentContact?.avatarUrl || session?.avatarUrl
                return !currentAvatarUrl
              })

            let extraContactMap: Record<string, { displayName?: string; avatarUrl?: string }> = {}
            if (needsEnrichment.length > 0) {
              for (let i = 0; i < needsEnrichment.length; i += EXPORT_AVATAR_ENRICH_BATCH_SIZE) {
                if (isStale()) return
                const batch = needsEnrichment.slice(i, i + EXPORT_AVATAR_ENRICH_BATCH_SIZE)
                if (batch.length === 0) continue
                try {
                  const enrichResult = await withTimeout(
                    window.electronAPI.chat.enrichSessionsContactInfo(batch, {
                      skipDisplayName: true,
                      onlyMissingAvatar: true
                    }),
                    CONTACT_ENRICH_TIMEOUT_MS
                  )
                  if (isStale()) return
                  if (enrichResult?.success && enrichResult.contacts) {
                    extraContactMap = {
                      ...extraContactMap,
                      ...enrichResult.contacts
                    }
                    hasFreshNetworkData = true
                    for (const [username, enriched] of Object.entries(enrichResult.contacts)) {
                      const current = sourceByUsername.get(username)
                      if (!current) continue
                      sourceByUsername.set(username, {
                        ...current,
                        displayName: enriched.displayName || current.displayName,
                        avatarUrl: enriched.avatarUrl || current.avatarUrl
                      })
                    }
                  }
                } catch (batchError) {
                  console.error('导出页分批补充会话联系人信息失败:', batchError)
                }

                const batchContacts = batch
                  .map(username => sourceByUsername.get(username))
                  .filter((contact): contact is ContactInfo => Boolean(contact))
                const upsertResult = upsertAvatarCacheFromContacts(avatarEntries, batchContacts, {
                  markCheckedUsernames: batch
                })
                avatarEntries = upsertResult.avatarEntries
                if (upsertResult.updatedAt) {
                  setSessionAvatarUpdatedAt(upsertResult.updatedAt)
                }
                await new Promise(resolve => setTimeout(resolve, 0))
              }
            }

            const contactsForPersist = Array.from(sourceByUsername.values())
            if (hasNetworkContactsSnapshot && contactsForPersist.length > 0) {
              const upsertResult = upsertAvatarCacheFromContacts(avatarEntries, contactsForPersist, {
                prune: true
              })
              avatarEntries = upsertResult.avatarEntries
              if (upsertResult.updatedAt) {
                setSessionAvatarUpdatedAt(upsertResult.updatedAt)
              }
            }
            contactMap = contactsForPersist.reduce<Record<string, ContactInfo>>((map, contact) => {
              map[contact.username] = contact
              return map
            }, contactMap)

            if (isStale()) return
            const nextSessions = toSessionRowsWithContacts(rawSessions, contactMap)
              .map((session) => {
                const extra = extraContactMap[session.username]
                const displayName = extra?.displayName || session.displayName || session.username
                const avatarUrl = extra?.avatarUrl || session.avatarUrl || avatarEntries[session.username]?.avatarUrl
                if (displayName === session.displayName && avatarUrl === session.avatarUrl) {
                  return session
                }
                return {
                  ...session,
                  displayName,
                  avatarUrl
                }
              })
              .sort((a, b) => (b.sortTimestamp || b.lastTimestamp || 0) - (a.sortTimestamp || a.lastTimestamp || 0))

            const contactsCachePayload = Object.values(contactMap).map((contact) => ({
              username: contact.username,
              displayName: contact.displayName || contact.username,
              remark: contact.remark,
              nickname: contact.nickname,
              type: contact.type
            }))

            const persistAt = Date.now()
            setSessions(nextSessions)
            sessionsHydratedAtRef.current = persistAt
            if (hasNetworkContactsSnapshot && contactsCachePayload.length > 0) {
              await configService.setContactsListCache(scopeKey, contactsCachePayload)
              setSessionContactsUpdatedAt(persistAt)
            }
            if (Object.keys(avatarEntries).length > 0) {
              await configService.setContactsAvatarCache(scopeKey, avatarEntries)
              setSessionAvatarUpdatedAt(persistAt)
            }
            if (hasFreshNetworkData) {
              setSessionDataSource('network')
            }
          } catch (enrichError) {
            console.error('导出页补充会话联系人信息失败:', enrichError)
          } finally {
            if (!isStale()) setIsSessionEnriching(false)
          }
        })()
      } else {
        setIsLoading(false)
      }
    } catch (error) {
      console.error('加载会话失败:', error)
      if (!isStale()) setIsLoading(false)
    } finally {
      if (!isStale()) setIsLoading(false)
    }
  }, [ensureExportCacheScope, loadContactsCaches, loadSessionMessageCounts, mergeSessionContentMetrics, syncContactTypeCounts])

  useEffect(() => {
    if (!isExportRoute) return
    const now = Date.now()
    const hasFreshSessionSnapshot = hasBaseConfigReadyRef.current &&
      sessionsRef.current.length > 0 &&
      now - sessionsHydratedAtRef.current <= EXPORT_REENTER_SESSION_SOFT_REFRESH_MS
    const hasFreshSnsSnapshot = hasSeededSnsStatsRef.current &&
      now - snsStatsHydratedAtRef.current <= EXPORT_REENTER_SNS_SOFT_REFRESH_MS

    void loadBaseConfig()
    void ensureSharedTabCountsLoaded()
    if (!hasFreshSessionSnapshot) {
      void loadSessions()
    }

    // 朋友圈统计延后一点加载，避免与首屏会话初始化抢占。
    const timer = window.setTimeout(() => {
      if (!hasFreshSnsSnapshot) {
        void loadSnsStats({ full: true })
      }
    }, 120)

    return () => window.clearTimeout(timer)
  }, [isExportRoute, ensureSharedTabCountsLoaded, loadBaseConfig, loadSessions, loadSnsStats])

  useEffect(() => {
    if (isExportRoute) return
    // 导出页隐藏时停止后台联系人补齐请求，避免与通讯录页面查询抢占。
    sessionLoadTokenRef.current = Date.now()
    sessionCountRequestIdRef.current += 1
    setIsSessionEnriching(false)
    setIsLoadingSessionCounts(false)
  }, [isExportRoute])

  useEffect(() => {
    activeTabRef.current = activeTab
  }, [activeTab])

  useEffect(() => {
    preselectAppliedRef.current = false
  }, [location.key, preselectSessionIds])

  useEffect(() => {
    if (preselectAppliedRef.current) return
    if (sessions.length === 0 || preselectSessionIds.length === 0) return

    const exists = new Set(sessions.map(session => session.username))
    const matched = preselectSessionIds.filter(id => exists.has(id))
    preselectAppliedRef.current = true

    if (matched.length > 0) {
      setSelectedSessions(new Set(matched))
    }
  }, [sessions, preselectSessionIds])

  const selectedCount = selectedSessions.size

  const toggleSelectSession = (sessionId: string) => {
    const target = sessions.find(session => session.username === sessionId)
    if (!target?.hasSession) return
    setSelectedSessions(prev => {
      const next = new Set(prev)
      if (next.has(sessionId)) {
        next.delete(sessionId)
      } else {
        next.add(sessionId)
      }
      return next
    })
  }

  const toggleSelectAllVisible = () => {
    const visibleIds = filteredContacts
      .filter(contact => sessionRowByUsername.get(contact.username)?.hasSession)
      .map(contact => contact.username)
    if (visibleIds.length === 0) return

    setSelectedSessions(prev => {
      const next = new Set(prev)
      const allSelected = visibleIds.every(id => next.has(id))
      if (allSelected) {
        for (const id of visibleIds) {
          next.delete(id)
        }
      } else {
        for (const id of visibleIds) {
          next.add(id)
        }
      }
      return next
    })
  }

  const clearSelection = () => setSelectedSessions(new Set())

  const openExportDialog = useCallback((payload: Omit<ExportDialogState, 'open'>) => {
    setExportDialog({ open: true, ...payload })
    setIsTimeRangeDialogOpen(false)
    setTimeRangePreset('all')

    setOptions(prev => {
      const nextDateRange = prev.dateRange ?? createDefaultDateRange()

      const next: ExportOptions = {
        ...prev,
        useAllTime: true,
        dateRange: nextDateRange
      }

      if (payload.scope === 'sns') {
        return next
      }

      if (payload.scope === 'content' && payload.contentType) {
        if (payload.contentType === 'text') {
          next.exportMedia = false
          next.exportImages = false
          next.exportVoices = false
          next.exportVideos = false
          next.exportEmojis = false
          next.exportAvatars = true
        } else {
          next.exportMedia = true
          next.exportImages = payload.contentType === 'image'
          next.exportVoices = payload.contentType === 'voice'
          next.exportVideos = payload.contentType === 'video'
          next.exportEmojis = payload.contentType === 'emoji'
          next.exportVoiceAsText = false
        }
      }

      return next
    })
  }, [])

  const closeExportDialog = useCallback(() => {
    setExportDialog(prev => ({ ...prev, open: false }))
    setIsTimeRangeDialogOpen(false)
    setTimeRangeDialogDraft(null)
    setTimeRangeDateInput({ start: '', end: '' })
    setTimeRangeDateInputError({ start: false, end: false })
  }, [])

  const buildTimeRangeDialogDraft = useCallback((): TimeRangeDialogDraft => {
    const dateRange = options.dateRange ?? createDefaultDateRange()
    return {
      preset: timeRangePreset,
      useAllTime: options.useAllTime,
      dateRange: {
        start: new Date(dateRange.start),
        end: new Date(dateRange.end)
      },
      startPanelMonth: toMonthStart(dateRange.start),
      endPanelMonth: toMonthStart(dateRange.end)
    }
  }, [options.dateRange, options.useAllTime, timeRangePreset])

  const openTimeRangeDialog = useCallback(() => {
    const draft = buildTimeRangeDialogDraft()
    setTimeRangeDialogDraft(draft)
    setIsTimeRangeDialogOpen(true)
  }, [buildTimeRangeDialogDraft])

  const closeTimeRangeDialog = useCallback(() => {
    setIsTimeRangeDialogOpen(false)
    setTimeRangeDialogDraft(null)
    setTimeRangeDateInput({ start: '', end: '' })
    setTimeRangeDateInputError({ start: false, end: false })
  }, [])

  const applyTimeRangePresetToDraft = useCallback((preset: Exclude<DateRangePreset, 'custom'>) => {
    setTimeRangeDialogDraft(prev => {
      const base = prev ?? buildTimeRangeDialogDraft()
      if (preset === 'all') {
        const previewRange = createDefaultDateRange()
        return {
          ...base,
          preset,
          useAllTime: true,
          dateRange: {
            start: previewRange.start,
            end: previewRange.end
          },
          startPanelMonth: toMonthStart(previewRange.start),
          endPanelMonth: toMonthStart(previewRange.end)
        }
      }
      const range = createDateRangeByPreset(preset)
      return {
        ...base,
        preset,
        useAllTime: false,
        dateRange: {
          start: range.start,
          end: range.end
        },
        startPanelMonth: toMonthStart(range.start),
        endPanelMonth: toMonthStart(range.end)
      }
    })
  }, [buildTimeRangeDialogDraft])

  const handleTimeRangePresetClick = useCallback((preset: Exclude<DateRangePreset, 'custom'>) => {
    applyTimeRangePresetToDraft(preset)
  }, [applyTimeRangePresetToDraft])

  const updateTimeRangeDraftStart = useCallback((targetDate: Date) => {
    const start = startOfDay(targetDate)
    setTimeRangeDialogDraft(prev => {
      const base = prev ?? buildTimeRangeDialogDraft()
      const nextEnd = base.dateRange.end < start ? endOfDay(start) : base.dateRange.end
      return {
        ...base,
        preset: 'custom',
        useAllTime: false,
        dateRange: {
          start,
          end: nextEnd
        },
        startPanelMonth: toMonthStart(start),
        endPanelMonth: toMonthStart(nextEnd)
      }
    })
  }, [buildTimeRangeDialogDraft])

  const updateTimeRangeDraftEnd = useCallback((targetDate: Date) => {
    const end = endOfDay(targetDate)
    setTimeRangeDialogDraft(prev => {
      const base = prev ?? buildTimeRangeDialogDraft()
      const isAllTimeMode = base.useAllTime
      const nextStart = isAllTimeMode
        ? startOfDay(targetDate)
        : base.dateRange.start
      const nextEnd = end < nextStart ? endOfDay(nextStart) : end
      return {
        ...base,
        preset: 'custom',
        useAllTime: false,
        dateRange: {
          start: nextStart,
          end: nextEnd
        },
        startPanelMonth: toMonthStart(nextStart),
        endPanelMonth: toMonthStart(nextEnd)
      }
    })
  }, [buildTimeRangeDialogDraft])

  const commitTimeRangeStartFromInput = useCallback(() => {
    const parsed = parseDateInputValue(timeRangeDateInput.start)
    if (!parsed) {
      setTimeRangeDateInputError(prev => ({ ...prev, start: true }))
      return
    }
    setTimeRangeDateInputError(prev => ({ ...prev, start: false }))
    updateTimeRangeDraftStart(parsed)
  }, [timeRangeDateInput.start, updateTimeRangeDraftStart])

  const commitTimeRangeEndFromInput = useCallback(() => {
    const parsed = parseDateInputValue(timeRangeDateInput.end)
    if (!parsed) {
      setTimeRangeDateInputError(prev => ({ ...prev, end: true }))
      return
    }
    setTimeRangeDateInputError(prev => ({ ...prev, end: false }))
    updateTimeRangeDraftEnd(parsed)
  }, [timeRangeDateInput.end, updateTimeRangeDraftEnd])

  const shiftTimeRangePanelMonth = useCallback((panel: 'start' | 'end', delta: number) => {
    setTimeRangeDialogDraft(prev => {
      const base = prev ?? buildTimeRangeDialogDraft()
      if (panel === 'start') {
        return {
          ...base,
          startPanelMonth: addMonths(base.startPanelMonth, delta)
        }
      }
      return {
        ...base,
        endPanelMonth: addMonths(base.endPanelMonth, delta)
      }
    })
  }, [buildTimeRangeDialogDraft])

  const commitTimeRangeDialogDraft = useCallback(() => {
    const draft = timeRangeDialogDraft ?? buildTimeRangeDialogDraft()
    setTimeRangePreset(draft.preset)
    setOptions(prev => ({
      ...prev,
      useAllTime: draft.useAllTime,
      dateRange: {
        start: new Date(draft.dateRange.start),
        end: new Date(draft.dateRange.end)
      }
    }))
    closeTimeRangeDialog()
  }, [buildTimeRangeDialogDraft, closeTimeRangeDialog, timeRangeDialogDraft])

  const timeRangeSummaryLabel = useMemo(() => {
    if (options.useAllTime) return '默认导出全部时间'
    if (timeRangePreset === 'today') return '今天'
    if (timeRangePreset === 'yesterday') return '昨天'
    if (timeRangePreset === 'last3days') return '最近3天'
    if (timeRangePreset === 'last7days') return '最近一周'
    if (timeRangePreset === 'last30days') return '最近30 天'
    if (timeRangePreset === 'last1year') return '最近一年'
    if (timeRangePreset === 'last2years') return '最近两年'
    if (options.dateRange) {
      return `${formatDateInputValue(options.dateRange.start)} 至 ${formatDateInputValue(options.dateRange.end)}`
    }
    return '自定义时间范围'
  }, [options.useAllTime, options.dateRange, timeRangePreset])

  const activeTimeRangeDialogDraft = timeRangeDialogDraft ?? buildTimeRangeDialogDraft()
  const isRangeModeActive = !activeTimeRangeDialogDraft.useAllTime
  const timeRangeModeText = isRangeModeActive
    ? '当前导出模式：按时间范围导出'
    : '当前导出模式：全部时间导出（选择下方日期将切换为按时间范围导出）'

  useEffect(() => {
    if (!isTimeRangeDialogOpen) return
    setTimeRangeDateInput({
      start: formatDateInputValue(activeTimeRangeDialogDraft.dateRange.start),
      end: formatDateInputValue(activeTimeRangeDialogDraft.dateRange.end)
    })
    setTimeRangeDateInputError({ start: false, end: false })
  }, [
    isTimeRangeDialogOpen,
    activeTimeRangeDialogDraft.dateRange.start.getTime(),
    activeTimeRangeDialogDraft.dateRange.end.getTime()
  ])

  const isTimeRangePresetActive = useCallback((preset: DateRangePreset): boolean => {
    if (preset === 'all') return activeTimeRangeDialogDraft.useAllTime
    return !activeTimeRangeDialogDraft.useAllTime && activeTimeRangeDialogDraft.preset === preset
  }, [activeTimeRangeDialogDraft])

  const startPanelCells = useMemo(
    () => buildCalendarCells(activeTimeRangeDialogDraft.startPanelMonth),
    [activeTimeRangeDialogDraft.startPanelMonth]
  )

  const endPanelCells = useMemo(
    () => buildCalendarCells(activeTimeRangeDialogDraft.endPanelMonth),
    [activeTimeRangeDialogDraft.endPanelMonth]
  )

  useEffect(() => {
    const unsubscribe = onOpenSingleExport((payload) => {
      void (async () => {
        const sessionId = typeof payload?.sessionId === 'string'
          ? payload.sessionId.trim()
          : ''
        if (!sessionId) return

        const sessionName = typeof payload?.sessionName === 'string'
          ? payload.sessionName.trim()
          : ''
        const displayName = sessionName || sessionId
        const requestId = typeof payload?.requestId === 'string'
          ? payload.requestId.trim()
          : ''

        const emitStatus = (
          status: 'initializing' | 'opened' | 'failed',
          message?: string
        ) => {
          if (!requestId) return
          emitSingleExportDialogStatus({ requestId, status, message })
        }

        try {
          if (!hasBaseConfigReadyRef.current) {
            emitStatus('initializing')
            const ready = await loadBaseConfig()
            if (!ready) {
              emitStatus('failed', '导出模块初始化失败，请重试')
              return
            }
          }

          setSelectedSessions(new Set([sessionId]))
          openExportDialog({
            scope: 'single',
            sessionIds: [sessionId],
            sessionNames: [displayName],
            title: `导出会话：${displayName}`
          })
          emitStatus('opened')
        } catch (error) {
          console.error('聊天页唤起导出弹窗失败:', error)
          emitStatus('failed', String(error))
        }
      })()
    })

    return unsubscribe
  }, [loadBaseConfig, openExportDialog])

  const buildExportOptions = (scope: TaskScope, contentType?: ContentType): ElectronExportOptions => {
    const sessionLayout: SessionLayout = writeLayout === 'C' ? 'per-session' : 'shared'
    const exportMediaEnabled = Boolean(options.exportImages || options.exportVoices || options.exportVideos || options.exportEmojis)

    const base: ElectronExportOptions = {
      format: options.format,
      exportAvatars: options.exportAvatars,
      exportMedia: exportMediaEnabled,
      exportImages: options.exportImages,
      exportVoices: options.exportVoices,
      exportVideos: options.exportVideos,
      exportEmojis: options.exportEmojis,
      exportVoiceAsText: options.exportVoiceAsText,
      excelCompactColumns: options.excelCompactColumns,
      txtColumns: options.txtColumns,
      displayNamePreference: options.displayNamePreference,
      exportConcurrency: options.exportConcurrency,
      sessionLayout,
      sessionNameWithTypePrefix,
      dateRange: options.useAllTime
        ? null
        : options.dateRange
          ? {
              start: Math.floor(options.dateRange.start.getTime() / 1000),
              end: Math.floor(options.dateRange.end.getTime() / 1000)
            }
          : null
    }

    if (scope === 'content' && contentType) {
      if (contentType === 'text') {
        const fastTextFormat: TextExportFormat = options.format === 'excel' ? 'arkme-json' : options.format
        const textExportConcurrency = Math.min(2, Math.max(1, base.exportConcurrency ?? options.exportConcurrency))
        return {
          ...base,
          format: fastTextFormat,
          contentType,
          exportConcurrency: textExportConcurrency,
          exportAvatars: true,
          exportMedia: false,
          exportImages: false,
          exportVoices: false,
          exportVideos: false,
          exportEmojis: false
        }
      }

      return {
        ...base,
        contentType,
        exportMedia: true,
        exportImages: contentType === 'image',
        exportVoices: contentType === 'voice',
        exportVideos: contentType === 'video',
        exportEmojis: contentType === 'emoji',
        exportVoiceAsText: false
      }
    }

    return base
  }

  const buildSnsExportOptions = () => {
    const format: SnsTimelineExportFormat = snsExportFormat
    const dateRange = options.useAllTime
      ? null
      : options.dateRange
        ? {
            startTime: Math.floor(options.dateRange.start.getTime() / 1000),
            endTime: Math.floor(options.dateRange.end.getTime() / 1000)
          }
        : null

    return {
      format,
      exportImages: snsExportImages,
      exportLivePhotos: snsExportLivePhotos,
      exportVideos: snsExportVideos,
      startTime: dateRange?.startTime,
      endTime: dateRange?.endTime
    }
  }

  const markSessionExported = useCallback((sessionIds: string[], timestamp: number) => {
    setLastExportBySession(prev => {
      const next = { ...prev }
      for (const id of sessionIds) {
        next[id] = timestamp
      }
      void configService.setExportLastSessionRunMap(next)
      return next
    })
  }, [])

  const markContentExported = useCallback((sessionIds: string[], contentTypes: ContentType[], timestamp: number) => {
    setLastExportByContent(prev => {
      const next = { ...prev }
      for (const id of sessionIds) {
        for (const type of contentTypes) {
          next[`${id}::${type}`] = timestamp
        }
      }
      void configService.setExportLastContentRunMap(next)
      return next
    })
  }, [])

  const resolveTaskExportContentLabel = useCallback((payload: ExportTaskPayload): string => {
    if (payload.scope === 'content' && payload.contentType) {
      return getContentTypeLabel(payload.contentType)
    }
    if (payload.scope === 'sns') return '朋友圈'

    const labels: string[] = ['聊天文本']
    const opts = payload.options
    if (opts?.exportMedia) {
      if (opts.exportImages) labels.push('图片')
      if (opts.exportVoices) labels.push('语音')
      if (opts.exportVideos) labels.push('视频')
      if (opts.exportEmojis) labels.push('表情包')
    }
    return Array.from(new Set(labels)).join('、')
  }, [])

  const markSessionExportRecords = useCallback((
    sessionIds: string[],
    content: string,
    outputDir: string,
    exportTime: number
  ) => {
    const normalizedContent = String(content || '').trim()
    const normalizedOutputDir = String(outputDir || '').trim()
    const normalizedExportTime = Number.isFinite(exportTime) ? Math.max(0, Math.floor(exportTime)) : Date.now()
    if (!normalizedContent || !normalizedOutputDir) return
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) return

    setExportRecordsBySession(prev => {
      const next: Record<string, configService.ExportSessionRecordEntry[]> = { ...prev }
      let changed = false

      for (const rawSessionId of sessionIds) {
        const sessionId = String(rawSessionId || '').trim()
        if (!sessionId) continue
        const existingList = Array.isArray(next[sessionId]) ? [...next[sessionId]] : []
        const lastRecord = existingList[existingList.length - 1]
        if (
          lastRecord &&
          lastRecord.content === normalizedContent &&
          lastRecord.outputDir === normalizedOutputDir &&
          Math.abs(Number(lastRecord.exportTime || 0) - normalizedExportTime) <= 2000
        ) {
          continue
        }
        existingList.push({
          exportTime: normalizedExportTime,
          content: normalizedContent,
          outputDir: normalizedOutputDir
        })
        next[sessionId] = existingList.slice(-80)
        changed = true
      }

      if (!changed) return prev
      void configService.setExportSessionRecordMap(next)
      return next
    })
  }, [])

  const inferContentTypesFromOptions = (opts: ElectronExportOptions): ContentType[] => {
    const types: ContentType[] = ['text']
    if (opts.exportMedia) {
      if (opts.exportVoices) types.push('voice')
      if (opts.exportImages) types.push('image')
      if (opts.exportVideos) types.push('video')
      if (opts.exportEmojis) types.push('emoji')
    }
    return types
  }

  const updateTask = useCallback((taskId: string, updater: (task: ExportTask) => ExportTask) => {
    setTasks(prev => prev.map(task => (task.id === taskId ? updater(task) : task)))
  }, [])

  const runNextTask = useCallback(async () => {
    if (runningTaskIdRef.current) return

    const queue = [...tasksRef.current].reverse()
    const next = queue.find(task => task.status === 'queued')
    if (!next) return

    runningTaskIdRef.current = next.id
    updateTask(next.id, task => ({
      ...task,
      status: 'running',
      settledSessionIds: [],
      startedAt: Date.now(),
      finishedAt: undefined,
      error: undefined,
      performance: isTextBatchTask(task)
        ? (task.performance || createEmptyTaskPerformance())
        : task.performance
    }))
    const taskExportContentLabel = resolveTaskExportContentLabel(next.payload)

    progressUnsubscribeRef.current?.()
    const settledSessionIdsFromProgress = new Set<string>()
    if (next.payload.scope === 'sns') {
      progressUnsubscribeRef.current = window.electronAPI.sns.onExportProgress((payload) => {
        updateTask(next.id, task => {
          if (task.status !== 'running') return task
          return {
            ...task,
            progress: {
              current: payload.current || 0,
              total: payload.total || 0,
              currentName: '',
              phase: 'exporting',
              phaseLabel: payload.status || '',
              phaseProgress: payload.total > 0 ? payload.current : 0,
              phaseTotal: payload.total || 0
            }
          }
        })
      })
    } else {
      progressUnsubscribeRef.current = window.electronAPI.export.onProgress((payload: ExportProgress) => {
        const now = Date.now()
        const currentSessionId = String(payload.currentSessionId || '').trim()
        if (payload.phase === 'complete' && currentSessionId && !settledSessionIdsFromProgress.has(currentSessionId)) {
          settledSessionIdsFromProgress.add(currentSessionId)
          const phaseLabel = String(payload.phaseLabel || '')
          const isFailed = phaseLabel.includes('失败')
          if (!isFailed) {
            const contentTypes = next.payload.contentType
              ? [next.payload.contentType]
              : (next.payload.options ? inferContentTypesFromOptions(next.payload.options) : [])
            markSessionExported([currentSessionId], now)
            if (contentTypes.length > 0) {
              markContentExported([currentSessionId], contentTypes, now)
            }
            markSessionExportRecords([currentSessionId], taskExportContentLabel, next.payload.outputDir, now)
          }
        }

        updateTask(next.id, task => {
          if (task.status !== 'running') return task
          const performance = applyProgressToTaskPerformance(task, payload, now)
          const settledSessionIds = task.settledSessionIds || []
          const nextSettledSessionIds = (
            payload.phase === 'complete' &&
            currentSessionId &&
            !settledSessionIds.includes(currentSessionId)
          )
            ? [...settledSessionIds, currentSessionId]
            : settledSessionIds
          return {
            ...task,
            progress: {
              current: payload.current,
              total: payload.total,
              currentName: payload.currentSession,
              phase: payload.phase,
              phaseLabel: payload.phaseLabel || '',
              phaseProgress: payload.phaseProgress || 0,
              phaseTotal: payload.phaseTotal || 0
            },
            settledSessionIds: nextSettledSessionIds,
            performance
          }
        })
      })
    }

    try {
      if (next.payload.scope === 'sns') {
        const snsOptions = next.payload.snsOptions || { format: 'html' as SnsTimelineExportFormat, exportImages: false, exportLivePhotos: false, exportVideos: false }
        const result = await window.electronAPI.sns.exportTimeline({
          outputDir: next.payload.outputDir,
          format: snsOptions.format,
          exportImages: snsOptions.exportImages,
          exportLivePhotos: snsOptions.exportLivePhotos,
          exportVideos: snsOptions.exportVideos,
          startTime: snsOptions.startTime,
          endTime: snsOptions.endTime
        })

        if (!result.success) {
          updateTask(next.id, task => ({
            ...task,
            status: 'error',
            finishedAt: Date.now(),
            error: result.error || '朋友圈导出失败',
            performance: finalizeTaskPerformance(task, Date.now())
          }))
        } else {
          const doneAt = Date.now()
          const exportedPosts = Math.max(0, result.postCount || 0)
          const mergedExportedCount = Math.max(lastSnsExportPostCount, exportedPosts)
          setLastSnsExportPostCount(mergedExportedCount)
          await configService.setExportLastSnsPostCount(mergedExportedCount)
          await loadSnsStats({ full: true })

          updateTask(next.id, task => ({
            ...task,
            status: 'success',
            finishedAt: doneAt,
            progress: {
              ...task.progress,
              current: exportedPosts,
              total: exportedPosts,
              phaseLabel: '完成',
              phaseProgress: 1,
              phaseTotal: 1
            },
            performance: finalizeTaskPerformance(task, doneAt)
          }))
        }
      } else {
        if (!next.payload.options) {
          throw new Error('导出参数缺失')
        }

        const result = await window.electronAPI.export.exportSessions(
          next.payload.sessionIds,
          next.payload.outputDir,
          next.payload.options
        )

        if (!result.success) {
          updateTask(next.id, task => ({
            ...task,
            status: 'error',
            finishedAt: Date.now(),
            error: result.error || '导出失败',
            performance: finalizeTaskPerformance(task, Date.now())
          }))
        } else {
          const doneAt = Date.now()
          const contentTypes = next.payload.contentType
            ? [next.payload.contentType]
            : inferContentTypesFromOptions(next.payload.options)
          const successSessionIds = Array.isArray(result.successSessionIds)
            ? result.successSessionIds
            : []
          if (successSessionIds.length > 0) {
            const unsettledSuccessSessionIds = successSessionIds.filter((sessionId) => !settledSessionIdsFromProgress.has(sessionId))
            if (unsettledSuccessSessionIds.length > 0) {
              markSessionExported(unsettledSuccessSessionIds, doneAt)
              markSessionExportRecords(unsettledSuccessSessionIds, taskExportContentLabel, next.payload.outputDir, doneAt)
              if (contentTypes.length > 0) {
                markContentExported(unsettledSuccessSessionIds, contentTypes, doneAt)
              }
            }
          }

          updateTask(next.id, task => ({
            ...task,
            status: 'success',
            finishedAt: doneAt,
            progress: {
              ...task.progress,
              current: task.progress.total || next.payload.sessionIds.length,
              total: task.progress.total || next.payload.sessionIds.length,
              phaseLabel: '完成',
              phaseProgress: 1,
              phaseTotal: 1
            },
            performance: finalizeTaskPerformance(task, doneAt)
          }))
        }
      }
    } catch (error) {
      const doneAt = Date.now()
      updateTask(next.id, task => ({
        ...task,
        status: 'error',
        finishedAt: doneAt,
        error: String(error),
        performance: finalizeTaskPerformance(task, doneAt)
      }))
    } finally {
      progressUnsubscribeRef.current?.()
      progressUnsubscribeRef.current = null
      runningTaskIdRef.current = null
      void runNextTask()
    }
  }, [
    updateTask,
    markSessionExported,
    markSessionExportRecords,
    markContentExported,
    resolveTaskExportContentLabel,
    loadSnsStats,
    lastSnsExportPostCount
  ])

  useEffect(() => {
    void runNextTask()
  }, [tasks, runNextTask])

  useEffect(() => {
    return () => {
      progressUnsubscribeRef.current?.()
      progressUnsubscribeRef.current = null
    }
  }, [])

  const createTask = async () => {
    if (!exportDialog.open || !exportFolder) return
    if (exportDialog.scope !== 'sns' && exportDialog.sessionIds.length === 0) return

    const exportOptions = exportDialog.scope === 'sns'
      ? undefined
      : buildExportOptions(exportDialog.scope, exportDialog.contentType)
    const snsOptions = exportDialog.scope === 'sns'
      ? buildSnsExportOptions()
      : undefined
    const title =
      exportDialog.scope === 'single'
        ? `${exportDialog.sessionNames[0] || '会话'} 导出`
        : exportDialog.scope === 'multi'
          ? `批量导出（${exportDialog.sessionIds.length} 个会话）`
          : exportDialog.scope === 'sns'
            ? '朋友圈批量导出'
            : `${contentTypeLabels[exportDialog.contentType || 'text']}批量导出`

    const task: ExportTask = {
      id: createTaskId(),
      title,
      status: 'queued',
      settledSessionIds: [],
      createdAt: Date.now(),
      payload: {
        sessionIds: exportDialog.sessionIds,
        sessionNames: exportDialog.sessionNames,
        outputDir: exportFolder,
        options: exportOptions,
        scope: exportDialog.scope,
        contentType: exportDialog.contentType,
        snsOptions
      },
      progress: createEmptyProgress(),
      performance: exportDialog.scope === 'content' && exportDialog.contentType === 'text'
        ? createEmptyTaskPerformance()
        : undefined
    }

    setTasks(prev => [task, ...prev])
    closeExportDialog()

    await configService.setExportDefaultFormat(options.format)
    await configService.setExportDefaultMedia(Boolean(options.exportImages || options.exportVoices || options.exportVideos || options.exportEmojis))
    await configService.setExportDefaultVoiceAsText(options.exportVoiceAsText)
    await configService.setExportDefaultExcelCompactColumns(options.excelCompactColumns)
    await configService.setExportDefaultTxtColumns(options.txtColumns)
    await configService.setExportDefaultConcurrency(options.exportConcurrency)
  }

  const openSingleExport = useCallback((session: SessionRow) => {
    if (!session.hasSession) return
    openExportDialog({
      scope: 'single',
      sessionIds: [session.username],
      sessionNames: [session.displayName || session.username],
      title: `导出会话：${session.displayName || session.username}`
    })
  }, [openExportDialog])

  const resolveSessionExistingMessageCount = useCallback((session: SessionRow): number => {
    const counted = normalizeMessageCount(sessionMessageCounts[session.username])
    if (typeof counted === 'number') return counted
    const hinted = normalizeMessageCount(session.messageCountHint)
    if (typeof hinted === 'number') return hinted
    return 0
  }, [sessionMessageCounts])

  const orderSessionsForExport = useCallback((source: SessionRow[]): SessionRow[] => {
    return source
      .filter((session) => session.hasSession && isContentScopeSession(session))
      .map((session) => ({
        session,
        count: resolveSessionExistingMessageCount(session)
      }))
      .filter((item) => item.count > 0)
      .sort((a, b) => {
        const kindDiff = exportKindPriority[a.session.kind] - exportKindPriority[b.session.kind]
        if (kindDiff !== 0) return kindDiff
        if (a.count !== b.count) return b.count - a.count
        const tsA = a.session.sortTimestamp || a.session.lastTimestamp || 0
        const tsB = b.session.sortTimestamp || b.session.lastTimestamp || 0
        if (tsA !== tsB) return tsB - tsA
        return (a.session.displayName || a.session.username)
          .localeCompare(b.session.displayName || b.session.username, 'zh-Hans-CN')
      })
      .map((item) => item.session)
  }, [resolveSessionExistingMessageCount])

  const openBatchExport = () => {
    const selectedSet = new Set(selectedSessions)
    const selectedRows = sessions.filter((session) => selectedSet.has(session.username))
    const orderedRows = orderSessionsForExport(selectedRows)
    if (orderedRows.length === 0) {
      window.alert('所选会话暂无可导出的消息（总消息数为 0）')
      return
    }
    const ids = orderedRows.map((session) => session.username)
    const names = orderedRows.map((session) => session.displayName || session.username)

    openExportDialog({
      scope: 'multi',
      sessionIds: ids,
      sessionNames: names,
      title: `批量导出（${ids.length} 个会话）`
    })
  }

  const openContentExport = (contentType: ContentType) => {
    const orderedRows = orderSessionsForExport(sessions)
    if (orderedRows.length === 0) {
      window.alert('当前会话列表暂无可导出的消息（总消息数为 0）')
      return
    }
    const ids = orderedRows.map((session) => session.username)
    const names = orderedRows.map((session) => session.displayName || session.username)

    openExportDialog({
      scope: 'content',
      contentType,
      sessionIds: ids,
      sessionNames: names,
      title: `${contentTypeLabels[contentType]}批量导出`
    })
  }

  const openSnsExport = () => {
    openExportDialog({
      scope: 'sns',
      sessionIds: [],
      sessionNames: ['全部朋友圈动态'],
      title: '朋友圈批量导出'
    })
  }

  const runningSessionIds = useMemo(() => {
    const set = new Set<string>()
    for (const task of tasks) {
      if (task.status !== 'running') continue
      const settled = new Set(task.settledSessionIds || [])
      for (const id of task.payload.sessionIds) {
        if (settled.has(id)) continue
        set.add(id)
      }
    }
    return set
  }, [tasks])

  const queuedSessionIds = useMemo(() => {
    const set = new Set<string>()
    for (const task of tasks) {
      if (task.status !== 'queued') continue
      for (const id of task.payload.sessionIds) {
        set.add(id)
      }
    }
    return set
  }, [tasks])

  const inProgressSessionIds = useMemo(() => {
    const set = new Set<string>()
    for (const task of tasks) {
      if (task.status !== 'running' && task.status !== 'queued') continue
      for (const id of task.payload.sessionIds) {
        set.add(id)
      }
    }
    return Array.from(set).sort()
  }, [tasks])
  const activeTaskCount = useMemo(
    () => tasks.filter(task => task.status === 'running' || task.status === 'queued').length,
    [tasks]
  )

  const inProgressSessionIdsKey = useMemo(
    () => inProgressSessionIds.join('||'),
    [inProgressSessionIds]
  )
  const inProgressStatusKey = useMemo(
    () => `${activeTaskCount}::${inProgressSessionIdsKey}`,
    [activeTaskCount, inProgressSessionIdsKey]
  )

  useEffect(() => {
    inProgressSessionIdsRef.current = inProgressSessionIds
  }, [inProgressSessionIds])

  useEffect(() => {
    activeTaskCountRef.current = activeTaskCount
  }, [activeTaskCount])

  useEffect(() => {
    emitExportSessionStatus({
      inProgressSessionIds: inProgressSessionIdsRef.current,
      activeTaskCount: activeTaskCountRef.current
    })
  }, [inProgressStatusKey])

  useEffect(() => {
    const unsubscribe = onExportSessionStatusRequest(() => {
      emitExportSessionStatus({
        inProgressSessionIds: inProgressSessionIdsRef.current,
        activeTaskCount: activeTaskCountRef.current
      })
    })
    return unsubscribe
  }, [])

  const runningCardTypes = useMemo(() => {
    const set = new Set<ContentCardType>()
    for (const task of tasks) {
      if (task.status !== 'running') continue
      if (task.payload.scope === 'sns') {
        set.add('sns')
        continue
      }
      if (task.payload.scope === 'content' && task.payload.contentType) {
        set.add(task.payload.contentType)
      }
    }
    return set
  }, [tasks])

  const contentCards = useMemo(() => {
    const scopeSessions = sessions.filter(isContentScopeSession)
    const snsExportedCount = Math.min(lastSnsExportPostCount, snsStats.totalPosts)

    const sessionCards = [
      { type: 'text' as ContentType, icon: MessageSquareText },
      { type: 'voice' as ContentType, icon: Mic },
      { type: 'image' as ContentType, icon: ImageIcon },
      { type: 'video' as ContentType, icon: Video },
      { type: 'emoji' as ContentType, icon: WandSparkles }
    ].map(item => {
      let exported = 0
      for (const session of scopeSessions) {
        if (lastExportByContent[`${session.username}::${item.type}`]) {
          exported += 1
        }
      }

      return {
        ...item,
        label: contentTypeLabels[item.type],
        stats: [
          { label: '已导出', value: exported, unit: '个对话' }
        ]
      }
    })

    const snsCard = {
      type: 'sns' as ContentCardType,
      icon: Aperture,
      label: '朋友圈',
      headerCount: snsStats.totalPosts,
      stats: [
        { label: '已导出', value: snsExportedCount, unit: '条' }
      ]
    }

    return [...sessionCards, snsCard]
  }, [sessions, lastExportByContent, snsStats, lastSnsExportPostCount])

  const activeTabLabel = useMemo(() => {
    if (activeTab === 'private') return '私聊'
    if (activeTab === 'group') return '群聊'
    if (activeTab === 'former_friend') return '曾经的好友'
    return '公众号'
  }, [activeTab])

  const sessionRowByUsername = useMemo(() => {
    const map = new Map<string, SessionRow>()
    for (const session of sessions) {
      map.set(session.username, session)
    }
    return map
  }, [sessions])

  const filteredContacts = useMemo(() => {
    const keyword = searchKeyword.trim().toLowerCase()
    const contacts = contactsList
      .filter((contact) => {
        if (!matchesContactTab(contact, activeTab)) return false
        if (!keyword) return true
        return (
          (contact.displayName || '').toLowerCase().includes(keyword) ||
          (contact.remark || '').toLowerCase().includes(keyword) ||
          contact.username.toLowerCase().includes(keyword)
        )
      })

    const indexedContacts = contacts.map((contact, index) => ({
      contact,
      index,
      count: (() => {
        const counted = normalizeMessageCount(sessionMessageCounts[contact.username])
        if (typeof counted === 'number') return counted
        const hinted = normalizeMessageCount(sessionRowByUsername.get(contact.username)?.messageCountHint)
        return hinted
      })()
    }))

    indexedContacts.sort((a, b) => {
      const aHasCount = typeof a.count === 'number'
      const bHasCount = typeof b.count === 'number'
      if (aHasCount && bHasCount) {
        const diff = (b.count as number) - (a.count as number)
        if (diff !== 0) return diff
      } else if (aHasCount) {
        return -1
      } else if (bHasCount) {
        return 1
      }
      // 无统计值或同分时保持原顺序，避免列表频繁跳动。
      return a.index - b.index
    })

    return indexedContacts.map(item => item.contact)
  }, [contactsList, activeTab, searchKeyword, sessionMessageCounts, sessionRowByUsername])

  useEffect(() => {
    contactsVirtuosoRef.current?.scrollToIndex({ index: 0, align: 'start' })
    setIsContactsListAtTop(true)
  }, [activeTab, searchKeyword])

  const contactByUsername = useMemo(() => {
    const map = new Map<string, ContactInfo>()
    for (const contact of contactsList) {
      map.set(contact.username, contact)
    }
    return map
  }, [contactsList])

  const currentSessionExportRecords = useMemo(() => {
    const sessionId = String(sessionDetail?.wxid || '').trim()
    if (!sessionId) return [] as configService.ExportSessionRecordEntry[]
    const records = Array.isArray(exportRecordsBySession[sessionId]) ? exportRecordsBySession[sessionId] : []
    return [...records]
      .sort((a, b) => Number(b.exportTime || 0) - Number(a.exportTime || 0))
      .slice(0, 20)
  }, [sessionDetail?.wxid, exportRecordsBySession])

  const applySessionDetailStats = useCallback((
    sessionId: string,
    metric: SessionExportMetric,
    cacheMeta?: SessionExportCacheMeta,
    relationLoadedOverride?: boolean
  ) => {
    mergeSessionContentMetrics({ [sessionId]: metric })
    setSessionDetail((prev) => {
      if (!prev || prev.wxid !== sessionId) return prev
      const relationLoaded = relationLoadedOverride ?? Boolean(prev.relationStatsLoaded)
      return {
        ...prev,
        messageCount: Number.isFinite(metric.totalMessages) ? metric.totalMessages : prev.messageCount,
        voiceMessages: Number.isFinite(metric.voiceMessages) ? metric.voiceMessages : prev.voiceMessages,
        imageMessages: Number.isFinite(metric.imageMessages) ? metric.imageMessages : prev.imageMessages,
        videoMessages: Number.isFinite(metric.videoMessages) ? metric.videoMessages : prev.videoMessages,
        emojiMessages: Number.isFinite(metric.emojiMessages) ? metric.emojiMessages : prev.emojiMessages,
        transferMessages: Number.isFinite(metric.transferMessages) ? metric.transferMessages : prev.transferMessages,
        redPacketMessages: Number.isFinite(metric.redPacketMessages) ? metric.redPacketMessages : prev.redPacketMessages,
        callMessages: Number.isFinite(metric.callMessages) ? metric.callMessages : prev.callMessages,
        groupMemberCount: Number.isFinite(metric.groupMemberCount) ? metric.groupMemberCount : prev.groupMemberCount,
        groupMyMessages: Number.isFinite(metric.groupMyMessages) ? metric.groupMyMessages : prev.groupMyMessages,
        groupActiveSpeakers: Number.isFinite(metric.groupActiveSpeakers) ? metric.groupActiveSpeakers : prev.groupActiveSpeakers,
        privateMutualGroups: relationLoaded && Number.isFinite(metric.privateMutualGroups)
          ? metric.privateMutualGroups
          : prev.privateMutualGroups,
        groupMutualFriends: relationLoaded && Number.isFinite(metric.groupMutualFriends)
          ? metric.groupMutualFriends
          : prev.groupMutualFriends,
        relationStatsLoaded: relationLoaded,
        statsUpdatedAt: cacheMeta?.updatedAt ?? prev.statsUpdatedAt,
        statsStale: typeof cacheMeta?.stale === 'boolean' ? cacheMeta.stale : prev.statsStale,
        firstMessageTime: Number.isFinite(metric.firstTimestamp) ? metric.firstTimestamp : prev.firstMessageTime,
        latestMessageTime: Number.isFinite(metric.lastTimestamp) ? metric.lastTimestamp : prev.latestMessageTime
      }
    })
  }, [mergeSessionContentMetrics])

  const loadSessionDetail = useCallback(async (sessionId: string) => {
    const normalizedSessionId = String(sessionId || '').trim()
    if (!normalizedSessionId) return

    const requestSeq = ++detailRequestSeqRef.current
    const mappedSession = sessionRowByUsername.get(normalizedSessionId)
    const mappedContact = contactByUsername.get(normalizedSessionId)
    const cachedMetric = sessionContentMetrics[normalizedSessionId]
    const countedCount = normalizeMessageCount(sessionMessageCounts[normalizedSessionId])
    const metricCount = normalizeMessageCount(cachedMetric?.totalMessages)
    const metricVoice = normalizeMessageCount(cachedMetric?.voiceMessages)
    const metricImage = normalizeMessageCount(cachedMetric?.imageMessages)
    const metricVideo = normalizeMessageCount(cachedMetric?.videoMessages)
    const metricEmoji = normalizeMessageCount(cachedMetric?.emojiMessages)
    const metricTransfer = normalizeMessageCount(cachedMetric?.transferMessages)
    const metricRedPacket = normalizeMessageCount(cachedMetric?.redPacketMessages)
    const metricCall = normalizeMessageCount(cachedMetric?.callMessages)
    const hintedCount = typeof mappedSession?.messageCountHint === 'number' && Number.isFinite(mappedSession.messageCountHint) && mappedSession.messageCountHint >= 0
      ? Math.floor(mappedSession.messageCountHint)
      : undefined
    const initialMessageCount = countedCount ?? metricCount ?? hintedCount

    setCopiedDetailField(null)
    setIsRefreshingSessionDetailStats(false)
    setIsLoadingSessionRelationStats(false)
    setSessionDetail((prev) => {
      const sameSession = prev?.wxid === normalizedSessionId
      return {
        wxid: normalizedSessionId,
        displayName: mappedSession?.displayName || mappedContact?.displayName || prev?.displayName || normalizedSessionId,
        remark: sameSession ? prev?.remark : mappedContact?.remark,
        nickName: sameSession ? prev?.nickName : mappedContact?.nickname,
        alias: sameSession ? prev?.alias : undefined,
        avatarUrl: mappedSession?.avatarUrl || mappedContact?.avatarUrl || (sameSession ? prev?.avatarUrl : undefined),
        messageCount: initialMessageCount ?? (sameSession ? prev.messageCount : Number.NaN),
        voiceMessages: metricVoice ?? (sameSession ? prev?.voiceMessages : undefined),
        imageMessages: metricImage ?? (sameSession ? prev?.imageMessages : undefined),
        videoMessages: metricVideo ?? (sameSession ? prev?.videoMessages : undefined),
        emojiMessages: metricEmoji ?? (sameSession ? prev?.emojiMessages : undefined),
        transferMessages: metricTransfer ?? (sameSession ? prev?.transferMessages : undefined),
        redPacketMessages: metricRedPacket ?? (sameSession ? prev?.redPacketMessages : undefined),
        callMessages: metricCall ?? (sameSession ? prev?.callMessages : undefined),
        privateMutualGroups: sameSession ? prev?.privateMutualGroups : undefined,
        groupMemberCount: sameSession ? prev?.groupMemberCount : undefined,
        groupMyMessages: sameSession ? prev?.groupMyMessages : undefined,
        groupActiveSpeakers: sameSession ? prev?.groupActiveSpeakers : undefined,
        groupMutualFriends: sameSession ? prev?.groupMutualFriends : undefined,
        relationStatsLoaded: sameSession ? prev?.relationStatsLoaded : false,
        statsUpdatedAt: sameSession ? prev?.statsUpdatedAt : undefined,
        statsStale: sameSession ? prev?.statsStale : undefined,
        firstMessageTime: sameSession ? prev?.firstMessageTime : undefined,
        latestMessageTime: sameSession ? prev?.latestMessageTime : undefined,
        messageTables: sameSession && Array.isArray(prev?.messageTables) ? prev.messageTables : []
      }
    })
    setIsLoadingSessionDetail(true)
    setIsLoadingSessionDetailExtra(true)

    try {
      const result = await window.electronAPI.chat.getSessionDetailFast(normalizedSessionId)
      if (requestSeq !== detailRequestSeqRef.current) return
      if (result.success && result.detail) {
        const fastMessageCount = normalizeMessageCount(result.detail.messageCount)
        if (typeof fastMessageCount === 'number') {
          setSessionMessageCounts((prev) => {
            if (prev[normalizedSessionId] === fastMessageCount) return prev
            return {
              ...prev,
              [normalizedSessionId]: fastMessageCount
            }
          })
          mergeSessionContentMetrics({
            [normalizedSessionId]: {
              totalMessages: fastMessageCount
            }
          })
        }
        setSessionDetail((prev) => ({
          wxid: normalizedSessionId,
          displayName: result.detail!.displayName || prev?.displayName || normalizedSessionId,
          remark: result.detail!.remark ?? prev?.remark,
          nickName: result.detail!.nickName ?? prev?.nickName,
          alias: result.detail!.alias ?? prev?.alias,
          avatarUrl: result.detail!.avatarUrl || prev?.avatarUrl,
          messageCount: Number.isFinite(result.detail!.messageCount) ? result.detail!.messageCount : prev?.messageCount ?? Number.NaN,
          voiceMessages: prev?.voiceMessages,
          imageMessages: prev?.imageMessages,
          videoMessages: prev?.videoMessages,
          emojiMessages: prev?.emojiMessages,
          transferMessages: prev?.transferMessages,
          redPacketMessages: prev?.redPacketMessages,
          callMessages: prev?.callMessages,
          privateMutualGroups: prev?.privateMutualGroups,
          groupMemberCount: prev?.groupMemberCount,
          groupMyMessages: prev?.groupMyMessages,
          groupActiveSpeakers: prev?.groupActiveSpeakers,
          groupMutualFriends: prev?.groupMutualFriends,
          relationStatsLoaded: prev?.relationStatsLoaded,
          statsUpdatedAt: prev?.statsUpdatedAt,
          statsStale: prev?.statsStale,
          firstMessageTime: prev?.firstMessageTime,
          latestMessageTime: prev?.latestMessageTime,
          messageTables: Array.isArray(prev?.messageTables) ? (prev?.messageTables || []) : []
        }))
      }
    } catch (error) {
      console.error('导出页加载会话详情失败:', error)
    } finally {
      if (requestSeq === detailRequestSeqRef.current) {
        setIsLoadingSessionDetail(false)
      }
    }

    try {
      const [extraResultSettled, statsResultSettled] = await Promise.allSettled([
        window.electronAPI.chat.getSessionDetailExtra(normalizedSessionId),
        window.electronAPI.chat.getExportSessionStats(
          [normalizedSessionId],
          { includeRelations: false, forceRefresh: true, preferAccurateSpecialTypes: true }
        )
      ])

      if (requestSeq !== detailRequestSeqRef.current) return

      if (extraResultSettled.status === 'fulfilled' && extraResultSettled.value.success) {
        const detail = extraResultSettled.value.detail
        if (detail) {
          setSessionDetail((prev) => {
            if (!prev || prev.wxid !== normalizedSessionId) return prev
            return {
              ...prev,
              firstMessageTime: detail.firstMessageTime,
              latestMessageTime: detail.latestMessageTime,
              messageTables: Array.isArray(detail.messageTables) ? detail.messageTables : []
            }
          })
        }
      }

      let refreshIncludeRelations = false
      let shouldRefreshStats = false
      if (statsResultSettled.status === 'fulfilled' && statsResultSettled.value.success) {
        const metric = statsResultSettled.value.data?.[normalizedSessionId] as SessionExportMetric | undefined
        const cacheMeta = statsResultSettled.value.cache?.[normalizedSessionId] as SessionExportCacheMeta | undefined
        refreshIncludeRelations = Boolean(cacheMeta?.includeRelations)
        if (metric) {
          applySessionDetailStats(normalizedSessionId, metric, cacheMeta, refreshIncludeRelations)
        } else if (cacheMeta) {
          setSessionDetail((prev) => {
            if (!prev || prev.wxid !== normalizedSessionId) return prev
            return {
              ...prev,
              relationStatsLoaded: refreshIncludeRelations || prev.relationStatsLoaded,
              statsUpdatedAt: cacheMeta.updatedAt,
              statsStale: cacheMeta.stale
            }
          })
        }
        shouldRefreshStats = Array.isArray(statsResultSettled.value.needsRefresh) &&
          statsResultSettled.value.needsRefresh.includes(normalizedSessionId)
      }

      if (shouldRefreshStats) {
        setIsRefreshingSessionDetailStats(true)
        void (async () => {
          try {
            const freshResult = await window.electronAPI.chat.getExportSessionStats(
              [normalizedSessionId],
              { includeRelations: refreshIncludeRelations, forceRefresh: true, preferAccurateSpecialTypes: true }
            )
            if (requestSeq !== detailRequestSeqRef.current) return
            if (freshResult.success && freshResult.data) {
              const metric = freshResult.data[normalizedSessionId] as SessionExportMetric | undefined
              const cacheMeta = freshResult.cache?.[normalizedSessionId] as SessionExportCacheMeta | undefined
              if (metric) {
                applySessionDetailStats(
                  normalizedSessionId,
                  metric,
                  cacheMeta,
                  refreshIncludeRelations ? true : undefined
                )
              }
            }
          } catch (error) {
            console.error('导出页刷新会话统计失败:', error)
          } finally {
            if (requestSeq === detailRequestSeqRef.current) {
              setIsRefreshingSessionDetailStats(false)
            }
          }
        })()
      }
    } catch (error) {
      console.error('导出页加载会话详情补充统计失败:', error)
    } finally {
      if (requestSeq === detailRequestSeqRef.current) {
        setIsLoadingSessionDetailExtra(false)
      }
    }
  }, [applySessionDetailStats, contactByUsername, mergeSessionContentMetrics, sessionContentMetrics, sessionMessageCounts, sessionRowByUsername])

  const loadSessionRelationStats = useCallback(async () => {
    const normalizedSessionId = String(sessionDetail?.wxid || '').trim()
    if (!normalizedSessionId || isLoadingSessionRelationStats) return

    const requestSeq = detailRequestSeqRef.current
    setIsLoadingSessionRelationStats(true)
    try {
      const relationResult = await window.electronAPI.chat.getExportSessionStats(
        [normalizedSessionId],
        { includeRelations: true, forceRefresh: true, preferAccurateSpecialTypes: true }
      )
      if (requestSeq !== detailRequestSeqRef.current) return

      const metric = relationResult.success && relationResult.data
        ? relationResult.data[normalizedSessionId] as SessionExportMetric | undefined
        : undefined
      const cacheMeta = relationResult.success
        ? relationResult.cache?.[normalizedSessionId] as SessionExportCacheMeta | undefined
        : undefined
      if (metric) {
        applySessionDetailStats(normalizedSessionId, metric, cacheMeta, true)
      }

      const needRefresh = relationResult.success &&
        Array.isArray(relationResult.needsRefresh) &&
        relationResult.needsRefresh.includes(normalizedSessionId)

      if (needRefresh) {
        setIsRefreshingSessionDetailStats(true)
        void (async () => {
          try {
            const freshResult = await window.electronAPI.chat.getExportSessionStats(
              [normalizedSessionId],
              { includeRelations: true, forceRefresh: true, preferAccurateSpecialTypes: true }
            )
            if (requestSeq !== detailRequestSeqRef.current) return
            if (freshResult.success && freshResult.data) {
              const freshMetric = freshResult.data[normalizedSessionId] as SessionExportMetric | undefined
              const freshMeta = freshResult.cache?.[normalizedSessionId] as SessionExportCacheMeta | undefined
              if (freshMetric) {
                applySessionDetailStats(normalizedSessionId, freshMetric, freshMeta, true)
              }
            }
          } catch (error) {
            console.error('导出页刷新会话关系统计失败:', error)
          } finally {
            if (requestSeq === detailRequestSeqRef.current) {
              setIsRefreshingSessionDetailStats(false)
            }
          }
        })()
      }
    } catch (error) {
      console.error('导出页加载会话关系统计失败:', error)
    } finally {
      if (requestSeq === detailRequestSeqRef.current) {
        setIsLoadingSessionRelationStats(false)
      }
    }
  }, [applySessionDetailStats, isLoadingSessionRelationStats, sessionDetail?.wxid])

  const closeSessionDetailPanel = useCallback(() => {
    detailRequestSeqRef.current += 1
    setShowSessionDetailPanel(false)
    setIsLoadingSessionDetail(false)
    setIsLoadingSessionDetailExtra(false)
    setIsRefreshingSessionDetailStats(false)
    setIsLoadingSessionRelationStats(false)
  }, [])

  const openSessionDetail = useCallback((sessionId: string) => {
    if (!sessionId) return
    setShowSessionDetailPanel(true)
    void loadSessionDetail(sessionId)
  }, [loadSessionDetail])

  useEffect(() => {
    if (!showSessionDetailPanel) return
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeSessionDetailPanel()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [closeSessionDetailPanel, showSessionDetailPanel])

  const handleCopyDetailField = useCallback(async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedDetailField(field)
      setTimeout(() => setCopiedDetailField(null), 1500)
    } catch {
      const textarea = document.createElement('textarea')
      textarea.value = text
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopiedDetailField(field)
      setTimeout(() => setCopiedDetailField(null), 1500)
    }
  }, [])

  const contactsIssueElapsedMs = useMemo(() => {
    if (!contactsLoadIssue) return 0
    if (isContactsListLoading && contactsLoadSession) {
      return Math.max(contactsLoadIssue.elapsedMs, contactsDiagnosticTick - contactsLoadSession.startedAt)
    }
    return contactsLoadIssue.elapsedMs
  }, [contactsDiagnosticTick, isContactsListLoading, contactsLoadIssue, contactsLoadSession])

  const contactsDiagnosticsText = useMemo(() => {
    if (!contactsLoadIssue || !contactsLoadSession) return ''
    return [
      `请求ID: ${contactsLoadSession.requestId}`,
      `请求序号: 第 ${contactsLoadSession.attempt} 次`,
      `阈值配置: ${contactsLoadSession.timeoutMs}ms`,
      `当前状态: ${contactsLoadIssue.kind === 'timeout' ? '超时等待中' : '请求失败'}`,
      `累计耗时: ${(contactsIssueElapsedMs / 1000).toFixed(1)}s`,
      `发生时间: ${new Date(contactsLoadIssue.occurredAt).toLocaleString()}`,
      '阶段: chat.getContacts',
      `原因: ${contactsLoadIssue.reason}`,
      `错误详情: ${contactsLoadIssue.errorDetail || '无'}`
    ].join('\n')
  }, [contactsIssueElapsedMs, contactsLoadIssue, contactsLoadSession])

  const copyContactsDiagnostics = useCallback(async () => {
    if (!contactsDiagnosticsText) return
    try {
      await navigator.clipboard.writeText(contactsDiagnosticsText)
      alert('诊断信息已复制')
    } catch (error) {
      console.error('复制诊断信息失败:', error)
      alert('复制失败，请手动复制诊断信息')
    }
  }, [contactsDiagnosticsText])

  const sessionContactsUpdatedAtLabel = useMemo(() => {
    if (!sessionContactsUpdatedAt) return ''
    return new Date(sessionContactsUpdatedAt).toLocaleString()
  }, [sessionContactsUpdatedAt])

  const sessionAvatarUpdatedAtLabel = useMemo(() => {
    if (!sessionAvatarUpdatedAt) return ''
    return new Date(sessionAvatarUpdatedAt).toLocaleString()
  }, [sessionAvatarUpdatedAt])

  const sessionAvatarCachedCount = useMemo(() => {
    return sessions.reduce((count, session) => (session.avatarUrl ? count + 1 : count), 0)
  }, [sessions])

  const visibleSelectableCount = useMemo(() => (
    filteredContacts.reduce((count, contact) => (
      sessionRowByUsername.get(contact.username)?.hasSession ? count + 1 : count
    ), 0)
  ), [filteredContacts, sessionRowByUsername])
  const isAllVisibleSelected = visibleSelectableCount > 0 && selectedCount === visibleSelectableCount

  const canCreateTask = exportDialog.scope === 'sns'
    ? Boolean(exportFolder)
    : Boolean(exportFolder) && exportDialog.sessionIds.length > 0
  const scopeLabel = exportDialog.scope === 'single'
    ? '单会话'
    : exportDialog.scope === 'multi'
      ? '多会话'
      : exportDialog.scope === 'sns'
        ? '朋友圈批量'
        : `按内容批量（${contentTypeLabels[exportDialog.contentType || 'text']}）`
  const scopeCountLabel = exportDialog.scope === 'sns'
    ? `共 ${snsStats.totalPosts} 条朋友圈动态`
    : `共 ${exportDialog.sessionIds.length} 个会话`
  const snsFormatOptions: Array<{ value: SnsTimelineExportFormat; label: string; desc: string }> = [
    { value: 'html', label: 'HTML', desc: '网页格式，可直接浏览' },
    { value: 'json', label: 'JSON', desc: '原始结构化格式（兼容旧导入）' },
    { value: 'arkmejson', label: 'ArkmeJSON', desc: '增强结构化格式，包含互动身份字段' }
  ]
  const formatCandidateOptions = exportDialog.scope === 'sns'
    ? snsFormatOptions
    : formatOptions
  const isContentScopeDialog = exportDialog.scope === 'content'
  const isContentTextDialog = isContentScopeDialog && exportDialog.contentType === 'text'
  const shouldShowFormatSection = !isContentScopeDialog || isContentTextDialog
  const shouldShowMediaSection = !isContentScopeDialog
  const shouldShowDisplayNameSection = !(
    exportDialog.scope === 'sns' ||
    (
      exportDialog.scope === 'content' &&
      (
        exportDialog.contentType === 'voice' ||
        exportDialog.contentType === 'image' ||
        exportDialog.contentType === 'video' ||
        exportDialog.contentType === 'emoji'
      )
    )
  )
  const isTabCountComputing = isSharedTabCountsLoading && !isSharedTabCountsReady
  const isSnsCardStatsLoading = !hasSeededSnsStats
  const taskRunningCount = tasks.filter(task => task.status === 'running').length
  const taskQueuedCount = tasks.filter(task => task.status === 'queued').length
  const hasFilteredContacts = filteredContacts.length > 0
  const showBackToTop = isPageScrolled || !isContactsListAtTop
  const closeTaskCenter = useCallback(() => {
    setIsTaskCenterOpen(false)
    setExpandedPerfTaskId(null)
  }, [])
  const toggleTaskPerfDetail = useCallback((taskId: string) => {
    setExpandedPerfTaskId(prev => (prev === taskId ? null : taskId))
  }, [])
  const renderContactRow = useCallback((_: number, contact: ContactInfo) => {
    const matchedSession = sessionRowByUsername.get(contact.username)
    const canExport = Boolean(matchedSession?.hasSession)
    const checked = canExport && selectedSessions.has(contact.username)
    const isRunning = canExport && runningSessionIds.has(contact.username)
    const isQueued = canExport && queuedSessionIds.has(contact.username)
    const recent = canExport ? formatRecentExportTime(lastExportBySession[contact.username], nowTick) : ''
    const countedMessages = normalizeMessageCount(sessionMessageCounts[contact.username])
    const hintedMessages = normalizeMessageCount(matchedSession?.messageCountHint)
    const displayedMessageCount = countedMessages ?? hintedMessages
    const messageCountLabel = !canExport
      ? '--'
      : typeof displayedMessageCount === 'number'
        ? displayedMessageCount.toLocaleString('zh-CN')
        : '获取中'
    return (
      <div className={`contact-row ${checked ? 'selected' : ''}`}>
        <div className="contact-item">
          <div className="row-select-cell">
            <button
              className={`select-icon-btn ${checked ? 'checked' : ''}`}
              type="button"
              disabled={!canExport}
              onClick={() => toggleSelectSession(contact.username)}
              title={canExport ? (checked ? '取消选择' : '选择会话') : '该联系人暂无会话记录'}
            >
              {checked ? <CheckSquare size={16} /> : <Square size={16} />}
            </button>
          </div>
          <div className="contact-avatar">
            {contact.avatarUrl ? (
              <img src={contact.avatarUrl} alt="" loading="lazy" />
            ) : (
              <span>{getAvatarLetter(contact.displayName)}</span>
            )}
          </div>
          <div className="contact-info">
            <div className="contact-name">{contact.displayName}</div>
            <div className="contact-remark">{contact.username}</div>
          </div>
          <div className="row-message-count">
            <div className="row-message-stats">
              <strong className={`row-message-count-value ${typeof displayedMessageCount === 'number' ? '' : 'muted'}`}>
                {messageCountLabel}
              </strong>
            </div>
          </div>
          <div className="row-action-cell">
            <div className="row-action-main">
              <button
                className="row-open-chat-btn"
                disabled={!canExport}
                title={canExport ? '在新窗口打开该会话' : '该联系人暂无会话记录'}
                onClick={() => {
                  if (!canExport) return
                  void window.electronAPI.window.openSessionChatWindow(contact.username)
                }}
              >
                <ExternalLink size={13} />
                打开对话
              </button>
              <button
                className={`row-detail-btn ${showSessionDetailPanel && sessionDetail?.wxid === contact.username ? 'active' : ''}`}
                onClick={() => openSessionDetail(contact.username)}
              >
                详情
              </button>
              <button
                className={`row-export-btn ${isRunning ? 'running' : ''} ${!canExport ? 'no-session' : ''}`}
                disabled={!canExport || isRunning}
                onClick={() => {
                  if (!matchedSession || !matchedSession.hasSession) return
                  openSingleExport({
                    ...matchedSession,
                    displayName: contact.displayName || matchedSession.displayName || matchedSession.username
                  })
                }}
              >
                {isRunning ? (
                  <>
                    <Loader2 size={14} className="spin" />
                    导出中
                  </>
                ) : !canExport ? '暂无会话' : isQueued ? '排队中' : '单会话导出'}
              </button>
            </div>
            {recent && <span className="row-export-time">{recent}</span>}
          </div>
        </div>
      </div>
    )
  }, [
    lastExportBySession,
    nowTick,
    openSessionDetail,
    openSingleExport,
    queuedSessionIds,
    runningSessionIds,
    selectedSessions,
    sessionDetail?.wxid,
    sessionMessageCounts,
    sessionRowByUsername,
    showSessionDetailPanel,
    toggleSelectSession
  ])
  const handleBackToTop = useCallback(() => {
    contactsVirtuosoRef.current?.scrollToIndex({ index: 0, align: 'start', behavior: 'smooth' })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])
  const handleContactsListWheelCapture = useCallback((event: WheelEvent<HTMLDivElement>) => {
    const deltaY = event.deltaY
    if (!deltaY) return
    const sectionTop = sessionTableSectionRef.current?.getBoundingClientRect().top ?? 0
    const sectionPinned = sectionTop <= 8

    if (deltaY > 0 && !sectionPinned) {
      event.preventDefault()
      window.scrollBy({ top: deltaY, behavior: 'auto' })
      return
    }

    if (deltaY < 0 && isContactsListAtTop) {
      event.preventDefault()
      window.scrollBy({ top: deltaY, behavior: 'auto' })
    }
  }, [isContactsListAtTop])
  useEffect(() => {
    if (hasFilteredContacts) return
    setIsContactsListAtTop(true)
  }, [hasFilteredContacts])
  const chooseExportFolder = useCallback(async () => {
    const result = await window.electronAPI.dialog.openFile({
      title: '选择导出目录',
      properties: ['openDirectory']
    })
    if (!result.canceled && result.filePaths.length > 0) {
      const nextPath = result.filePaths[0]
      setExportFolder(nextPath)
      await configService.setExportPath(nextPath)
    }
  }, [])

  return (
    <div className="export-board-page">
      <div className="export-top-panel">
        <div className="global-export-controls">
          <div className="path-control">
            <span className="control-label">导出位置</span>
            <div className="path-inline-row">
              <div className="path-value">
                <button
                  className="path-link"
                  type="button"
                  title={exportFolder}
                  onClick={() => void chooseExportFolder()}
                >
                  {exportFolder || '未设置'}
                </button>
                <button className="path-change-btn" type="button" onClick={() => void chooseExportFolder()}>
                  更换
                </button>
              </div>
              <button className="secondary-btn" onClick={() => exportFolder && void window.electronAPI.shell.openPath(exportFolder)}>
                <ExternalLink size={14} /> 打开
              </button>
            </div>
          </div>

          <WriteLayoutSelector
            writeLayout={writeLayout}
            onChange={async (value) => {
              setWriteLayout(value)
              await configService.setExportWriteLayout(value)
            }}
            sessionNameWithTypePrefix={sessionNameWithTypePrefix}
            onSessionNameWithTypePrefixChange={async (enabled) => {
              setSessionNameWithTypePrefix(enabled)
              await configService.setExportSessionNamePrefixEnabled(enabled)
            }}
          />

          <div className="task-center-control">
            <span className="control-label">任务中心</span>
            <div className="task-center-inline">
              <div className="task-summary">
                <span>进行中 {taskRunningCount}</span>
                <span>排队 {taskQueuedCount}</span>
                <span>总计 {tasks.length}</span>
              </div>
              <button
                className={`task-open-btn ${taskRunningCount > 0 ? 'active-running' : ''}`}
                type="button"
                onClick={() => setIsTaskCenterOpen(true)}
              >
                任务卡片
                {taskRunningCount > 0 && <span className="task-running-badge">{taskRunningCount}</span>}
              </button>
            </div>
          </div>
        </div>
      </div>

      <TaskCenterModal
        isOpen={isTaskCenterOpen}
        tasks={tasks}
        taskRunningCount={taskRunningCount}
        taskQueuedCount={taskQueuedCount}
        expandedPerfTaskId={expandedPerfTaskId}
        nowTick={nowTick}
        onClose={closeTaskCenter}
        onTogglePerfTask={toggleTaskPerfDetail}
      />

      <div className="export-section-title-row">
        <h3 className="export-section-title">按类型批量导出</h3>
        <SectionInfoTooltip
          label="按类型批量导出"
          heading="按类型批量导出说明"
          messages={[
            '按数据类型统一导出，适合横向汇总同类内容，比如集中导出图片、语音或视频。',
            '发起前可先设置导出时间范围和格式，能减少无关数据，导出结果更聚焦。',
            '每个类型卡片中展示到已导出会话数，统计范围会涵盖下方按会话导出。'
          ]}
        />
      </div>
      <div className="content-card-grid">
        {contentCards.map(card => {
          const Icon = card.icon
          const isCardStatsLoading = card.type === 'sns'
            ? isSnsCardStatsLoading
            : false
          const isCardRunning = runningCardTypes.has(card.type)
          return (
            <div key={card.type} className="content-card">
              <div className="card-header">
                <div className="card-title"><Icon size={16} /> {card.label}</div>
                {card.type === 'sns' && (
                  <div className="card-title-meta">
                    {isCardStatsLoading ? (
                      <span className="count-loading">
                        统计中<span className="animated-ellipsis" aria-hidden="true">...</span>
                      </span>
                    ) : `${card.headerCount.toLocaleString()} 条`}
                  </div>
                )}
              </div>
              <div className="card-stats">
                {card.stats.map((stat) => (
                  <div key={stat.label} className="stat-item">
                    <span>{stat.label}</span>
                    <strong>
                      {isCardStatsLoading ? (
                        <span className="count-loading">
                          统计中<span className="animated-ellipsis" aria-hidden="true">...</span>
                        </span>
                      ) : `${stat.value.toLocaleString()} ${stat.unit}`}
                    </strong>
                  </div>
                ))}
              </div>
              <button
                className={`card-export-btn ${isCardRunning ? 'running' : ''}`}
                disabled={isCardRunning}
                onClick={() => {
                  if (card.type === 'sns') {
                    openSnsExport()
                    return
                  }
                  openContentExport(card.type)
                }}
              >
                {isCardRunning ? (
                  <>
                    <span>批量导出中</span>
                    <Loader2 size={14} className="spin" />
                  </>
                ) : '批量导出'}
              </button>
            </div>
          )
        })}
      </div>

      <div className="export-section-title-row">
        <h3 className="export-section-title">按会话导出</h3>
        <SectionInfoTooltip
          label="按会话导出"
          heading="按会话导出说明"
          messages={[
            '按会话维度导出完整上下文，适合按客户、项目或群组进行归档。',
            '你可以先在列表中筛选目标会话，再批量导出，结果会保留每个会话的结构与时间线。'
          ]}
        />
      </div>
      <div className="session-table-section" ref={sessionTableSectionRef}>
        <div className="session-table-layout">
          <div className="table-wrap">
            <div className="session-table-sticky">
              <div className="table-toolbar">
                <div className="table-tabs" role="tablist" aria-label="会话类型">
                  <button className={`tab-btn ${activeTab === 'private' ? 'active' : ''}`} onClick={() => setActiveTab('private')}>
                    私聊 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.private}
                  </button>
                  <button className={`tab-btn ${activeTab === 'group' ? 'active' : ''}`} onClick={() => setActiveTab('group')}>
                    群聊 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.group}
                  </button>
                  <button className={`tab-btn ${activeTab === 'official' ? 'active' : ''}`} onClick={() => setActiveTab('official')}>
                    公众号 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.official}
                  </button>
                  <button className={`tab-btn ${activeTab === 'former_friend' ? 'active' : ''}`} onClick={() => setActiveTab('former_friend')}>
                    曾经的好友 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.former_friend}
                  </button>
                </div>

                <div className="toolbar-actions">
                  <div className="search-input-wrap">
                    <Search size={14} />
                    <input
                      value={searchKeyword}
                      onChange={(event) => setSearchKeyword(event.target.value)}
                      placeholder={`搜索${activeTabLabel}联系人...`}
                    />
                    {searchKeyword && (
                      <button className="clear-search" onClick={() => setSearchKeyword('')}>
                        <X size={12} />
                      </button>
                    )}
                  </div>
                  <button className="secondary-btn" onClick={() => void loadContactsList()} disabled={isContactsListLoading}>
                    <RefreshCw size={14} className={isContactsListLoading ? 'spin' : ''} />
                    刷新
                  </button>
                </div>
              </div>

              {contactsList.length > 0 && isContactsListLoading && (
                <div className="table-stage-hint">
                  <Loader2 size={14} className="spin" />
                  联系人列表同步中…
                </div>
              )}

              {hasFilteredContacts && (
                <div className="contacts-list-header">
                  <span className="contacts-list-header-select">
                    <button
                      className={`select-icon-btn ${isAllVisibleSelected ? 'checked' : ''}`}
                      type="button"
                      onClick={toggleSelectAllVisible}
                      disabled={visibleSelectableCount === 0}
                      title={isAllVisibleSelected ? '取消全选当前筛选联系人' : '全选当前筛选联系人'}
                    >
                      {isAllVisibleSelected ? <CheckSquare size={16} /> : <Square size={16} />}
                    </button>
                  </span>
                  <span className="contacts-list-header-main">
                    <span className="contacts-list-header-main-label">联系人（头像/名称/微信号）</span>
                  </span>
                  <span className="contacts-list-header-count">总消息数</span>
                  <span className="contacts-list-header-actions">
                    {selectedCount > 0 && (
                      <>
                        <button
                          className="selection-clear-btn"
                          type="button"
                          onClick={clearSelection}
                        >
                          清空
                        </button>
                        <button
                          className="selection-export-btn"
                          type="button"
                          onClick={openBatchExport}
                        >
                          <span>批量导出</span>
                          <span className="selection-export-count">{selectedCount}</span>
                        </button>
                      </>
                    )}
                  </span>
                </div>
              )}
            </div>

            {contactsList.length === 0 && contactsLoadIssue ? (
              <div className="load-issue-state">
                <div className="issue-card">
                  <div className="issue-title">
                    <AlertTriangle size={18} />
                    <span>{contactsLoadIssue.title}</span>
                  </div>
                  <p className="issue-message">{contactsLoadIssue.message}</p>
                  <p className="issue-reason">{contactsLoadIssue.reason}</p>
                  <ul className="issue-hints">
                    <li>可能原因1：数据库当前仍在执行高开销查询（例如导出页后台统计）。</li>
                    <li>可能原因2：contact.db 数据量较大，首次查询时间过长。</li>
                    <li>可能原因3：数据库连接状态异常或 IPC 调用卡住。</li>
                  </ul>
                  <div className="issue-actions">
                    <button className="issue-btn primary" onClick={() => void loadContactsList()}>
                      <RefreshCw size={14} />
                      <span>重试加载</span>
                    </button>
                    <button className="issue-btn" onClick={() => setShowContactsDiagnostics(prev => !prev)}>
                      <ClipboardList size={14} />
                      <span>{showContactsDiagnostics ? '收起诊断详情' : '查看诊断详情'}</span>
                    </button>
                    <button className="issue-btn" onClick={copyContactsDiagnostics}>
                      <span>复制诊断信息</span>
                    </button>
                  </div>
                  {showContactsDiagnostics && (
                    <pre className="issue-diagnostics">{contactsDiagnosticsText}</pre>
                  )}
                </div>
              </div>
            ) : isContactsListLoading && contactsList.length === 0 ? (
              <div className="loading-state">
                <Loader2 size={32} className="spin" />
                <span>联系人加载中...</span>
              </div>
            ) : !hasFilteredContacts ? (
              <div className="empty-state">
                <span>暂无联系人</span>
              </div>
            ) : (
              <div
                className="contacts-list"
                onWheelCapture={handleContactsListWheelCapture}
              >
                <Virtuoso
                  ref={contactsVirtuosoRef}
                  className="contacts-virtuoso"
                  data={filteredContacts}
                  computeItemKey={(_, contact) => contact.username}
                  itemContent={renderContactRow}
                  atTopStateChange={setIsContactsListAtTop}
                  overscan={420}
                />
              </div>
            )}
          </div>

          {showSessionDetailPanel && (
            <div
              className="export-session-detail-overlay"
              onClick={closeSessionDetailPanel}
            >
              <aside
                className="export-session-detail-panel"
                role="dialog"
                aria-modal="true"
                aria-label="会话详情"
                onClick={(event) => event.stopPropagation()}
              >
              <div className="detail-header">
                <div className="detail-header-main">
                  <div className="detail-header-avatar">
                    {sessionDetail?.avatarUrl ? (
                      <img src={sessionDetail.avatarUrl} alt="" />
                    ) : (
                      <span>{getAvatarLetter(sessionDetail?.displayName || sessionDetail?.wxid || '')}</span>
                    )}
                  </div>
                  <div className="detail-header-meta">
                    <h4>{sessionDetail?.displayName || '会话详情'}</h4>
                    <div className="detail-header-id">{sessionDetail?.wxid || ''}</div>
                  </div>
                </div>
                <button className="close-btn" onClick={closeSessionDetailPanel}>
                  <X size={16} />
                </button>
              </div>
              {isLoadingSessionDetail && !sessionDetail ? (
                <div className="detail-loading">
                  <Loader2 size={20} className="spin" />
                  <span>加载中...</span>
                </div>
              ) : sessionDetail ? (
                <div className="detail-content">
                  <div className="detail-section">
                    <div className="detail-item">
                      <Hash size={14} />
                      <span className="label">微信ID</span>
                      <span className="value">{sessionDetail.wxid}</span>
                      <button className="copy-btn" title="复制" onClick={() => void handleCopyDetailField(sessionDetail.wxid, 'wxid')}>
                        {copiedDetailField === 'wxid' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                    {sessionDetail.remark && (
                      <div className="detail-item">
                        <span className="label">备注</span>
                        <span className="value">{sessionDetail.remark}</span>
                        <button className="copy-btn" title="复制" onClick={() => void handleCopyDetailField(sessionDetail.remark || '', 'remark')}>
                          {copiedDetailField === 'remark' ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    )}
                    {sessionDetail.nickName && (
                      <div className="detail-item">
                        <span className="label">昵称</span>
                        <span className="value">{sessionDetail.nickName}</span>
                        <button className="copy-btn" title="复制" onClick={() => void handleCopyDetailField(sessionDetail.nickName || '', 'nickName')}>
                          {copiedDetailField === 'nickName' ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    )}
                    {sessionDetail.alias && (
                      <div className="detail-item">
                        <span className="label">微信号</span>
                        <span className="value">{sessionDetail.alias}</span>
                        <button className="copy-btn" title="复制" onClick={() => void handleCopyDetailField(sessionDetail.alias || '', 'alias')}>
                          {copiedDetailField === 'alias' ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="detail-section">
                    <div className="section-title">
                      <ClipboardList size={14} />
                      <span>导出记录（最近 20 条）</span>
                    </div>
                    {currentSessionExportRecords.length === 0 ? (
                      <div className="detail-record-empty">暂无导出记录</div>
                    ) : (
                      <div className="detail-record-list">
                        {currentSessionExportRecords.map((record, index) => (
                          <div className="detail-record-item" key={`${record.exportTime}-${record.content}-${index}`}>
                            <div className="record-row">
                              <span className="label">导出时间</span>
                              <span className="value">{formatYmdHmDateTime(record.exportTime)}</span>
                            </div>
                            <div className="record-row">
                              <span className="label">导出内容</span>
                              <span className="value">{record.content}</span>
                            </div>
                            <div className="record-row">
                              <span className="label">导出目录</span>
                              <span className="value path" title={record.outputDir}>{formatPathBrief(record.outputDir)}</span>
                              <button
                                className="detail-inline-btn"
                                type="button"
                                onClick={() => void window.electronAPI.shell.openPath(record.outputDir)}
                              >
                                打开
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="detail-section">
                    <div className="section-title">
                      <MessageSquare size={14} />
                      <span>消息统计（导出口径）</span>
                    </div>
                    <div className="detail-stats-meta">
                      {isRefreshingSessionDetailStats
                        ? '统计刷新中...'
                        : sessionDetail.statsUpdatedAt
                          ? `${sessionDetail.statsStale ? '缓存于' : '更新于'} ${formatYmdHmDateTime(sessionDetail.statsUpdatedAt)}${sessionDetail.statsStale ? '（将后台刷新）' : ''}`
                          : (isLoadingSessionDetailExtra ? '统计加载中...' : '暂无统计缓存')}
                    </div>
                    <div className="detail-item">
                      <span className="label">消息总数</span>
                      <span className="value highlight">
                        {Number.isFinite(sessionDetail.messageCount)
                          ? sessionDetail.messageCount.toLocaleString()
                          : ((isLoadingSessionDetail || isLoadingSessionDetailExtra) ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">语音</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.voiceMessages)
                          ? (sessionDetail.voiceMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">图片</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.imageMessages)
                          ? (sessionDetail.imageMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">视频</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.videoMessages)
                          ? (sessionDetail.videoMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">表情包</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.emojiMessages)
                          ? (sessionDetail.emojiMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">转账消息数</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.transferMessages)
                          ? (sessionDetail.transferMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">红包消息数</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.redPacketMessages)
                          ? (sessionDetail.redPacketMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="label">通话消息数</span>
                      <span className="value">
                        {Number.isFinite(sessionDetail.callMessages)
                          ? (sessionDetail.callMessages as number).toLocaleString()
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    {sessionDetail.wxid.includes('@chatroom') ? (
                      <>
                        <div className="detail-item">
                          <span className="label">我发的消息数</span>
                          <span className="value">
                            {Number.isFinite(sessionDetail.groupMyMessages)
                              ? (sessionDetail.groupMyMessages as number).toLocaleString()
                              : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                          </span>
                        </div>
                        <div className="detail-item">
                          <span className="label">群人数</span>
                          <span className="value">
                            {Number.isFinite(sessionDetail.groupMemberCount)
                              ? (sessionDetail.groupMemberCount as number).toLocaleString()
                              : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                          </span>
                        </div>
                        <div className="detail-item">
                          <span className="label">群发言人数</span>
                          <span className="value">
                            {Number.isFinite(sessionDetail.groupActiveSpeakers)
                              ? (sessionDetail.groupActiveSpeakers as number).toLocaleString()
                              : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                          </span>
                        </div>
                        <div className="detail-item">
                          <span className="label">群共同好友数</span>
                          <span className="value">
                            {sessionDetail.relationStatsLoaded
                              ? (Number.isFinite(sessionDetail.groupMutualFriends)
                                ? (sessionDetail.groupMutualFriends as number).toLocaleString()
                                : '—')
                              : (
                                <button
                                  className="detail-inline-btn"
                                  onClick={() => { void loadSessionRelationStats() }}
                                  disabled={isLoadingSessionRelationStats || isLoadingSessionDetailExtra}
                                >
                                  {isLoadingSessionRelationStats ? '加载中...' : '点击加载'}
                                </button>
                              )}
                          </span>
                        </div>
                      </>
                    ) : (
                      <div className="detail-item">
                        <span className="label">共同群聊数</span>
                        <span className="value">
                          {sessionDetail.relationStatsLoaded
                            ? (Number.isFinite(sessionDetail.privateMutualGroups)
                              ? (sessionDetail.privateMutualGroups as number).toLocaleString()
                              : '—')
                            : (
                              <button
                                className="detail-inline-btn"
                                onClick={() => { void loadSessionRelationStats() }}
                                disabled={isLoadingSessionRelationStats || isLoadingSessionDetailExtra}
                              >
                                {isLoadingSessionRelationStats ? '加载中...' : '点击加载'}
                              </button>
                            )}
                        </span>
                      </div>
                    )}
                    <div className="detail-item">
                      <Calendar size={14} />
                      <span className="label">首条消息</span>
                      <span className="value">
                        {sessionDetail.firstMessageTime
                          ? formatYmdDateFromSeconds(sessionDetail.firstMessageTime)
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                    <div className="detail-item">
                      <Calendar size={14} />
                      <span className="label">最新消息</span>
                      <span className="value">
                        {sessionDetail.latestMessageTime
                          ? formatYmdDateFromSeconds(sessionDetail.latestMessageTime)
                          : (isLoadingSessionDetailExtra ? '统计中...' : '—')}
                      </span>
                    </div>
                  </div>

                  <div className="detail-section">
                    <div className="section-title">
                      <Database size={14} />
                      <span>数据库分布</span>
                    </div>
                    {Array.isArray(sessionDetail.messageTables) && sessionDetail.messageTables.length > 0 ? (
                      <div className="table-list">
                        {sessionDetail.messageTables.map((table, index) => (
                          <div key={`${table.dbName}-${table.tableName}-${index}`} className="table-item">
                            <span className="db-name">{table.dbName}</span>
                            <span className="table-count">{table.count.toLocaleString()} 条</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="detail-table-placeholder">
                        {isLoadingSessionDetailExtra ? '统计中...' : '暂无统计数据'}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="detail-empty">暂无详情</div>
              )}
              </aside>
            </div>
          )}
        </div>
      </div>

      {showBackToTop && (
        <button
          type="button"
          className="back-to-top-btn"
          onClick={handleBackToTop}
        >
          回到顶部
        </button>
      )}

      {exportDialog.open && createPortal(
        <div className="export-dialog-overlay" onClick={closeExportDialog}>
          <div className="export-dialog" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="dialog-header">
              <h3>{exportDialog.title}</h3>
              <button className="close-icon-btn" onClick={closeExportDialog}><X size={16} /></button>
            </div>

            <div className="dialog-body">
              <div className="dialog-section">
                <h4>导出范围</h4>
                <div className="scope-tag-row">
                  <span className="scope-tag">{scopeLabel}</span>
                  <span className="scope-count">{scopeCountLabel}</span>
                </div>
                <div className="scope-list">
                  {exportDialog.sessionNames.slice(0, 20).map(name => (
                    <span key={name} className="scope-item">{name}</span>
                  ))}
                  {exportDialog.sessionNames.length > 20 && <span className="scope-item">... 还有 {exportDialog.sessionNames.length - 20} 个</span>}
                </div>
              </div>

              {shouldShowFormatSection && (
                <div className="dialog-section">
                  <h4>{exportDialog.scope === 'sns' ? '朋友圈导出格式选择' : '对话文本导出格式选择'}</h4>
                  {isContentTextDialog && (
                    <div className="format-note">说明：此模式默认导出头像，不导出图片、语音、视频、表情包等媒体内容。</div>
                  )}
                  <div className="format-grid">
                    {formatCandidateOptions.map(option => (
                      <button
                        key={option.value}
                        className={`format-card ${exportDialog.scope === 'sns'
                          ? (snsExportFormat === option.value ? 'active' : '')
                          : (options.format === option.value ? 'active' : '')}`}
                        onClick={() => {
                          if (exportDialog.scope === 'sns') {
                            setSnsExportFormat(option.value as SnsTimelineExportFormat)
                          } else {
                            setOptions(prev => ({ ...prev, format: option.value as TextExportFormat }))
                          }
                        }}
                      >
                        <div className="format-label">{option.label}</div>
                        <div className="format-desc">{option.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="dialog-section">
                <div className="section-header-action">
                  <h4>时间范围</h4>
                  <button
                    type="button"
                    className="time-range-trigger"
                    onClick={openTimeRangeDialog}
                  >
                    <span>{timeRangeSummaryLabel}</span>
                    <span className="time-range-arrow">&gt;</span>
                  </button>
                </div>
              </div>

              {shouldShowMediaSection && (
                <div className="dialog-section">
                  <h4>{exportDialog.scope === 'sns' ? '媒体文件（可多选）' : '媒体与头像'}</h4>
                  <div className="media-check-grid">
                    {exportDialog.scope === 'sns' ? (
                      <>
                        <label><input type="checkbox" checked={snsExportImages} onChange={event => setSnsExportImages(event.target.checked)} /> 图片</label>
                        <label><input type="checkbox" checked={snsExportLivePhotos} onChange={event => setSnsExportLivePhotos(event.target.checked)} /> 实况图</label>
                        <label><input type="checkbox" checked={snsExportVideos} onChange={event => setSnsExportVideos(event.target.checked)} /> 视频</label>
                      </>
                    ) : (
                      <>
                        <label><input type="checkbox" checked={options.exportImages} onChange={event => setOptions(prev => ({ ...prev, exportImages: event.target.checked }))} /> 图片</label>
                        <label><input type="checkbox" checked={options.exportVoices} onChange={event => setOptions(prev => ({ ...prev, exportVoices: event.target.checked }))} /> 语音</label>
                        <label><input type="checkbox" checked={options.exportVideos} onChange={event => setOptions(prev => ({ ...prev, exportVideos: event.target.checked }))} /> 视频</label>
                        <label><input type="checkbox" checked={options.exportEmojis} onChange={event => setOptions(prev => ({ ...prev, exportEmojis: event.target.checked }))} /> 表情包</label>
                        <label><input type="checkbox" checked={options.exportVoiceAsText} onChange={event => setOptions(prev => ({ ...prev, exportVoiceAsText: event.target.checked }))} /> 语音转文字</label>
                        <label><input type="checkbox" checked={options.exportAvatars} onChange={event => setOptions(prev => ({ ...prev, exportAvatars: event.target.checked }))} /> 导出头像</label>
                      </>
                    )}
                  </div>
                  {exportDialog.scope === 'sns' && (
                    <div className="format-note">全不勾选时仅导出文本信息，不导出媒体文件。</div>
                  )}
                </div>
              )}

              {shouldShowDisplayNameSection && (
                <div className="dialog-section">
                  <h4>发送者名称显示</h4>
                  <div className="display-name-options" role="radiogroup" aria-label="发送者名称显示">
                    {displayNameOptions.map(option => {
                      const isActive = options.displayNamePreference === option.value
                      return (
                        <button
                          key={option.value}
                          type="button"
                          role="radio"
                          aria-checked={isActive}
                          className={`display-name-item ${isActive ? 'active' : ''}`}
                          onClick={() => setOptions(prev => ({ ...prev, displayNamePreference: option.value }))}
                        >
                          <span>{option.label}</span>
                          <small>{option.desc}</small>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>

            <div className="dialog-actions">
              <button className="secondary-btn" onClick={closeExportDialog}>取消</button>
              <button className="primary-btn" onClick={() => void createTask()} disabled={!canCreateTask}>
                <Download size={14} /> 创建导出任务
              </button>
            </div>

            {isTimeRangeDialogOpen && (
              <div className="time-range-dialog-overlay" onClick={closeTimeRangeDialog}>
                <div className="time-range-dialog" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
                  <div className="time-range-dialog-header">
                    <h4>时间范围设置</h4>
                    <button
                      type="button"
                      className="close-icon-btn"
                      onClick={closeTimeRangeDialog}
                      aria-label="关闭时间范围设置"
                    >
                      <X size={14} />
                    </button>
                  </div>

                  <div className="time-range-preset-list">
                    {([
                      { value: 'all', label: '全部时间' },
                      { value: 'today', label: '今天' },
                      { value: 'yesterday', label: '昨天' },
                      { value: 'last3days', label: '最近3天' },
                      { value: 'last7days', label: '最近一周' },
                      { value: 'last30days', label: '最近30 天' },
                      { value: 'last1year', label: '最近一年' }
                    ] as Array<{ value: Exclude<DateRangePreset, 'custom'>; label: string }>).map((preset) => {
                      const isActive = isTimeRangePresetActive(preset.value)
                      return (
                        <button
                          key={preset.value}
                          type="button"
                          className={`time-range-preset-item ${isActive ? 'active' : ''}`}
                          onClick={() => handleTimeRangePresetClick(preset.value)}
                        >
                          <span>{preset.label}</span>
                          {isActive && <Check size={14} />}
                        </button>
                      )
                    })}
                  </div>

                  <div className={`time-range-mode-banner ${isRangeModeActive ? 'range' : 'all'}`}>
                    {timeRangeModeText}
                  </div>

                  <div className="time-range-calendar-grid">
                    <section className="time-range-calendar-panel">
                      <div className="time-range-calendar-panel-header">
                        <div className="time-range-calendar-date-label">
                          <span>起始日期</span>
                          <input
                            type="text"
                            className={`time-range-date-input ${timeRangeDateInputError.start ? 'invalid' : ''}`}
                            value={timeRangeDateInput.start}
                            placeholder="YYYY-MM-DD"
                            onChange={(event) => {
                              const nextValue = event.target.value
                              setTimeRangeDateInput(prev => ({ ...prev, start: nextValue }))
                              if (timeRangeDateInputError.start) {
                                setTimeRangeDateInputError(prev => ({ ...prev, start: false }))
                              }
                            }}
                            onKeyDown={(event) => {
                              if (event.key !== 'Enter') return
                              event.preventDefault()
                              commitTimeRangeStartFromInput()
                            }}
                            onBlur={() => {
                              commitTimeRangeStartFromInput()
                            }}
                          />
                        </div>
                        <div className="time-range-calendar-nav">
                          <button type="button" onClick={() => shiftTimeRangePanelMonth('start', -1)} aria-label="上个月">‹</button>
                          <span>{formatCalendarMonthTitle(activeTimeRangeDialogDraft.startPanelMonth)}</span>
                          <button type="button" onClick={() => shiftTimeRangePanelMonth('start', 1)} aria-label="下个月">›</button>
                        </div>
                      </div>
                      <div className="time-range-calendar-weekdays">
                        {WEEKDAY_SHORT_LABELS.map(label => (
                          <span key={`start-weekday-${label}`}>{label}</span>
                        ))}
                      </div>
                      <div className="time-range-calendar-days">
                        {startPanelCells.map((cell) => {
                          const isSelected = !activeTimeRangeDialogDraft.useAllTime &&
                            isSameDay(cell.date, activeTimeRangeDialogDraft.dateRange.start)
                          return (
                            <button
                              key={`start-${cell.date.getTime()}`}
                              type="button"
                              className={`time-range-calendar-day ${cell.inCurrentMonth ? '' : 'outside'} ${isSelected ? 'selected' : ''}`}
                              onClick={() => updateTimeRangeDraftStart(cell.date)}
                            >
                              {cell.date.getDate()}
                            </button>
                          )
                        })}
                      </div>
                    </section>

                    <section className="time-range-calendar-panel">
                      <div className="time-range-calendar-panel-header">
                        <div className="time-range-calendar-date-label">
                          <span>截止日期</span>
                          <input
                            type="text"
                            className={`time-range-date-input ${timeRangeDateInputError.end ? 'invalid' : ''}`}
                            value={timeRangeDateInput.end}
                            placeholder="YYYY-MM-DD"
                            onChange={(event) => {
                              const nextValue = event.target.value
                              setTimeRangeDateInput(prev => ({ ...prev, end: nextValue }))
                              if (timeRangeDateInputError.end) {
                                setTimeRangeDateInputError(prev => ({ ...prev, end: false }))
                              }
                            }}
                            onKeyDown={(event) => {
                              if (event.key !== 'Enter') return
                              event.preventDefault()
                              commitTimeRangeEndFromInput()
                            }}
                            onBlur={() => {
                              commitTimeRangeEndFromInput()
                            }}
                          />
                        </div>
                        <div className="time-range-calendar-nav">
                          <button type="button" onClick={() => shiftTimeRangePanelMonth('end', -1)} aria-label="上个月">‹</button>
                          <span>{formatCalendarMonthTitle(activeTimeRangeDialogDraft.endPanelMonth)}</span>
                          <button type="button" onClick={() => shiftTimeRangePanelMonth('end', 1)} aria-label="下个月">›</button>
                        </div>
                      </div>
                      <div className="time-range-calendar-weekdays">
                        {WEEKDAY_SHORT_LABELS.map(label => (
                          <span key={`end-weekday-${label}`}>{label}</span>
                        ))}
                      </div>
                      <div className="time-range-calendar-days">
                        {endPanelCells.map((cell) => {
                          const isSelected = !activeTimeRangeDialogDraft.useAllTime &&
                            isSameDay(cell.date, activeTimeRangeDialogDraft.dateRange.end)
                          return (
                            <button
                              key={`end-${cell.date.getTime()}`}
                              type="button"
                              className={`time-range-calendar-day ${cell.inCurrentMonth ? '' : 'outside'} ${isSelected ? 'selected' : ''}`}
                              onClick={() => updateTimeRangeDraftEnd(cell.date)}
                            >
                              {cell.date.getDate()}
                            </button>
                          )
                        })}
                      </div>
                    </section>
                  </div>

                  <div className="time-range-dialog-actions">
                    <button type="button" className="secondary-btn" onClick={closeTimeRangeDialog}>
                      取消
                    </button>
                    <button type="button" className="primary-btn" onClick={commitTimeRangeDialogDraft}>
                      确认
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default ExportPage
