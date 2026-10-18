import type { ApiError, CreateScanRequest, ScanReport, ScanStatusResponse } from './types'

const configuredBase = (import.meta.env.VITE_API_BASE_URL ?? '').trim()
export const API_BASE_URL = configuredBase.replace(/\/$/, '')

function detailMessage(detail: unknown): string {
  if (typeof detail === 'string' && detail.trim()) return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') return item
        if (typeof item === 'object' && item !== null && 'msg' in item) {
          return String((item as { msg?: unknown }).msg ?? '')
        }
        return ''
      })
      .filter(Boolean)
    if (messages.length) return messages.join(' ')
  }
  return ''
}

function endpoint(path: string): string {
  return `${API_BASE_URL}${path}`
}

async function request<T>(path: string, init?: RequestInit, parse?: (response: Response) => Promise<T>): Promise<T> {
  let response: Response
  try {
    response = await fetch(endpoint(path), {
      ...init,
      headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to reach the SENTINEL API.'
    throw { message } satisfies ApiError
  }

  if (!response.ok) {
    const contentType = response.headers.get('content-type') ?? ''
    const payload: unknown = contentType.includes('application/json') ? await response.json() : await response.text()
    const detail = typeof payload === 'object' && payload !== null && 'detail' in payload
      ? detailMessage((payload as { detail?: unknown }).detail)
      : ''
    throw { message: detail || `Request failed with status ${response.status}.`, status: response.status } satisfies ApiError
  }
  if (parse) return parse(response)
  const contentType = response.headers.get('content-type') ?? ''
  return (contentType.includes('application/json') ? await response.json() : await response.text()) as T
}

export function createScan(input: CreateScanRequest, signal?: AbortSignal): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>('/scans', {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(`/scans/${encodeURIComponent(scanId)}`, { signal })
}

export function getScanReportJson(scanId: string, signal?: AbortSignal): Promise<ScanReport> {
  return request<ScanReport>(`/scans/${encodeURIComponent(scanId)}/report?format=json`, { signal })
}

export function getScanReportMarkdown(scanId: string, signal?: AbortSignal): Promise<string> {
  return request<string>(
    `/scans/${encodeURIComponent(scanId)}/report?format=markdown`,
    { signal, headers: { Accept: 'text/markdown' } },
    (response) => response.text(),
  )
}

export function cancelScan(scanId: string, signal?: AbortSignal): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(`/scans/${encodeURIComponent(scanId)}/cancel`, {
    method: 'POST',
    signal,
  })
}
