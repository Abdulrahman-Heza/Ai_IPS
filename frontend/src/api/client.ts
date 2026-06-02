const BASE = ''

async function request<T>(url: string, options: RequestInit): Promise<T> {
  const res = await fetch(BASE + url, options)
  const data = await res.json()
  if (!res.ok) {
    throw new Error((data as { message?: string }).message ?? `HTTP ${res.status}`)
  }
  return data as T
}

export function apiGet<T>(path: string, token: string): Promise<T> {
  return request<T>(path, {
    headers: { Authorization: `Bearer ${token}` },
  })
}

export function apiPost<T>(path: string, body: unknown, token?: string): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
}

export function apiDelete<T>(path: string, token: string): Promise<T> {
  return request<T>(path, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  })
}
