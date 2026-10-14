import axios from 'axios'

// Set VITE_API_URL in frontend/.env (or as a Docker build arg) when deploying
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1'

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// --- Anonymous per-browser id: the server uses it to show you only YOUR scan history ---
const VISITOR_KEY = 'cg-visitor-id'
let memoryVisitorId = null

// crypto.randomUUID() only exists on https or localhost, so build a v4 UUID ourselves
function newId() {
  const b = crypto.getRandomValues(new Uint8Array(16))
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

function getVisitorId() {
  try {
    let id = localStorage.getItem(VISITOR_KEY)
    if (!id) {
      id = newId()
      localStorage.setItem(VISITOR_KEY, id)
    }
    return id
  } catch {
    // storage blocked (private mode): keep an id for this tab session only
    if (!memoryVisitorId) memoryVisitorId = newId()
    return memoryVisitorId
  }
}

apiClient.interceptors.request.use((config) => {
  config.headers['X-Visitor-Id'] = getVisitorId()
  return config
})

export const checkHealth = async () => {
  const response = await apiClient.get('/health')
  return response.data
}

export const scanUrl = async (url) => {
  try {
    const response = await apiClient.post('/scan/url', { url })
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const scanQrCode = async (file) => {
  try {
    const formData = new FormData()
    formData.append('file', file)
    const response = await apiClient.post('/scan/qr', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const scanMessage = async (message) => {
  try {
    const response = await apiClient.post('/scan/message', { message })
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const scanBatch = async (items, scanType = 'url') => {
  try {
    // A slow 50-item batch can take longer than the default 60 s timeout
    const response = await apiClient.post(
      '/scan/batch',
      { items, scan_type: scanType },
      { timeout: 180000 }
    )
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const getScanHistory = async () => {
  try {
    const response = await apiClient.get('/history')
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const clearHistory = async () => {
  try {
    const response = await apiClient.delete('/history')
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

export const exportPdf = async (scanData) => {
  try {
    const response = await apiClient.post('/export/pdf', scanData, {
      responseType: 'blob',
    })
    return response.data
  } catch (error) {
    throw handleApiError(error)
  }
}

const handleApiError = (error) => {
  if (error.response) {
    const detail = error.response.data?.detail
    if (typeof detail === 'string') return new Error(detail)
    if (error.response.status === 429) return new Error('Too many requests. Please wait a moment and try again.')
    return new Error(`Server error: ${error.response.status}`)
  } else if (error.request) {
    return new Error('Unable to reach the CyberGuardian server. Please check your connection and try again.')
  } else {
    return new Error(error.message || 'An unexpected error occurred during scan.')
  }
}

