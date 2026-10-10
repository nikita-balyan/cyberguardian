import axios from 'axios'

const API_BASE_URL = 'http://127.0.0.1:8000/api/v1'

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
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
    const response = await apiClient.post('/scan/batch', { items, scan_type: scanType }, { timeout: 180000 })
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
    return new Error(error.response.data?.detail || `Server error: ${error.response.status}`)
  } else if (error.request) {
    return new Error('Unable to reach CyberGuardian backend. Please ensure FastAPI server is running at http://127.0.0.1:8000.')
  } else {
    return new Error(error.message || 'An unexpected error occurred during scan.')
  }
}

