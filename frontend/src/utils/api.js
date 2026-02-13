import axios from 'axios';
import { API_BASE_URL } from './constants';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('soc_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status, data } = error.response;

      if (status === 401) {
        localStorage.removeItem('soc_token');
        console.warn('[SOC-AI] Authentication expired');
      }

      if (status === 429) {
        console.warn('[SOC-AI] Rate limit reached');
      }

      if (status >= 500) {
        console.error('[SOC-AI] Server error:', data?.detail || 'Unknown error');
      }

      return Promise.reject({
        status,
        message: data?.detail || data?.message || 'An error occurred',
        data,
      });
    }

    if (error.code === 'ECONNABORTED') {
      return Promise.reject({
        status: 408,
        message: 'Request timeout - the server took too long to respond',
      });
    }

    return Promise.reject({
      status: 0,
      message: 'Network error - please check your connection',
    });
  }
);

// API methods
export const investigationAPI = {
  submit: (alertData) => api.post('/api/investigate', alertData),
  submitFile: (formData) =>
    api.post('/api/investigate/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  getAll: (params) => api.get('/api/investigations', { params }),
  getById: (id) => api.get(`/api/investigations/${id}`),
  getReport: (id, format = 'html') =>
    api.get(`/api/investigations/${id}/report`, {
      params: { format },
      responseType: format === 'pdf' ? 'blob' : 'text',
    }),
  delete: (id) => api.delete(`/api/investigations/${id}`),
};

export const dashboardAPI = {
  getStats: () => api.get('/api/dashboard/stats'),
  getVerdictDistribution: () => api.get('/api/dashboard/verdicts'),
  getTimeline: (days = 30) =>
    api.get('/api/dashboard/timeline', { params: { days } }),
  getTopIOCs: (limit = 10) =>
    api.get('/api/dashboard/top-iocs', { params: { limit } }),
  getTopTechniques: (limit = 10) =>
    api.get('/api/dashboard/top-techniques', { params: { limit } }),
  getRecentInvestigations: (limit = 10) =>
    api.get('/api/dashboard/recent', { params: { limit } }),
};

export const iocAPI = {
  getAll: (params) => api.get('/api/iocs', { params }),
  getById: (id) => api.get(`/api/iocs/${id}`),
  search: (query) => api.get('/api/iocs/search', { params: { q: query } }),
  getEnrichment: (id) => api.get(`/api/iocs/${id}/enrichment`),
};

export const mitreAPI = {
  getHeatmap: () => api.get('/api/mitre/heatmap'),
  getTechnique: (id) => api.get(`/api/mitre/techniques/${id}`),
  getTactics: () => api.get('/api/mitre/tactics'),
};

export const analyticsAPI = {
  getTopAttackers: (days = 30) =>
    api.get('/api/analytics/top-attackers', { params: { days } }),
  getTrends: (days = 30) =>
    api.get('/api/analytics/trends', { params: { days } }),
  getSeverityDistribution: () =>
    api.get('/api/analytics/severity-distribution'),
};

export default api;
