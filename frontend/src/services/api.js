const API_BASE_URL = 'http://localhost:8000/api';

const getHeaders = () => {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

export const api = {
  // Authentication
  register: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Registration failed');
    }
    return response.json();
  },

  login: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Login failed');
    }
    return response.json();
  },

  verifyOtp: async (email, otpCode) => {
    const response = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp_code: otpCode }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Invalid OTP');
    }
    const data = await response.json();
    localStorage.setItem('token', data.access_token);
    localStorage.setItem('email', data.email);
    localStorage.setItem('role', data.role);
    return data;
  },

  getMe: async () => {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) {
      throw new Error('Failed to fetch user context');
    }
    return response.json();
  },

  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    localStorage.removeItem('role');
  },

  isAuthenticated: () => {
    return !!localStorage.getItem('token');
  },

  // Devices
  listDevices: async () => {
    const response = await fetch(`${API_BASE_URL}/devices/`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load devices');
    return response.json();
  },

  getDeviceTrust: async (deviceId) => {
    const response = await fetch(`${API_BASE_URL}/devices/${deviceId}/trust-breakdown`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load trust score breakdown');
    return response.json();
  },

  // Threats
  listThreatEvents: async () => {
    const response = await fetch(`${API_BASE_URL}/threats/events`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load threat events');
    return response.json();
  },

  getThreatDetails: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load event details');
    return response.json();
  },

  updateThreatStatus: async (eventId, status) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/status?status_update=${status}`, {
      method: 'PUT',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to update event status');
    return response.json();
  },

  getThreatExplanation: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/explanation`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load AI explanation');
    return response.json();
  },

  getThreatStoryline: async (eventId) => {
    const response = await fetch(`${API_BASE_URL}/threats/events/${eventId}/storyline`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load attack storyline');
    return response.json();
  },

  // Reports
  getDashboardSummary: async () => {
    const response = await fetch(`${API_BASE_URL}/reports/summary`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to load dashboard statistics');
    return response.json();
  },

  getExportReportUrl: () => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/reports/export-html?token=${token}`; // For opening in new window
  }
};
