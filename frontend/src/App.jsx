import React, { useState, useEffect, useRef } from 'react';
import { api } from './services/api';
import Navbar from './components/Navbar';
import Auth from './components/Auth';
import DashboardOverview from './components/DashboardOverview';
import ThreatCenter from './components/ThreatCenter';
import DeviceTrust from './components/DeviceTrust';
import Reports from './components/Reports';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(api.isAuthenticated());
  const [userEmail, setUserEmail] = useState(localStorage.getItem('email') || '');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const pollingRef = useRef(null);

  useEffect(() => {
    if (isAuthenticated) {
      fetchUserContext();
      loadDashboardSummary();
      startPolling();
    } else {
      stopPolling();
    }
    return () => stopPolling();
  }, [isAuthenticated]);

  const fetchUserContext = async () => {
    try {
      const user = await api.getMe();
      setUserEmail(user.email);
    } catch (err) {
      console.error("Session expired or invalid: ", err);
      handleLogout();
    }
  };

  const loadDashboardSummary = async () => {
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err) {
      console.error("Failed to load summary: ", err);
    }
  };

  const startPolling = () => {
    stopPolling();
    // Poll dashboard summaries every 5 seconds for near-real-time agent logging updates
    pollingRef.current = setInterval(() => {
      loadDashboardSummary();
    }, 5000);
  };

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  const handleAuthSuccess = (data) => {
    setIsAuthenticated(true);
    setUserEmail(data.email);
  };

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
    setUserEmail('');
    setSummary(null);
    setActiveTab('dashboard');
    setSelectedEventId(null);
  };

  if (!isAuthenticated) {
    return <Auth onAuthSuccess={handleAuthSuccess} />;
  }

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <Navbar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        handleLogout={handleLogout}
        userEmail={userEmail}
      />

      {/* Main Workspace Frame */}
      <div className="main-content">
        {activeTab === 'dashboard' && (
          <DashboardOverview 
            summary={summary}
            loading={!summary}
            setActiveTab={setActiveTab}
            setSelectedEventId={setSelectedEventId}
          />
        )}

        {activeTab === 'threats' && (
          <ThreatCenter 
            selectedEventId={selectedEventId}
            setSelectedEventId={setSelectedEventId}
          />
        )}

        {activeTab === 'devices' && (
          <DeviceTrust />
        )}

        {activeTab === 'reports' && (
          <Reports />
        )}
      </div>
    </div>
  );
}
