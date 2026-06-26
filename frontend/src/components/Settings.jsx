import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { User, Settings as SettingsIcon, Shield, Bell } from 'lucide-react';

export default function Settings() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadUser = async () => {
      try {
        const data = await api.getMe();
        setUser(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    loadUser();
  }, []);

  return (
    <div style={{ padding: '32px', maxWidth: '1000px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '32px' }}>
        <SettingsIcon size={28} color="var(--cyan)" />
        <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>Account Settings</h1>
      </div>

      {loading ? (
        <div style={{ color: 'var(--text-muted)' }}>Loading settings...</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
          {/* Profile Section */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <User size={20} color="var(--text-secondary)" />
              <h2 style={{ fontSize: '18px', color: 'var(--text-main)', margin: 0 }}>Profile details</h2>
            </div>
            
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Email Address</label>
              <div style={{ color: 'var(--text-main)', fontSize: '15px' }}>{user?.email}</div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Role</label>
              <div style={{ display: 'inline-block', background: 'rgba(67, 233, 123, 0.1)', color: '#43e97b', padding: '4px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>
                {user?.role || 'admin'}
              </div>
            </div>
            
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Account Created</label>
              <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
              </div>
            </div>
          </div>

          {/* Security Section */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
              <Shield size={20} color="var(--text-secondary)" />
              <h2 style={{ fontSize: '18px', color: 'var(--text-main)', margin: 0 }}>Security</h2>
            </div>
            
            <div style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ color: 'var(--text-main)', fontSize: '15px', fontWeight: 500 }}>Multi-Factor Authentication</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>Requires a code from an authenticator app.</div>
              </div>
              <div style={{ color: '#43e97b', fontSize: '13px', fontWeight: 600 }}>Enabled</div>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
