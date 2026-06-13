import React from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  AlertOctagon, 
  Smartphone, 
  FileSpreadsheet, 
  LogOut 
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, handleLogout, userEmail }) {
  const navItems = [
    { id: 'dashboard', name: 'Dashboard', icon: LayoutDashboard },
    { id: 'threats', name: 'Threat Center', icon: AlertOctagon },
    { id: 'devices', name: 'Device Trust', icon: Smartphone },
    { id: 'reports', name: 'Reports', icon: FileSpreadsheet },
  ];

  return (
    <div style={{
      width: '260px',
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border-color)',
      padding: '24px',
      display: 'flex',
      flexDirection: 'column',
      position: 'fixed',
      top: 0,
      bottom: 0,
      left: 0,
      zIndex: 10
    }}>
      {/* Brand Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '40px',
        padding: '0 8px'
      }}>
        <div style={{
          background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
          padding: '8px',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 10px var(--cyan-glow)'
        }}>
          <Shield size={22} color="#040810" strokeWidth={2.5} />
        </div>
        <div>
          <h2 style={{
            fontSize: '18px',
            fontWeight: 800,
            letterSpacing: '0.02em',
            background: 'linear-gradient(90deg, #ffffff, #a0aec0)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>ANTIGRAVITY</h2>
          <span style={{
            fontSize: '11px',
            color: 'var(--cyan)',
            fontWeight: 600,
            letterSpacing: '0.1em',
            textTransform: 'uppercase'
          }}>Ransomware Shield</span>
        </div>
      </div>

      {/* Nav List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '14px',
                padding: '12px 16px',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'rgba(79, 172, 254, 0.08)' : 'transparent',
                color: isActive ? 'var(--cyan)' : 'var(--text-secondary)',
                fontFamily: 'var(--font-primary)',
                fontSize: '15px',
                fontWeight: isActive ? 600 : 500,
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'var(--transition)',
                boxShadow: isActive ? 'inset 0 0 0 1px rgba(0, 242, 254, 0.15)' : 'none',
              }}
            >
              <Icon size={20} strokeWidth={isActive ? 2.2 : 1.8} />
              {item.name}
            </button>
          );
        })}
      </div>

      {/* User Session Footer */}
      <div style={{
        borderTop: '1px solid var(--border-color)',
        paddingTop: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px'
      }}>
        <div style={{ padding: '0 8px' }}>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>Signed in as</p>
          <p style={{
            fontSize: '13px',
            color: 'var(--text-main)',
            fontWeight: 600,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            marginTop: '2px'
          }} title={userEmail}>
            {userEmail}
          </p>
        </div>
        <button
          onClick={handleLogout}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 16px',
            borderRadius: '8px',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            background: 'rgba(239, 68, 68, 0.03)',
            color: '#ef4444',
            fontFamily: 'var(--font-primary)',
            fontSize: '14px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'var(--transition)'
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.03)'}
        >
          <LogOut size={16} />
          Sign Out
        </button>
      </div>
    </div>
  );
}
