import React, { useState } from 'react';
import { api } from '../services/api';
import { Shield, Eye, EyeOff, KeyRound, Mail, Info } from 'lucide-react';
import ForgotPassword from './ForgotPassword';

export default function Auth({ onAuthSuccess }) {
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [step, setStep] = useState(1); // 1 = credentials, 2 = TOTP/MFA verify
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [qrCode, setQrCode] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleCredentialsSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isLogin) {
        const data = await api.login(email, password);
        setStep(2);
        setQrCode(data.qr_code);
        setTotpSecret(data.totp_secret);
        setTotpEnabled(data.totp_enabled);
      } else {
        await api.register(email, password);
        setIsLogin(true);
        setError('Account created successfully! Please log in to configure MFA.');
      }
    } catch (err) {
      setError(err.message || 'Incorrect credentials');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.verifyOtp(email, otpCode);
      onAuthSuccess(data);
    } catch (err) {
      setError(err.message || 'Invalid authenticator code');
    } finally {
      setLoading(false);
    }
  };

  if (showForgotPassword) {
    return <ForgotPassword onBackToLogin={() => setShowForgotPassword(false)} />;
  }

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      width: '100%',
      padding: '20px'
    }}>
      <div className="glass-card" style={{
        width: '100%',
        maxWidth: '440px',
        padding: '40px',
        boxShadow: '0 20px 50px rgba(0,0,0,0.5)',
        border: '1px solid rgba(255, 255, 255, 0.08)'
      }}>
        {/* Logo Header */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          marginBottom: '28px'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
            padding: '12px',
            borderRadius: '12px',
            boxShadow: '0 0 20px var(--cyan-glow)',
            marginBottom: '16px'
          }}>
            <Shield size={32} color="#040810" />
          </div>
          <h2 style={{ fontSize: '24px', fontWeight: 800 }}>ANTIGRAVITY</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '4px' }}>
            {step === 1 ? 'Ransomware Protection Platform' : 'Two-Factor Authentication (MFA)'}
          </p>
        </div>

        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            borderRadius: '8px',
            padding: '12px',
            color: '#ef4444',
            fontSize: '14px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <Info size={16} />
            <span>{error}</span>
          </div>
        )}

        {step === 1 ? (
          /* Credentials Screen */
          <form onSubmit={handleCredentialsSubmit}>
            <div className="input-group">
              <label className="input-label">Email Address</label>
              <div style={{ position: 'relative' }}>
                <Mail size={18} color="var(--text-muted)" style={{
                  position: 'absolute',
                  left: '14px',
                  top: '50%',
                  transform: 'translateY(-50%)'
                }} />
                <input
                  type="email"
                  required
                  placeholder="name@domain.com"
                  className="text-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{ width: '100%', paddingLeft: '44px' }}
                />
              </div>
            </div>

            <div className="input-group">
              <label className="input-label">Password</label>
              <div style={{ position: 'relative' }}>
                <KeyRound size={18} color="var(--text-muted)" style={{
                  position: 'absolute',
                  left: '14px',
                  top: '50%',
                  transform: 'translateY(-50%)'
                }} />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••"
                  className="text-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ width: '100%', paddingLeft: '44px', paddingRight: '44px' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '14px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--text-muted)'
                  }}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              {isLogin && (
                <div style={{ textAlign: 'right', marginTop: '8px' }}>
                  <button
                    type="button"
                    onClick={() => setShowForgotPassword(true)}
                    style={{ background: 'none', border: 'none', color: 'var(--cyan)', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Forgot Password?
                  </button>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', marginTop: '8px' }}
            >
              {loading ? 'Processing...' : isLogin ? 'Login Securely' : 'Register Account'}
            </button>

            <div style={{ textAlign: 'center', marginTop: '24px' }}>
              <button
                type="button"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setError('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--cyan)',
                  fontSize: '14px',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                {isLogin ? "Don't have an account? Sign up" : 'Already have an account? Log in'}
              </button>
            </div>
          </form>
        ) : (
          /* MFA Verification Screen */
          <form onSubmit={handleOtpSubmit}>
            {/* Show QR Code only if TOTP is not yet enabled (i.e. first time setup) */}
            {!totpEnabled ? (
              <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                  🔒 Scan the QR code below with **Google Authenticator** to link your secure account:
                </p>
                {qrCode && (
                  <div style={{
                    background: '#ffffff',
                    padding: '12px',
                    borderRadius: '12px',
                    display: 'inline-block',
                    boxShadow: '0 0 25px rgba(255, 255, 255, 0.1)',
                    marginBottom: '16px'
                  }}>
                    <img 
                      src={qrCode} 
                      alt="Google Authenticator QR Code" 
                      style={{ display: 'block', width: '180px', height: '180px' }}
                    />
                  </div>
                )}
                <div style={{
                  fontSize: '12px',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px dashed var(--border-color)',
                  borderRadius: '6px',
                  padding: '8px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-secondary)',
                  wordBreak: 'break-all'
                }}>
                  Key: {totpSecret}
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                  🔑 Enter the 6-digit verification code displayed in your **Google Authenticator** app:
                </p>
              </div>
            )}

            <div className="input-group">
              <input
                type="text"
                maxLength={6}
                required
                placeholder="000000"
                className="text-input"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                style={{ 
                  width: '100%', 
                  textAlign: 'center', 
                  fontSize: '24px', 
                  letterSpacing: '8px',
                  fontWeight: 700 
                }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%' }}
            >
              {loading ? 'Authenticating...' : 'Verify TOTP & Log In'}
            </button>

            <div style={{ textAlign: 'center', marginTop: '24px' }}>
              <button
                type="button"
                onClick={() => {
                  setStep(1);
                  setOtpCode('');
                  setQrCode('');
                  setTotpSecret('');
                  setError('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  fontSize: '14px',
                  fontWeight: 500,
                  cursor: 'pointer'
                }}
              >
                ← Back to credentials
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
