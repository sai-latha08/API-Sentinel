import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/common/Navbar';
import Footer from './components/common/Footer';
import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResults from './pages/ScanResults';
import ScanHistory from './pages/ScanHistory';
import ScanCompare from './pages/ScanCompare';
import SecurityReport from './pages/SecurityReport';
import AuthPage from './pages/AuthPage';

export default function App() {
  return (
    <div className="min-h-screen flex flex-col bg-white font-sans text-ink selection:bg-sentinel-100 selection:text-sentinel-900">
      <Navbar />
      <main className="flex-1">
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/:id" element={<ScanResults />} />
          <Route path="/scans" element={<ScanHistory />} />
          <Route path="/compare" element={<ScanCompare />} />
          <Route path="/reports/:id" element={<SecurityReport />} />
          <Route path="/login" element={<AuthPage isRegister={false} />} />
          <Route path="/register" element={<AuthPage isRegister={true} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}
