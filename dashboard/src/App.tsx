import { Route, Routes } from 'react-router-dom';

import { AppShell } from './components/layout/AppShell';
import { apiConfig } from './config';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { ConfigErrorPage } from './pages/ConfigErrorPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';

/** Route table: the overview, the alerts list, and one alert's detail. */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

export function App() {
  if (!apiConfig.ok) {
    return <ConfigErrorPage reason={apiConfig.reason} />;
  }
  return <AppRoutes />;
}
