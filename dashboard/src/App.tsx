import { Route, Routes } from 'react-router-dom';

import { AppShell } from './components/layout/AppShell';
import { apiConfig } from './config';
import { ConfigErrorPage } from './pages/ConfigErrorPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';

/**
 * Route table. Later phases add the alerts explorer and the alert detail
 * page here (and enable the matching navigation item in NavBar).
 */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
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
