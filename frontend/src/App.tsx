import { Navigate, Route, Routes } from 'react-router-dom';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { AnalysisPage } from './pages/AnalysisPage';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/policies" element={<PoliciesPage />} />
        <Route path="/analyses/:id" element={<AnalysisPage />} />
      </Route>
      <Route path="/" element={<Navigate to="/policies" replace />} />
    </Routes>
  );
}

export default App;
