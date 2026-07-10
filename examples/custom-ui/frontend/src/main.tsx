import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { loadConfig } from './config';
import './styles.css';

// Load runtime config (/config.json in deployed mode, VITE_* in local dev)
// BEFORE rendering, so the Cognito user pool can be constructed on demand.
loadConfig().then(() => {
  ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
    <React.StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </React.StrictMode>
  );
});
