import React, { createContext, useContext } from 'react';

export const AppConfirmContext = createContext(null);
export const AppFeedbackContext = createContext(null);

export function useAppConfirm() {
  const ctx = useContext(AppConfirmContext);
  if (!ctx) throw new Error('useAppConfirm must be used within AppConfirmProvider');
  return ctx;
}

/**
 * @returns {{
 *   push: Function,
 *   dismiss: Function,
 *   clear: Function,
 *   success: Function,
 *   error: Function,
 *   warning: Function,
 *   info: Function
 * }}
 */
export function useAppFeedback() {
  const ctx = useContext(AppFeedbackContext);
  if (!ctx) throw new Error('useAppFeedback must be used within AppFeedbackProvider');
  return ctx;
}
