import { useRef, useState } from 'react';
import {
  CONFIRM_ACTION_INITIAL_STATE,
  createConfirmActionController
} from './confirmActionController.js';

// React binding for the shared confirm-action controller. Returns the current
// state plus the controller so a page can drive one ConfirmActionModal for any
// provider action (e.g. disabling a provider).
export function useConfirmAction() {
  const [state, setState] = useState(CONFIRM_ACTION_INITIAL_STATE);
  const controllerRef = useRef(null);
  if (!controllerRef.current) {
    controllerRef.current = createConfirmActionController(setState);
  }
  return { state, controller: controllerRef.current };
}
