import { useRef, useState } from 'react';
import {
  REMOVE_KEY_INITIAL_STATE,
  createRemoveKeyConfirmController
} from './removeKeyConfirm.js';

// React binding for the shared remove-key confirmation controller. Returns the
// current state plus the controller so the page can open the modal from any
// provider's action bar and render a single ConfirmRemoveKeyModal.
export function useRemoveKeyConfirm() {
  const [state, setState] = useState(REMOVE_KEY_INITIAL_STATE);
  const controllerRef = useRef(null);
  if (!controllerRef.current) {
    controllerRef.current = createRemoveKeyConfirmController(setState);
  }
  return { state, controller: controllerRef.current };
}
