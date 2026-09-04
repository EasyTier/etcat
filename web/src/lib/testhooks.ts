// Compatibility surface for the EasyTier browser smoke harness. The harness
// drives the page with ?mode=listen|send, ?sink=hash, ?relay=, ?relayKey= and
// polls window.etcatTest; keep every field and query parameter intact.

import { reactive } from "vue";

export interface EtcatTestState {
  ready: boolean;
  listenToken: string | null;
  recvBytes: number;
  recvHash: string | null;
  recvDone: boolean;
  sentBytes: number;
  sentHash: string | null;
  sentDone: boolean;
  errors: string[];
}

declare global {
  interface Window {
    etcatTest: EtcatTestState;
  }
}

export const testState = reactive<EtcatTestState>({
  ready: false,
  listenToken: null,
  recvBytes: 0,
  recvHash: null,
  recvDone: false,
  sentBytes: 0,
  sentHash: null,
  sentDone: false,
  errors: [],
});

export function recordError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  testState.errors.push(message);
  return message;
}

export function installTestHooks(): void {
  window.etcatTest = testState;
  window.addEventListener("error", (event) => {
    testState.errors.push(String(event.message));
  });
  window.addEventListener("unhandledrejection", (event) => {
    testState.errors.push(
      event.reason instanceof Error ? event.reason.message : String(event.reason),
    );
  });
}

export interface QueryAutomation {
  mode: "listen" | "send" | null;
  token: string | null;
  bytes: number | null;
  sinkHash: boolean;
}

export function queryAutomation(): QueryAutomation {
  const params = new URLSearchParams(window.location.search);
  const modeParameter = params.get("mode");
  const bytesParameter = params.get("bytes");
  return {
    mode: modeParameter === "listen" || modeParameter === "send"
      ? modeParameter
      : null,
    token: params.get("token"),
    bytes: bytesParameter === null || bytesParameter.length === 0
      ? null
      : Number(bytesParameter),
    sinkHash: params.get("sink") === "hash",
  };
}
