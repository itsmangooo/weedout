import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/dom";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

class IntersectionObserverMock {
  constructor(callback) {
    this.callback = callback;
  }

  observe(target) {
    this.callback([{ isIntersecting: true, target }], this);
  }

  disconnect() {}
  unobserve() {}
}

globalThis.IntersectionObserver = IntersectionObserverMock;
window.scrollTo = vi.fn();

// Lazy route imports share the worker pool with the rest of the suite. One
// second is tight enough to make a healthy route fail only under full-suite
// load, so assertions get a small deterministic window without changing any
// production timing.
configure({ asyncUtilTimeout: 5000 });

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
