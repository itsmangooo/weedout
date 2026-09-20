import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../../../app/queryClient";
import { dashboardQueryKey } from "../../dashboard/hooks/useDashboard";
import { openFindingsQueryKey } from "../../findings/hooks/useOpenFindings";
import {
  LIVE_UPDATE_EVENT,
  LIVE_UPDATES_PATH,
  useLiveDashboardUpdates,
} from "./useLiveDashboardUpdates";

class MockEventSource {
  static instances = [];

  constructor(url, options) {
    this.url = url;
    this.options = options;
    this.listeners = new Map();
    this.addEventListener = vi.fn((type, listener) => {
      this.listeners.set(type, listener);
    });
    this.removeEventListener = vi.fn((type, listener) => {
      if (this.listeners.get(type) === listener) {
        this.listeners.delete(type);
      }
    });
    this.close = vi.fn();
    MockEventSource.instances.push(this);
  }

  emit(type, data = "{}") {
    this.listeners.get(type)?.({ data });
  }
}

function LiveHarness() {
  const status = useLiveDashboardUpdates();
  return <span>{status}</span>;
}

function renderLiveHook() {
  const client = createQueryClient({ queries: { retry: false } });
  const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue(undefined);
  const view = render(
    <QueryClientProvider client={client}>
      <LiveHarness />
    </QueryClientProvider>,
  );
  return { ...view, client, invalidate, source: MockEventSource.instances[0] };
}

describe("dashboard live query refresh", () => {
  beforeEach(() => {
    MockEventSource.instances = [];
    vi.stubGlobal("EventSource", MockEventSource);
  });

  it("opens one credentialed stream and reflects native reconnect state", () => {
    const { source } = renderLiveHook();

    expect(MockEventSource.instances).toHaveLength(1);
    expect(source.url).toBe(LIVE_UPDATES_PATH);
    expect(source.options).toEqual({ withCredentials: true });
    expect(source.addEventListener).toHaveBeenCalledTimes(3);

    act(() => source.emit("open"));
    expect(screen.getByText("live")).toBeInTheDocument();

    act(() => source.emit("error"));
    expect(screen.getByText("reconnecting")).toBeInTheDocument();
    expect(MockEventSource.instances).toHaveLength(1);
  });

  it("invalidates the dashboard query when stats change", async () => {
    const { invalidate, source } = renderLiveHook();

    act(() => source.emit(LIVE_UPDATE_EVENT));

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: dashboardQueryKey }),
    );
  });

  it("invalidates the open findings query when stats change", async () => {
    const { invalidate, source } = renderLiveHook();

    act(() => source.emit(LIVE_UPDATE_EVENT));

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: openFindingsQueryKey }),
    );
  });

  it("removes every listener and closes EventSource on unmount", () => {
    const { source, unmount } = renderLiveHook();

    unmount();

    expect(source.removeEventListener).toHaveBeenCalledTimes(3);
    expect(source.listeners.size).toBe(0);
    expect(source.close).toHaveBeenCalledTimes(1);
  });
});
