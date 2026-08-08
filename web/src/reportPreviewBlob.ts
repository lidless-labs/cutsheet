/** Injectable URL.createObjectURL / revokeObjectURL surface for tests. */
export interface ObjectURLApi {
  createObjectURL(obj: Blob): string;
  revokeObjectURL(url: string): void;
}

/**
 * Owns the single live report-preview blob URL.
 *
 * Contract:
 * - adopt does not revoke the URL just assigned (setState/rerender must keep it live)
 * - adopting a different URL revokes the prior one exactly once
 * - dispose revokes the live URL exactly once (idempotent)
 */
export function createReportPreviewBlobLifecycle(api: ObjectURLApi = URL) {
  let live: string | null = null;

  return {
    current(): string | null {
      return live;
    },

    adopt(url: string): string {
      if (live && live !== url) {
        api.revokeObjectURL(live);
      }
      live = url;
      return url;
    },

    dispose(): void {
      if (live) {
        api.revokeObjectURL(live);
        live = null;
      }
    },
  };
}

export type ReportPreviewBlobLifecycle = ReturnType<
  typeof createReportPreviewBlobLifecycle
>;

export interface ReportPreviewControllerOptions {
  fetchReport: (changeId: number) => Promise<Blob>;
  urls?: ObjectURLApi;
}

export interface ReportPreviewLoadArgs {
  /** Current route param (`/changes/:id`). */
  routeId: string | undefined;
  /** Loaded change id; must match routeId or the load is refused. */
  changeId: number;
  onAdopt: (url: string) => void;
  onError: (message: string) => void;
}

/**
 * Async load/cancel controller used by ChangeDetailPage.
 *
 * Soft cancel (effect cleanup / StrictMode) abandons the in-flight fetch without
 * revoking a still-live iframe URL. dispose() abandons in-flight work and
 * revokes the live URL (route leave / unmount). Late success must not adopt;
 * late failure must not toast.
 */
export function createReportPreviewController(
  options: ReportPreviewControllerOptions,
) {
  const urls = options.urls ?? URL;
  const blob = createReportPreviewBlobLifecycle(urls);
  let active: object | null = null;

  function abandoned(token: object, softCancelled: boolean): boolean {
    return softCancelled || active !== token;
  }

  return {
    current(): string | null {
      return blob.current();
    },

    load(args: ReportPreviewLoadArgs): () => void {
      if (
        args.routeId === undefined ||
        String(args.changeId) !== args.routeId
      ) {
        return () => {};
      }

      const token = {};
      active = token;
      let softCancelled = false;

      void options
        .fetchReport(args.changeId)
        .then((data) => {
          if (abandoned(token, softCancelled)) {
            return;
          }
          const url = urls.createObjectURL(
            new Blob([data], { type: "text/html" }),
          );
          if (abandoned(token, softCancelled)) {
            urls.revokeObjectURL(url);
            return;
          }
          blob.adopt(url);
          args.onAdopt(url);
        })
        .catch((err: unknown) => {
          if (abandoned(token, softCancelled)) {
            return;
          }
          const message = err instanceof Error ? err.message : String(err);
          args.onError(message);
        });

      return () => {
        softCancelled = true;
        if (active === token) {
          active = null;
        }
      };
    },

    dispose(): void {
      active = null;
      blob.dispose();
    },
  };
}

export type ReportPreviewController = ReturnType<
  typeof createReportPreviewController
>;
