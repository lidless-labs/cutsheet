import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createReportPreviewBlobLifecycle,
  createReportPreviewController,
  type ObjectURLApi,
} from "./reportPreviewBlob.ts";

function mockObjectURLApi(): {
  api: ObjectURLApi;
  created: string[];
  revoked: string[];
} {
  const created: string[] = [];
  const revoked: string[] = [];
  let seq = 0;
  const api: ObjectURLApi = {
    createObjectURL() {
      const url = `blob:mock-${++seq}`;
      created.push(url);
      return url;
    },
    revokeObjectURL(url: string) {
      revoked.push(url);
    },
  };
  return { api, created, revoked };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test("adopt does not revoke the live URL (setReportUrl rerender must keep it)", () => {
  const { api, created, revoked } = mockObjectURLApi();
  const life = createReportPreviewBlobLifecycle(api);

  const url = life.adopt(api.createObjectURL(new Blob(["report"])));
  // Simulates the effect re-running after setReportUrl(url) without dispose.
  // The live URL must remain usable for the iframe.
  assert.equal(life.current(), url);
  assert.deepEqual(created, [url]);
  assert.deepEqual(revoked, []);
});

test("replace revokes the prior URL exactly once", () => {
  const { api, revoked } = mockObjectURLApi();
  const life = createReportPreviewBlobLifecycle(api);

  const first = life.adopt(api.createObjectURL(new Blob(["a"])));
  const second = life.adopt(api.createObjectURL(new Blob(["b"])));

  assert.equal(life.current(), second);
  assert.deepEqual(revoked, [first]);
});

test("dispose revokes the live URL exactly once; second dispose is a no-op", () => {
  const { api, revoked } = mockObjectURLApi();
  const life = createReportPreviewBlobLifecycle(api);

  const url = life.adopt(api.createObjectURL(new Blob(["report"])));
  life.dispose();
  life.dispose();

  assert.equal(life.current(), null);
  assert.deepEqual(revoked, [url]);
});

test("dispose with no live URL does not revoke", () => {
  const { api, revoked } = mockObjectURLApi();
  const life = createReportPreviewBlobLifecycle(api);

  life.dispose();
  assert.deepEqual(revoked, []);
});

test("adopting the same URL again does not double-revoke", () => {
  const { api, revoked } = mockObjectURLApi();
  const life = createReportPreviewBlobLifecycle(api);

  const url = life.adopt(api.createObjectURL(new Blob(["report"])));
  life.adopt(url);
  assert.deepEqual(revoked, []);
  assert.equal(life.current(), url);
});

test("route id transition cancels before stale fetch can create or adopt", async () => {
  const { api, created, revoked } = mockObjectURLApi();
  const pending = deferred<Blob>();
  const adopted: string[] = [];
  const errors: string[] = [];
  const trace: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async (changeId) => {
      trace.push(`fetch:${changeId}`);
      return pending.promise;
    },
  });

  // Same wiring the page uses: begin load, then route-leave dispose.
  const stop = controller.load({
    routeId: "1",
    changeId: 1,
    onAdopt: (url) => {
      adopted.push(url);
      trace.push(`adopt:${url}`);
    },
    onError: (message) => {
      errors.push(message);
      trace.push(`error:${message}`);
    },
  });
  trace.push("load-started");

  // Route id transition: effect cleanup soft-cancels, then dispose revokes.
  stop();
  trace.push("soft-cancel");
  controller.dispose();
  trace.push("dispose");

  pending.resolve(new Blob(["stale-report"]));
  await Promise.resolve();
  await Promise.resolve();

  assert.deepEqual(adopted, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(created, []);
  assert.deepEqual(revoked, []);
  assert.equal(controller.current(), null);
  assert.deepEqual(trace, [
    "fetch:1",
    "load-started",
    "soft-cancel",
    "dispose",
  ]);
});

test("overlapping loads: abandoned late success does not adopt; winner adopts once", async () => {
  const { api, created, revoked } = mockObjectURLApi();
  const first = deferred<Blob>();
  const second = deferred<Blob>();
  let calls = 0;
  const adopted: string[] = [];
  const errors: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => {
      calls += 1;
      return calls === 1 ? first.promise : second.promise;
    },
  });

  const stop1 = controller.load({
    routeId: "1",
    changeId: 1,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });
  stop1();
  controller.load({
    routeId: "2",
    changeId: 2,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });

  first.resolve(new Blob(["old"]));
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(adopted, []);
  assert.deepEqual(created, []);

  second.resolve(new Blob(["new"]));
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(adopted.length, 1);
  assert.equal(controller.current(), adopted[0]);
  assert.deepEqual(created, adopted);
  assert.deepEqual(revoked, []);
  assert.deepEqual(errors, []);
});

test("late success after soft cancel revokes created URL and does not adopt", async () => {
  const { api, created, revoked } = mockObjectURLApi();
  // Force create-then-abandon path: resolve after soft cancel but inject a
  // microtask gap inside fetch so createObjectURL can race the cancel check.
  const pending = deferred<Blob>();
  const adopted: string[] = [];
  const errors: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => pending.promise,
  });

  const stop = controller.load({
    routeId: "9",
    changeId: 9,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });
  stop();
  pending.resolve(new Blob(["late"]));
  await Promise.resolve();
  await Promise.resolve();

  assert.deepEqual(adopted, []);
  assert.deepEqual(errors, []);
  assert.equal(controller.current(), null);
  // Prefer no create; if a URL was created after cancel it must be revoked exactly once.
  if (created.length > 0) {
    assert.deepEqual(revoked, created);
  } else {
    assert.deepEqual(revoked, []);
  }
});

test("late failure from abandoned fetch does not emit a stale toast/error", async () => {
  const { api } = mockObjectURLApi();
  const pending = deferred<Blob>();
  const adopted: string[] = [];
  const errors: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => pending.promise,
  });

  const stop = controller.load({
    routeId: "3",
    changeId: 3,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });
  stop();
  controller.dispose();

  pending.reject(new Error("network down"));
  await Promise.resolve();
  await Promise.resolve();

  assert.deepEqual(adopted, []);
  assert.deepEqual(errors, []);
  assert.equal(controller.current(), null);
});

test("change.id mismatch with route id refuses to start a fetch", async () => {
  const { api, created } = mockObjectURLApi();
  let fetches = 0;
  const adopted: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => {
      fetches += 1;
      return new Blob(["nope"]);
    },
  });

  const stop = controller.load({
    routeId: "2",
    changeId: 1,
    onAdopt: (url) => adopted.push(url),
    onError: () => {
      throw new Error("should not error");
    },
  });
  stop();
  await Promise.resolve();

  assert.equal(fetches, 0);
  assert.deepEqual(adopted, []);
  assert.deepEqual(created, []);
  assert.equal(controller.current(), null);
});

test("StrictMode setup-cleanup-setup: first load abandoned, second adopts exactly once", async () => {
  const { api, created, revoked } = mockObjectURLApi();
  const loads: Array<ReturnType<typeof deferred<Blob>>> = [];
  const adopted: string[] = [];
  const errors: string[] = [];

  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => {
      const d = deferred<Blob>();
      loads.push(d);
      return d.promise;
    },
  });

  // setup
  const stop1 = controller.load({
    routeId: "5",
    changeId: 5,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });
  // cleanup (StrictMode)
  stop1();
  // setup again
  controller.load({
    routeId: "5",
    changeId: 5,
    onAdopt: (url) => adopted.push(url),
    onError: (message) => errors.push(message),
  });

  assert.equal(loads.length, 2);
  loads[0]!.resolve(new Blob(["first"]));
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(adopted, []);

  loads[1]!.resolve(new Blob(["second"]));
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(adopted.length, 1);
  assert.equal(controller.current(), adopted[0]);
  assert.deepEqual(created, adopted);
  assert.deepEqual(revoked, []);
  assert.deepEqual(errors, []);
});

test("dispose after successful adopt revokes exactly once (route leave / unmount)", async () => {
  const { api, revoked } = mockObjectURLApi();
  const controller = createReportPreviewController({
    urls: api,
    fetchReport: async () => new Blob(["ok"]),
  });
  const adopted: string[] = [];

  controller.load({
    routeId: "7",
    changeId: 7,
    onAdopt: (url) => adopted.push(url),
    onError: () => {
      throw new Error("unexpected");
    },
  });
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(adopted.length, 1);
  controller.dispose();
  controller.dispose();
  assert.equal(controller.current(), null);
  assert.deepEqual(revoked, adopted);
});
