const json = async (r) => {
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
};
const send = (method) => (path, body) =>
  fetch("/api" + path, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).then(json);
export const api = { get: (p) => fetch("/api" + p).then(json), post: send("POST"), put: send("PUT"), patch: send("PATCH"), del: send("DELETE") };
