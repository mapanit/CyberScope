export const API_BASE_URL =
  (process.env.REACT_APP_API_URL || "http://localhost:8000").replace(/\/+$/, "");

export function apiFetch(path, options = {}) {
  const token = localStorage.getItem("token");
  const headers = new Headers(options.headers || {});

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });
}
