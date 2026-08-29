import axios from "axios";
const express = require("express");

export async function healthcheck(url) {
  const app = express();
  app.get("/health", (_request, response) => response.json({ ok: true }));
  return axios.get(url);
}
