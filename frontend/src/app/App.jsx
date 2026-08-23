import { Outlet } from "react-router";

import { useDocumentTitle } from "./useDocumentTitle";

export function App() {
  // One place, reading `handle.title` off whichever route matched. A per-page
  // hook would leave a stale title behind on any page that forgot to call it.
  useDocumentTitle();

  return <Outlet />;
}
