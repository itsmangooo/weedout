import { Component } from "react";
import { AlertTriangle } from "lucide-react";
import { Link, isRouteErrorResponse, useRouteError } from "react-router";

import { Button } from "../ui/Button";
import { InlineNotice } from "../ui/InlineNotice";

function FatalError({ children, message, onReset }) {
  return (
    <main className="fatal-error" id="main">
      <div className="fatal-error__inner">
        <p className="eyebrow">Weedout / interface</p>
        <h1>The interface hit an unexpected error.</h1>
        <InlineNotice icon={AlertTriangle} title="This view could not render" tone="danger">
          <p>{message}</p>
        </InlineNotice>
        {onReset ? <Button onClick={onReset}>Try rendering again</Button> : null}
        {children}
      </div>
    </main>
  );
}

export class AppErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <FatalError
          message="This view could not be shown. Your account data has not been changed."
          onReset={() => this.setState({ error: null })}
        />
      );
    }

    return this.props.children;
  }
}

export function RouteErrorBoundary() {
  const error = useRouteError();
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error?.message || "The requested page could not be rendered.";

  return (
    <FatalError message={message}>
      <Link className="text-link" to="/">
        Return to the foundation
      </Link>
    </FatalError>
  );
}
