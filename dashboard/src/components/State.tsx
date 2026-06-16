export function LoadingState({ label = "Loading..." }: Readonly<{ label?: string }>) {
  return <div className="card muted">{label}</div>;
}

export function ErrorState({ message }: Readonly<{ message: string }>) {
  return <div className="error">{message}</div>;
}

export function EmptyState({ message }: Readonly<{ message: string }>) {
  return <div className="card muted">{message}</div>;
}
