import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-muted-foreground">404</h1>
        <p className="text-xl mt-4 mb-6">Page not found</p>
        <Link to="/" className="text-primary hover:underline">
          Back to vault
        </Link>
      </div>
    </div>
  )
}
