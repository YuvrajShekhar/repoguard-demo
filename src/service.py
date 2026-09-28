"""Minimal HTTP service."""

def handler(request):
    # Return a health check response.
    return {"status": "ok"}
