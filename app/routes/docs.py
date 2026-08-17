"""Public documentation.

Read-only and unauthenticated. Both handlers go through `docs_service`
functions that can only return published pages, so there is no predicate here
for a future edit to drop and no path by which a draft becomes public.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.deps import DbSession, OptionalUser
from app.markdown import render_markdown
from app.services.docs_service import get_published, list_public
from app.templating import render

router = APIRouter(tags=["docs"])


@router.get("/docs")
async def docs_index(request: Request, db: DbSession, user: OptionalUser):
    pages = await list_public(db)
    return render(
        request,
        "docs/index.html",
        {
            "page_title": "Documentation",
            "pages": pages,
        },
    )


@router.get("/docs/{slug}")
async def docs_page(request: Request, db: DbSession, user: OptionalUser, slug: str):
    page = await get_published(db, slug)
    if page is None:
        # A draft and a non-existent page are indistinguishable from outside,
        # which is what makes "unpublished" mean anything.
        raise HTTPException(status_code=404, detail="That page doesn't exist.")

    pages = await list_public(db)
    return render(
        request,
        "docs/page.html",
        {
            "page_title": page.title,
            "page": page,
            "pages": pages,
            "body_html": render_markdown(page.content),
        },
    )
