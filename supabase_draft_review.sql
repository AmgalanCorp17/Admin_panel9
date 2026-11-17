alter table public.content_drafts
    drop constraint if exists content_drafts_status_check;

alter table public.content_drafts
    add constraint content_drafts_status_check
    check (status in ('draft', 'published', 'rejected'));

grant select, update (status) on table public.content_drafts to service_role;
