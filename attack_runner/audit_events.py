from detectors.engine import FileAccessData, SecurityEvent

from .audit_match import AuditedFileRead


def build_file_access_event(
    audited: AuditedFileRead,
) -> SecurityEvent:
    record = audited.audit

    roots = (
        tuple(record.authorized_roots)
        if record.authorized_roots is not None
        else None
    )

    return SecurityEvent(
        event_id=f"{record.request_id}:filesystem.read",
        resource_type="filesystem",
        operation="read",
        data=FileAccessData(
            resolved_path=record.resolved_path,
            authorized_roots=roots,
        ),
    )
