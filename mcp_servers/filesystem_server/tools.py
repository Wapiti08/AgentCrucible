from uuid import uuid4

from .audit import JsonlAuditWriter, build_audit_record
from .models import ReadRequest
from .serialization import ReadFileResponse, serialize_read_result
from .service import FileService


class FileTools:
    def __init__(
        self,
        service: FileService,
        audit_writer: JsonlAuditWriter,
    ) -> None:
        self._service = service
        self._audit_writer = audit_writer

    def read_file(self, path: str) -> ReadFileResponse:
        self._audit_writer.ensure_available()

        request = ReadRequest(
            request_id=str(uuid4()),
            original_path=path,
        )

        result = self._service.read(request)

        record = build_audit_record(result)
        self._audit_writer.write(record)

        return serialize_read_result(result)