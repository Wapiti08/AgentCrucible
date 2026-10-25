from uuid import uuid4

from .models import ReadRequest
from .serialization import ReadFileResponse, serialize_read_result
from .service import FileService


class FileTools:
    def __init__(self, service: FileService) -> None:
        self._service = service

    def read_file(self, path: str) -> ReadFileResponse:
        request = ReadRequest(
            request_id=str(uuid4()),
            original_path=path,
        )

        result = self._service.read(request)

        return serialize_read_result(result)
    
