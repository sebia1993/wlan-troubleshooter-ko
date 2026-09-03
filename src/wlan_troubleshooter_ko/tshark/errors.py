"""TShark 실행 경계의 공개 오류 형식."""


class TSharkExecutionError(RuntimeError):
    """TShark 실행 준비 또는 제한 실행 경계가 안전하지 않은 경우."""
