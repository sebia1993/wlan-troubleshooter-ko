"""JavaScript와 외부 참조를 허용하지 않는 단일 HTML 보고서."""

from html.parser import HTMLParser
import re
from typing import List, Optional, Sequence, Tuple


_BLOCKED_TAGS = {"script", "iframe", "object", "embed", "base", "link", "form"}
_ALLOWED_TAGS = {
    "a",
    "article",
    "body",
    "br",
    "caption",
    "code",
    "col",
    "colgroup",
    "dd",
    "div",
    "dl",
    "dt",
    "em",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hr",
    "html",
    "img",
    "li",
    "main",
    "meta",
    "ol",
    "p",
    "pre",
    "section",
    "small",
    "span",
    "strong",
    "style",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "title",
    "tr",
    "ul",
}
_VOID_TAGS = {"br", "col", "hr", "img", "meta"}
_GLOBAL_ATTRIBUTES = {"class", "dir", "id", "lang", "role", "style", "title"}
_TAG_ATTRIBUTES = {
    "a": {"href"},
    "col": {"span"},
    "img": {"alt", "height", "src", "width"},
    "meta": {"charset", "content", "http-equiv"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
}
_URI_ATTRIBUTES = {"src", "href", "action", "formaction", "poster", "data", "srcset"}
_BLOCKED_SCHEMES = tuple(
    name + ":" for name in ("http", "https", "ws", "wss", "ftp", "file", "javascript")
)
_DATA_IMAGE_PATTERN = re.compile(
    r"(?i)^data:image/(?:png|jpeg|gif|webp);base64,[a-z0-9+/]+={0,2}$"
)
_REQUIRED_CSP_PARTS = (
    "default-src 'none'",
    "connect-src 'none'",
    "img-src data:",
    "style-src 'unsafe-inline'",
    "script-src 'none'",
    "font-src 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
)
_REQUIRED_CSP = {
    part.split(None, 1)[0]: part.split(None, 1)[1] for part in _REQUIRED_CSP_PARTS
}


class OfflineHtmlError(ValueError):
    """보고서가 오프라인 단일 파일 정책을 위반한 경우."""


def _contains_blocked_scheme(value: str) -> bool:
    lowered = value.casefold()
    return any(scheme in lowered for scheme in _BLOCKED_SCHEMES) or "//" in lowered


def _validate_css(value: str) -> None:
    lowered = value.casefold()
    if (
        "\\" in value
        or "/*" in value
        or "*/" in value
        or "@" in value
        or '"' in value
        or "'" in value
    ):
        raise OfflineHtmlError("CSS escape, 주석, at-rule은 허용하지 않습니다.")
    if any(token in lowered for token in ("expression(", "behavior:", "-moz-binding")):
        raise OfflineHtmlError("실행 가능한 CSS 표현은 허용하지 않습니다.")
    if re.search(r"url\s*\(", lowered):
        raise OfflineHtmlError("CSS url 표현식은 허용하지 않습니다.")
    if any(
        token in lowered
        for token in ("image(", "image-set(", "-webkit-image-set(", "cross-fade(", "element(")
    ):
        raise OfflineHtmlError("외부 이미지를 참조할 수 있는 CSS 함수는 허용하지 않습니다.")


class _OfflineParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.errors: List[str] = []
        self.csp: Optional[str] = None
        self.csp_count = 0
        self.doctype_count = 0
        self._style_depth = 0
        self._stack: List[str] = []
        self._head_content_seen = False
        self._tag_counts = {"html": 0, "head": 0, "body": 0}
        self._head_closed = False
        self._body_closed = False

    def _inspect_topology(self, tag: str) -> None:
        if tag == "html":
            if self._stack or self._tag_counts["html"] or self.doctype_count != 1:
                self.errors.append("html은 문서형 선언 직후의 단일 루트여야 합니다.")
            return
        if tag == "head":
            if self._stack != ["html"] or self._head_closed or self._tag_counts["body"]:
                self.errors.append("head는 html의 첫 번째 자식이어야 합니다.")
            return
        if tag == "body":
            if self._stack != ["html"] or not self._head_closed or self._body_closed:
                self.errors.append("body는 닫힌 head 다음의 html 자식이어야 합니다.")
            return
        if not self._stack or self._stack[0] != "html":
            self.errors.append("모든 요소는 단일 html 루트 내부에 있어야 합니다.")
            return
        if self._stack[-1] == "html":
            self.errors.append("html의 직접 자식은 head와 body만 허용합니다.")
            return
        if "head" in self._stack:
            if tag not in {"meta", "style", "title"} or self._stack[-1] != "head":
                self.errors.append("head에는 meta, style, title만 직접 배치할 수 있습니다.")
        elif "body" not in self._stack:
            self.errors.append("콘텐츠 요소는 body 내부에 있어야 합니다.")

    def _inspect_tag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        normalized_tag = tag.casefold()
        self._inspect_topology(normalized_tag)
        if normalized_tag in _BLOCKED_TAGS:
            self.errors.append("금지된 HTML 태그: " + normalized_tag)
        if normalized_tag not in _ALLOWED_TAGS:
            self.errors.append("허용되지 않은 HTML 태그: " + normalized_tag)
        if normalized_tag in self._tag_counts:
            self._tag_counts[normalized_tag] += 1

        attributes = {}
        for raw_name, raw_value in attrs:
            name = raw_name.casefold()
            if name in attributes:
                self.errors.append("중복 HTML 속성은 허용하지 않습니다: " + name)
                continue
            attributes[name] = raw_value or ""
            allowed = (
                name in _GLOBAL_ATTRIBUTES
                or name in _TAG_ATTRIBUTES.get(normalized_tag, set())
                or name.startswith("aria-")
            )
            if ":" in name or not allowed:
                self.errors.append("허용되지 않은 HTML 속성: " + name)
        if normalized_tag == "meta":
            directive = attributes.get("http-equiv", "").casefold()
            if directive == "refresh":
                self.errors.append("meta refresh는 허용하지 않습니다.")
            if directive == "content-security-policy":
                self.csp_count += 1
                self.csp = attributes.get("content", "")
                if not self._stack or self._stack[-1] != "head":
                    self.errors.append("Content Security Policy는 head 내부에 있어야 합니다.")
                if self._head_content_seen:
                    self.errors.append("Content Security Policy는 head의 첫 콘텐츠여야 합니다.")

        for name, value in attributes.items():
            if name.startswith("on"):
                self.errors.append("이벤트 처리 속성은 허용하지 않습니다: " + name)
            local_name = name.rsplit(":", 1)[-1]
            if local_name in _URI_ATTRIBUTES:
                lowered = value.strip().casefold()
                allowed = local_name == "href" and lowered.startswith("#")
                allowed = allowed or (
                    local_name == "src" and bool(_DATA_IMAGE_PATTERN.fullmatch(value.strip()))
                )
                if value and not allowed:
                    self.errors.append("외부 또는 파일 참조 속성은 허용하지 않습니다: " + name)
            if name == "style":
                try:
                    _validate_css(value)
                except OfflineHtmlError as exc:
                    self.errors.append(str(exc))
            if _contains_blocked_scheme(value):
                self.errors.append("URI 스킴이 포함된 속성은 허용하지 않습니다: " + name)

        if normalized_tag == "style":
            if self.csp_count != 1:
                self.errors.append("style보다 먼저 Content Security Policy가 필요합니다.")
            self._style_depth += 1

        if self._stack and self._stack[-1] == "head":
            is_csp = (
                normalized_tag == "meta"
                and attributes.get("http-equiv", "").casefold() == "content-security-policy"
            )
            if not is_csp:
                self._head_content_seen = True
        if normalized_tag == "body" and self.csp_count != 1:
            self.errors.append("body보다 먼저 Content Security Policy가 필요합니다.")

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        self._inspect_tag(tag, attrs)
        normalized_tag = tag.casefold()
        if normalized_tag not in _VOID_TAGS:
            self._stack.append(normalized_tag)

    def handle_startendtag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        self._inspect_tag(tag, attrs)
        normalized_tag = tag.casefold()
        if normalized_tag not in _VOID_TAGS:
            self.errors.append("비어 있지 않은 HTML 요소를 축약 종료할 수 없습니다.")
        if normalized_tag == "style":
            self._style_depth = max(0, self._style_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.casefold()
        if normalized_tag == "style":
            self._style_depth = max(0, self._style_depth - 1)
        if not self._stack or self._stack[-1] != normalized_tag:
            self.errors.append("HTML 태그 중첩이 올바르지 않습니다: " + normalized_tag)
            return
        self._stack.pop()
        if normalized_tag == "head":
            self._head_closed = True
        elif normalized_tag == "body":
            self._body_closed = True
        elif normalized_tag == "html" and not self._body_closed:
            self.errors.append("html 종료 전에 body가 정확히 닫혀야 합니다.")

    def handle_data(self, data: str) -> None:
        if data.strip() and not self._stack:
            self.errors.append("html 루트 밖의 텍스트는 허용하지 않습니다.")
        if data.strip() and self._stack and self._stack[-1] == "head":
            self.errors.append("head 직접 텍스트는 허용하지 않습니다.")
        if self._stack and self._stack[-1] == "head" and data.strip() and self.csp_count == 0:
            self._head_content_seen = True
        if self._style_depth:
            try:
                _validate_css(data)
            except OfflineHtmlError as exc:
                self.errors.append(str(exc))

    def handle_comment(self, data: str) -> None:
        self.errors.append("HTML 주석은 허용하지 않습니다.")

    def handle_decl(self, declaration: str) -> None:
        if declaration.strip().casefold() != "doctype html":
            self.errors.append("HTML5 문서형 선언만 허용합니다.")
        if self.doctype_count or self._stack or any(self._tag_counts.values()):
            self.errors.append("문서형 선언은 문서의 첫 번째 항목이어야 합니다.")
        self.doctype_count += 1

    def handle_pi(self, data: str) -> None:
        self.errors.append("처리 명령은 허용하지 않습니다.")

    def unknown_decl(self, data: str) -> None:
        self.errors.append("알 수 없는 선언은 허용하지 않습니다.")


def validate_offline_html(document: str) -> None:
    """외부 통신, 스크립트, 폼, 프레임이 없는지 실패-폐쇄형으로 검사한다."""

    if _contains_blocked_scheme(document):
        raise OfflineHtmlError("보고서 전체에 금지된 URI 스킴이 포함돼 있습니다.")
    parser = _OfflineParser()
    try:
        parser.feed(document)
        parser.close()
    except Exception as exc:
        raise OfflineHtmlError("HTML을 안전하게 해석할 수 없습니다.") from exc
    if parser.errors:
        raise OfflineHtmlError("; ".join(sorted(set(parser.errors))))
    if (
        parser._stack
        or parser.doctype_count != 1
        or parser._tag_counts != {"html": 1, "head": 1, "body": 1}
        or not parser._head_closed
        or not parser._body_closed
    ):
        raise OfflineHtmlError(
            "HTML5 문서형과 html, head, body 구조가 정확히 한 번씩 필요합니다."
        )
    if parser.csp is None or parser.csp_count != 1:
        raise OfflineHtmlError("정확히 한 개의 Content Security Policy가 필요합니다.")
    directives = {}
    for raw_directive in parser.csp.split(";"):
        tokens = raw_directive.strip().casefold().split(None, 1)
        if not tokens:
            continue
        name = tokens[0]
        value = tokens[1] if len(tokens) == 2 else ""
        if name in directives:
            raise OfflineHtmlError("Content Security Policy 지시문이 중복됐습니다.")
        directives[name] = value
    if directives != _REQUIRED_CSP:
        raise OfflineHtmlError("Content Security Policy가 정확한 필수 차단 규칙과 다릅니다.")
