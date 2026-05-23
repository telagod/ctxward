use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Read, Write},
};

use bytes::Bytes;
use lopdf::Document as LopdfDocument;
use quick_xml::{
    Reader, Writer,
    events::{BytesCData, BytesText, Event},
};
use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::FileOptions};

use crate::{
    auth::Principal,
    config::AttachmentConfig,
    detect::{DetectionFinding, Detector},
    policy::{PolicyEngine, PolicyOutcome, ResolvedFinding},
    presidio::PresidioAnalyzer,
    redact::{apply_mask, redact_text},
    tokenize::{TokenizationError, Tokenizer},
    types::{DecisionAction, Direction},
};

#[derive(Clone, Debug)]
pub struct AttachmentEngine {
    config: AttachmentPolicyConfig,
}

impl AttachmentEngine {
    pub fn from_config(config: &AttachmentConfig) -> Self {
        Self {
            config: AttachmentPolicyConfig {
                enabled: config.enabled,
                max_bytes: config.max_bytes,
                max_text_chars: config.max_text_chars,
                allowed_media_types: config.allowed_media_types.clone(),
            },
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub async fn scan_request(
        &self,
        deps: AttachmentScanDeps<'_>,
        principal: &Principal,
        body: &Bytes,
        content_type: Option<&str>,
    ) -> Result<Option<AttachmentScanResult>, AttachmentError> {
        let Some(content_type) = content_type else {
            return Ok(None);
        };
        if !self.enabled() || !is_multipart_form(Some(content_type)) {
            return Ok(None);
        }

        let boundary = parse_boundary(content_type).ok_or(AttachmentError::MissingBoundary)?;
        let parts = parse_multipart_parts(body, &boundary)?;
        if parts.is_empty() {
            return Ok(Some(AttachmentScanResult {
                sanitized_body: body.clone(),
                policy: PolicyOutcome {
                    decision: DecisionAction::Allow,
                    findings: Vec::new(),
                    source: "builtin".to_string(),
                    reason: None,
                },
            }));
        }

        let mut attachment_parts = Vec::new();
        let mut findings = Vec::<DetectionFinding>::new();

        for part in parts {
            if !part.is_attachment() {
                attachment_parts.push(ScannedPart {
                    raw: part,
                    pointer: String::new(),
                    rewrite_plan: RewritePlan::None,
                    rewritten_body: None,
                });
                continue;
            }

            let media_type = part.media_type();
            let pointer = format!("/attachments/{}", part.pointer_name());
            if !is_media_type_allowed(&media_type, &self.config.allowed_media_types) {
                attachment_parts.push(ScannedPart {
                    raw: part,
                    pointer,
                    rewrite_plan: RewritePlan::None,
                    rewritten_body: None,
                });
                continue;
            }
            if part.body.len() > self.config.max_bytes {
                return Err(AttachmentError::TooLarge(part.body.len()));
            }

            let content =
                extract_attachment_content(&part.body, &media_type, part.file_name(), &pointer)?;
            findings.extend(
                scan_attachment_content(deps, &content, &pointer, self.config.max_text_chars)
                    .await?,
            );

            attachment_parts.push(ScannedPart {
                raw: part,
                pointer,
                rewrite_plan: RewritePlan::from_content(content),
                rewritten_body: None,
            });
        }

        let mut policy = deps
            .policy_engine
            .resolve(principal, findings, Direction::Request);

        let non_rewritable_sensitive = attachment_parts.iter().any(|part| {
            !part.rewrite_plan.is_rewritable()
                && policy
                    .findings
                    .iter()
                    .any(|finding| finding_targets_part(finding, &part.pointer))
        });

        if non_rewritable_sensitive && policy.decision == DecisionAction::Redact {
            policy.decision = DecisionAction::Review;
            policy.source = "attachment_review_fallback".to_string();
            policy.reason = Some(
                "attachment contains sensitive content that cannot be rewritten safely".to_string(),
            );
        }

        if policy.decision == DecisionAction::Redact {
            for part in &mut attachment_parts {
                match part.rewrite_plan.rewrite(
                    &part.raw.body,
                    &part.pointer,
                    &policy.findings,
                    deps.tokenizer,
                ) {
                    Ok(rewritten) => {
                        part.rewritten_body = rewritten;
                    }
                    Err(AttachmentError::PdfRewrite(_)) => {
                        policy.decision = DecisionAction::Review;
                        policy.source = "attachment_review_fallback".to_string();
                        policy.reason = Some(
                            "attachment contains sensitive content that cannot be rewritten safely"
                                .to_string(),
                        );
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        let sanitized_body = if policy.decision == DecisionAction::Redact {
            rebuild_multipart_body(&boundary, &attachment_parts)
        } else {
            body.clone()
        };

        Ok(Some(AttachmentScanResult {
            sanitized_body,
            policy,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct AttachmentScanResult {
    pub sanitized_body: Bytes,
    pub policy: PolicyOutcome,
}

#[derive(Clone, Copy)]
pub struct AttachmentScanDeps<'a> {
    pub detector: &'a Detector,
    pub presidio: Option<&'a PresidioAnalyzer>,
    pub policy_engine: &'a PolicyEngine,
    pub tokenizer: Option<&'a Tokenizer>,
}

#[derive(Clone, Debug)]
struct AttachmentPolicyConfig {
    enabled: bool,
    max_bytes: usize,
    max_text_chars: usize,
    allowed_media_types: Vec<String>,
}

#[derive(Clone, Debug)]
struct MultipartPart {
    headers: Vec<u8>,
    body: Vec<u8>,
    content_disposition: Option<String>,
    content_type: Option<String>,
}

impl MultipartPart {
    fn is_attachment(&self) -> bool {
        self.file_name().is_some()
    }

    fn file_name(&self) -> Option<&str> {
        self.content_disposition
            .as_deref()
            .and_then(|value| parse_disposition_param(value, "filename"))
    }

    fn part_name(&self) -> Option<&str> {
        self.content_disposition
            .as_deref()
            .and_then(|value| parse_disposition_param(value, "name"))
    }

    fn pointer_name(&self) -> String {
        self.part_name()
            .or_else(|| self.file_name())
            .unwrap_or("file")
            .to_string()
    }

    fn media_type(&self) -> String {
        let declared = self.content_type.as_deref().map(str::trim).unwrap_or("");
        if declared.is_empty()
            || declared.eq_ignore_ascii_case("application/octet-stream")
            || declared.eq_ignore_ascii_case("binary/octet-stream")
        {
            detect_media_type(self.file_name().unwrap_or(""))
        } else {
            declared.to_string()
        }
    }
}

#[derive(Clone, Debug)]
struct ScannedPart {
    raw: MultipartPart,
    pointer: String,
    rewrite_plan: RewritePlan,
    rewritten_body: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
enum RewritePlan {
    None,
    Text,
    Pdf(PdfDocument),
    Ooxml(OoxmlDocument),
}

impl RewritePlan {
    fn from_content(content: AttachmentContent) -> Self {
        match content {
            AttachmentContent::Text(_) => Self::Text,
            AttachmentContent::Pdf(document) => Self::Pdf(document),
            AttachmentContent::Ooxml(document) => Self::Ooxml(document),
            AttachmentContent::ExtractedText(_) | AttachmentContent::None => Self::None,
        }
    }

    fn is_rewritable(&self) -> bool {
        matches!(self, Self::Text | Self::Pdf(_) | Self::Ooxml(_))
    }

    fn rewrite(
        &self,
        raw_body: &[u8],
        part_pointer: &str,
        findings: &[ResolvedFinding],
        tokenizer: Option<&Tokenizer>,
    ) -> Result<Option<Vec<u8>>, AttachmentError> {
        match self {
            Self::None => Ok(None),
            Self::Text => {
                let part_findings = findings
                    .iter()
                    .filter(|finding| finding.pointer == part_pointer)
                    .cloned()
                    .collect::<Vec<_>>();
                if part_findings.is_empty() {
                    return Ok(None);
                }
                let text = String::from_utf8_lossy(raw_body);
                let rewritten = redact_text(&text, &part_findings, tokenizer)?;
                Ok(Some(rewritten.into_bytes()))
            }
            Self::Pdf(document) => document.rewrite(findings, tokenizer),
            Self::Ooxml(document) => document.rewrite(findings, tokenizer),
        }
    }
}

#[derive(Clone, Debug)]
enum AttachmentContent {
    None,
    Text(String),
    ExtractedText(String),
    Pdf(PdfDocument),
    Ooxml(OoxmlDocument),
}

#[derive(Clone, Debug)]
struct PdfDocument {
    original: Vec<u8>,
    pages: Vec<PdfPage>,
}

impl PdfDocument {
    fn rewrite(
        &self,
        findings: &[ResolvedFinding],
        tokenizer: Option<&Tokenizer>,
    ) -> Result<Option<Vec<u8>>, AttachmentError> {
        let mut replacements_by_page = BTreeMap::<u32, BTreeMap<String, String>>::new();
        for page in &self.pages {
            let mut replacements = BTreeMap::new();
            for finding in findings {
                if finding.pointer != page.pointer
                    || finding.effective_action == DecisionAction::Allow
                {
                    continue;
                }
                let replacement =
                    apply_mask(&finding.matched, finding.masking, &finding.label, tokenizer)?;
                if replacement != finding.matched {
                    replacements.insert(finding.matched.clone(), replacement);
                }
            }
            if !replacements.is_empty() {
                replacements_by_page.insert(page.page_number, replacements);
            }
        }

        if replacements_by_page.is_empty() {
            return Ok(None);
        }

        let mut document = LopdfDocument::load_mem(&self.original)
            .map_err(|err| AttachmentError::PdfRewrite(err.to_string()))?;
        let mut total_replacements = 0usize;

        for page in &self.pages {
            let Some(replacements) = replacements_by_page.get(&page.page_number) else {
                continue;
            };
            let mut ordered = replacements.iter().collect::<Vec<_>>();
            ordered.sort_by(|(left, _), (right, _)| {
                right.len().cmp(&left.len()).then(left.cmp(right))
            });

            for (matched, replacement) in ordered {
                let replaced = document
                    .replace_partial_text(page.page_number, matched, replacement, Some("?"))
                    .map_err(|err| AttachmentError::PdfRewrite(err.to_string()))?;
                if replaced == 0 {
                    return Err(AttachmentError::PdfRewrite(format!(
                        "page {} content stream did not replace target {:?}",
                        page.page_number, matched
                    )));
                }
                total_replacements += replaced;
            }
        }

        if total_replacements == 0 {
            return Ok(None);
        }

        let mut output = Vec::new();
        document
            .save_to(&mut output)
            .map_err(|err| AttachmentError::PdfRewrite(err.to_string()))?;
        Ok(Some(output))
    }
}

#[derive(Clone, Debug)]
struct PdfPage {
    page_number: u32,
    pointer: String,
    text: String,
}

#[derive(Clone, Debug)]
struct OoxmlDocument {
    original: Vec<u8>,
    entries: Vec<OoxmlEntry>,
}

impl OoxmlDocument {
    fn rewrite(
        &self,
        findings: &[ResolvedFinding],
        tokenizer: Option<&Tokenizer>,
    ) -> Result<Option<Vec<u8>>, AttachmentError> {
        let mut findings_by_pointer: HashMap<&str, Vec<ResolvedFinding>> = HashMap::new();
        for finding in findings {
            findings_by_pointer
                .entry(finding.pointer.as_str())
                .or_default()
                .push(finding.clone());
        }

        let mut rewritten_entries = BTreeMap::new();
        for entry in &self.entries {
            let mut replacements = BTreeMap::new();
            for node in &entry.nodes {
                let Some(node_findings) = findings_by_pointer.get(node.pointer.as_str()) else {
                    continue;
                };
                let rewritten = redact_text(&node.text, node_findings, tokenizer)?;
                if rewritten != node.text {
                    replacements.insert(node.event_index, rewritten);
                }
            }

            if replacements.is_empty() {
                continue;
            }

            rewritten_entries.insert(
                entry.path.clone(),
                rewrite_ooxml_xml(&entry.xml, &replacements)?,
            );
        }

        if rewritten_entries.is_empty() {
            return Ok(None);
        }

        Ok(Some(rebuild_ooxml_archive(
            &self.original,
            &rewritten_entries,
        )?))
    }
}

#[derive(Clone, Debug)]
struct OoxmlEntry {
    path: String,
    xml: String,
    nodes: Vec<OoxmlTextNode>,
}

#[derive(Clone, Debug)]
struct OoxmlTextNode {
    pointer: String,
    event_index: usize,
    text: String,
}

#[derive(Debug, Error)]
pub enum AttachmentError {
    #[error("multipart boundary missing")]
    MissingBoundary,
    #[error("multipart body malformed")]
    MalformedMultipart,
    #[error("attachment too large: {0} bytes")]
    TooLarge(usize),
    #[error("failed to extract pdf text: {0}")]
    Pdf(String),
    #[error("failed to rewrite pdf text stream: {0}")]
    PdfRewrite(String),
    #[error("failed to read office archive: {0}")]
    Zip(String),
    #[error("failed to rewrite office archive: {0}")]
    ZipWrite(String),
    #[error("failed to process office document xml: {0}")]
    Xml(String),
    #[error("attachment text analysis failed: {0}")]
    Presidio(String),
    #[error(transparent)]
    Tokenization(#[from] TokenizationError),
}

pub fn is_multipart_form(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| {
            value
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        })
        .unwrap_or(false)
}

fn parse_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("boundary=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn parse_multipart_parts(
    body: &Bytes,
    boundary: &str,
) -> Result<Vec<MultipartPart>, AttachmentError> {
    let boundary_marker = format!("--{boundary}").into_bytes();
    let next_marker = format!("\r\n--{boundary}").into_bytes();
    let bytes = body.as_ref();
    let Some(mut cursor) = find_subslice(bytes, &boundary_marker) else {
        return Err(AttachmentError::MalformedMultipart);
    };
    cursor += boundary_marker.len();
    let mut parts = Vec::new();

    loop {
        if bytes.get(cursor..cursor + 2) == Some(b"--".as_slice()) {
            break;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"\r\n".as_slice()) {
            cursor += 2;
        }
        let headers_end = find_subslice(&bytes[cursor..], b"\r\n\r\n")
            .ok_or(AttachmentError::MalformedMultipart)?;
        let headers_end = cursor + headers_end;
        let headers = bytes[cursor..headers_end].to_vec();
        let headers_str = String::from_utf8_lossy(&headers);
        let parsed_headers = parse_headers(&headers_str);
        let body_start = headers_end + 4;
        let body_end_rel = find_subslice(&bytes[body_start..], &next_marker)
            .ok_or(AttachmentError::MalformedMultipart)?;
        let body_end = body_start + body_end_rel;

        parts.push(MultipartPart {
            headers,
            body: bytes[body_start..body_end].to_vec(),
            content_disposition: parsed_headers.get("content-disposition").cloned(),
            content_type: parsed_headers.get("content-type").cloned(),
        });

        cursor = body_end + 2 + boundary_marker.len();
        if bytes.get(cursor..cursor + 2) == Some(b"--".as_slice()) {
            break;
        }
    }

    Ok(parts)
}

fn parse_headers(input: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in input.lines() {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    headers
}

fn parse_disposition_param<'a>(disposition: &'a str, key: &str) -> Option<&'a str> {
    for part in disposition.split(';').skip(1) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{key}=")) {
            return Some(value.trim_matches('"'));
        }
    }
    None
}

fn is_media_type_allowed(media_type: &str, allowed: &[String]) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    allowed.iter().any(|candidate| {
        let candidate = candidate.to_ascii_lowercase();
        candidate == media_type
            || (candidate.ends_with("/*")
                && media_type.starts_with(candidate.trim_end_matches('*')))
    })
}

fn detect_media_type(file_name: &str) -> String {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else if lower.ends_with(".docx") {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string()
    } else if lower.ends_with(".xlsx") {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string()
    } else if lower.ends_with(".pptx") {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string()
    } else if lower.ends_with(".json") {
        "application/json".to_string()
    } else if lower.ends_with(".csv") {
        "text/csv".to_string()
    } else if lower.ends_with(".xml") {
        "application/xml".to_string()
    } else {
        "text/plain".to_string()
    }
}

fn extract_attachment_content(
    bytes: &[u8],
    media_type: &str,
    file_name: Option<&str>,
    attachment_pointer: &str,
) -> Result<AttachmentContent, AttachmentError> {
    let lower_media = media_type.to_ascii_lowercase();
    if lower_media.starts_with("text/")
        || matches!(
            lower_media.as_str(),
            "application/json" | "application/xml" | "text/xml" | "text/csv"
        )
    {
        return Ok(AttachmentContent::Text(
            String::from_utf8_lossy(bytes).into_owned(),
        ));
    }
    if lower_media == "application/pdf" {
        if let Ok(document) = extract_pdf_document(bytes, attachment_pointer)
            && !document.pages.is_empty()
        {
            return Ok(AttachmentContent::Pdf(document));
        }
        return Ok(AttachmentContent::ExtractedText(
            pdf_extract::extract_text_from_mem(bytes)
                .map_err(|err| AttachmentError::Pdf(err.to_string()))?,
        ));
    }
    if is_ooxml_attachment(&lower_media, file_name) {
        return Ok(AttachmentContent::Ooxml(extract_ooxml_document(
            bytes,
            attachment_pointer,
        )?));
    }
    Ok(AttachmentContent::None)
}

#[cfg(test)]
fn extract_attachment_text(
    bytes: &[u8],
    media_type: &str,
    file_name: Option<&str>,
) -> Result<String, AttachmentError> {
    let lower_media = media_type.to_ascii_lowercase();
    if lower_media.starts_with("text/")
        || matches!(
            lower_media.as_str(),
            "application/json" | "application/xml" | "text/xml" | "text/csv"
        )
    {
        return Ok(String::from_utf8_lossy(bytes).into_owned());
    }
    if lower_media == "application/pdf" {
        if let Ok(document) = extract_pdf_document(bytes, "/attachments/file")
            && !document.pages.is_empty()
        {
            let mut out = String::new();
            for page in document.pages {
                append_extracted_text(&mut out, &page.text);
            }
            return Ok(out);
        }
        return pdf_extract::extract_text_from_mem(bytes)
            .map_err(|err| AttachmentError::Pdf(err.to_string()));
    }
    if is_ooxml_attachment(&lower_media, file_name) {
        return extract_ooxml_text(bytes);
    }
    Ok(String::new())
}

fn is_ooxml_attachment(media_type: &str, file_name: Option<&str>) -> bool {
    media_type.contains("wordprocessingml.document")
        || media_type.contains("spreadsheetml.sheet")
        || media_type.contains("presentationml.presentation")
        || file_name
            .map(|name| {
                let name = name.to_ascii_lowercase();
                name.ends_with(".docx") || name.ends_with(".xlsx") || name.ends_with(".pptx")
            })
            .unwrap_or(false)
}

#[cfg(test)]
fn extract_ooxml_text(bytes: &[u8]) -> Result<String, AttachmentError> {
    let document = extract_ooxml_document(bytes, "/attachments/file")?;
    let mut out = String::new();
    for entry in document.entries {
        for node in entry.nodes {
            append_extracted_text(&mut out, &node.text);
        }
    }
    Ok(out)
}

fn extract_ooxml_document(
    bytes: &[u8],
    attachment_pointer: &str,
) -> Result<OoxmlDocument, AttachmentError> {
    let reader = Cursor::new(bytes);
    let mut archive =
        ZipArchive::new(reader).map_err(|err| AttachmentError::Zip(err.to_string()))?;
    let mut entries = Vec::new();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| AttachmentError::Zip(err.to_string()))?;
        let path = file.name().to_string();
        if !is_ooxml_xml_entry(&path) {
            continue;
        }
        let mut xml = String::new();
        file.read_to_string(&mut xml)
            .map_err(|err| AttachmentError::Xml(err.to_string()))?;
        let nodes = collect_ooxml_text_nodes(&xml, attachment_pointer, &path)?;
        entries.push(OoxmlEntry { path, xml, nodes });
    }

    Ok(OoxmlDocument {
        original: bytes.to_vec(),
        entries,
    })
}

fn extract_pdf_document(
    bytes: &[u8],
    attachment_pointer: &str,
) -> Result<PdfDocument, AttachmentError> {
    let document =
        LopdfDocument::load_mem(bytes).map_err(|err| AttachmentError::Pdf(err.to_string()))?;
    let mut pages = Vec::new();

    for page_number in document.get_pages().keys().copied() {
        let text = document
            .extract_text(&[page_number])
            .map_err(|err| AttachmentError::Pdf(err.to_string()))?;
        if text.trim().is_empty() {
            continue;
        }
        pages.push(PdfPage {
            page_number,
            pointer: format!("{attachment_pointer}/page/{page_number}"),
            text,
        });
    }

    Ok(PdfDocument {
        original: bytes.to_vec(),
        pages,
    })
}

#[cfg(test)]
pub(crate) fn build_pdf_bytes_for_test(text: &str) -> Vec<u8> {
    use lopdf::{
        Document as LopdfDocument, Object as LopdfObject, Stream as LopdfStream,
        content::{Content, Operation},
        dictionary,
    };

    let mut doc = LopdfDocument::with_version("1.5");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! {
            "F1" => font_id,
        },
    });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new("Tj", vec![LopdfObject::string_literal(text)]),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = doc.add_object(LopdfStream::new(dictionary! {}, content.encode().unwrap()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
    });
    doc.objects.insert(
        pages_id,
        lopdf::Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }),
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

fn is_ooxml_xml_entry(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with(".xml")
        && (path.starts_with("word/") || path.starts_with("xl/") || path.starts_with("ppt/"))
}

fn collect_ooxml_text_nodes(
    xml: &str,
    attachment_pointer: &str,
    entry_path: &str,
) -> Result<Vec<OoxmlTextNode>, AttachmentError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut event_index = 0usize;
    let mut text_index = 0usize;
    let mut nodes = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(text)) => {
                let decoded = text
                    .decode()
                    .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                if !decoded.trim().is_empty() {
                    nodes.push(OoxmlTextNode {
                        pointer: format!("{attachment_pointer}/{entry_path}#text/{text_index}"),
                        event_index,
                        text: decoded.into_owned(),
                    });
                    text_index += 1;
                }
                event_index += 1;
            }
            Ok(Event::CData(text)) => {
                let decoded = text
                    .decode()
                    .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                if !decoded.trim().is_empty() {
                    nodes.push(OoxmlTextNode {
                        pointer: format!("{attachment_pointer}/{entry_path}#text/{text_index}"),
                        event_index,
                        text: decoded.into_owned(),
                    });
                    text_index += 1;
                }
                event_index += 1;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(AttachmentError::Xml(err.to_string())),
        }
        buf.clear();
    }

    Ok(nodes)
}

#[cfg(test)]
fn append_extracted_text(out: &mut String, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}

async fn scan_attachment_content(
    deps: AttachmentScanDeps<'_>,
    content: &AttachmentContent,
    pointer: &str,
    max_text_chars: usize,
) -> Result<Vec<DetectionFinding>, AttachmentError> {
    match content {
        AttachmentContent::None => Ok(Vec::new()),
        AttachmentContent::Text(text) | AttachmentContent::ExtractedText(text) => {
            scan_limited_text(deps, text, pointer, max_text_chars).await
        }
        AttachmentContent::Pdf(document) => scan_pdf_document(deps, document, max_text_chars).await,
        AttachmentContent::Ooxml(document) => {
            scan_ooxml_document(deps, document, max_text_chars).await
        }
    }
}

async fn scan_limited_text(
    deps: AttachmentScanDeps<'_>,
    text: &str,
    pointer: &str,
    max_text_chars: usize,
) -> Result<Vec<DetectionFinding>, AttachmentError> {
    let limited = limit_text(text, max_text_chars);
    scan_text_with_engines(deps, &limited, pointer).await
}

async fn scan_ooxml_document(
    deps: AttachmentScanDeps<'_>,
    document: &OoxmlDocument,
    max_text_chars: usize,
) -> Result<Vec<DetectionFinding>, AttachmentError> {
    let mut findings = Vec::new();
    let mut remaining = max_text_chars;

    for entry in &document.entries {
        for node in &entry.nodes {
            if remaining == 0 {
                return Ok(findings);
            }
            let limited = limit_text(&node.text, remaining);
            remaining = remaining.saturating_sub(limited.chars().count());
            findings.extend(scan_text_with_engines(deps, &limited, &node.pointer).await?);
        }
    }

    Ok(findings)
}

async fn scan_pdf_document(
    deps: AttachmentScanDeps<'_>,
    document: &PdfDocument,
    max_text_chars: usize,
) -> Result<Vec<DetectionFinding>, AttachmentError> {
    let mut findings = Vec::new();
    let mut remaining = max_text_chars;

    for page in &document.pages {
        if remaining == 0 {
            return Ok(findings);
        }
        let limited = limit_text(&page.text, remaining);
        remaining = remaining.saturating_sub(limited.chars().count());
        findings.extend(scan_text_with_engines(deps, &limited, &page.pointer).await?);
    }

    Ok(findings)
}

async fn scan_text_with_engines(
    deps: AttachmentScanDeps<'_>,
    text: &str,
    pointer: &str,
) -> Result<Vec<DetectionFinding>, AttachmentError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = deps.detector.scan_text(text, pointer);
    if let Some(presidio) = deps.presidio {
        findings.extend(
            presidio
                .analyze(text, pointer)
                .await
                .map_err(|err| AttachmentError::Presidio(err.to_string()))?,
        );
    }
    Ok(findings)
}

fn finding_targets_part(finding: &ResolvedFinding, part_pointer: &str) -> bool {
    if part_pointer.is_empty() {
        return false;
    }
    finding.pointer == part_pointer
        || finding.pointer.starts_with(&format!("{part_pointer}/"))
        || finding.pointer.starts_with(&format!("{part_pointer}#"))
}

fn rewrite_ooxml_xml(
    xml: &str,
    replacements: &BTreeMap<usize, String>,
) -> Result<Vec<u8>, AttachmentError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut event_index = 0usize;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(text)) => {
                if let Some(rewritten) = replacements.get(&event_index) {
                    writer
                        .write_event(Event::Text(BytesText::new(rewritten.as_str())))
                        .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                } else {
                    writer
                        .write_event(Event::Text(text.borrow()))
                        .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                }
                event_index += 1;
            }
            Ok(Event::CData(text)) => {
                if let Some(rewritten) = replacements.get(&event_index) {
                    for chunk in BytesCData::escaped(rewritten.as_str()) {
                        writer
                            .write_event(Event::CData(chunk))
                            .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                    }
                } else {
                    writer
                        .write_event(Event::CData(text.borrow()))
                        .map_err(|err| AttachmentError::Xml(err.to_string()))?;
                }
                event_index += 1;
            }
            Ok(Event::Eof) => break,
            Ok(event) => writer
                .write_event(event.borrow())
                .map_err(|err| AttachmentError::Xml(err.to_string()))?,
            Err(err) => return Err(AttachmentError::Xml(err.to_string())),
        }
        buf.clear();
    }

    Ok(writer.into_inner().into_inner())
}

fn rebuild_ooxml_archive(
    original: &[u8],
    rewritten_entries: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, AttachmentError> {
    let reader = Cursor::new(original);
    let mut archive =
        ZipArchive::new(reader).map_err(|err| AttachmentError::Zip(err.to_string()))?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));

    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|err| AttachmentError::Zip(err.to_string()))?;
        let name = file.name().to_string();
        let options = zip_file_options(
            &file,
            rewritten_entries
                .get(&name)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or_else(|| file.size()),
        );

        if file.is_dir() {
            writer
                .add_directory(name, options)
                .map_err(|err| AttachmentError::ZipWrite(err.to_string()))?;
            continue;
        }

        if let Some(rewritten) = rewritten_entries.get(&name) {
            writer
                .start_file(name, options)
                .map_err(|err| AttachmentError::ZipWrite(err.to_string()))?;
            writer
                .write_all(rewritten)
                .map_err(|err| AttachmentError::ZipWrite(err.to_string()))?;
        } else {
            writer
                .raw_copy_file(file)
                .map_err(|err| AttachmentError::ZipWrite(err.to_string()))?;
        }
    }

    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|err| AttachmentError::ZipWrite(err.to_string()))
}

fn zip_file_options(file: &zip::read::ZipFile<'_>, uncompressed_size: u64) -> FileOptions {
    let mut options = FileOptions::default()
        .compression_method(file.compression())
        .last_modified_time(file.last_modified())
        .large_file(
            uncompressed_size > u32::MAX as u64 || file.compressed_size() > u32::MAX as u64,
        );
    if let Some(mode) = file.unix_mode() {
        options = options.unix_permissions(mode);
    }
    options
}

fn rebuild_multipart_body(boundary: &str, parts: &[ScannedPart]) -> Bytes {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        out.extend_from_slice(&part.raw.headers);
        out.extend_from_slice(b"\r\n\r\n");
        match &part.rewritten_body {
            Some(body) => out.extend_from_slice(body),
            None => out.extend_from_slice(&part.raw.body),
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Bytes::from(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn limit_text(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use bytes::Bytes;
    use lopdf::Document as LopdfDocument;
    use zip::{CompressionMethod, ZipWriter, write::FileOptions};

    use crate::{
        policy::ResolvedFinding,
        types::{DecisionAction, MaskingStrategy, Severity},
    };

    use super::{extract_ooxml_document, is_multipart_form};

    fn collect_request_attachments_for_test(
        body: &Bytes,
        content_type: Option<&str>,
    ) -> Vec<String> {
        let boundary = super::parse_boundary(content_type.unwrap()).unwrap();
        super::parse_multipart_parts(body, &boundary)
            .unwrap()
            .into_iter()
            .filter(|part| part.is_attachment())
            .map(|part| {
                super::extract_attachment_text(&part.body, &part.media_type(), part.file_name())
                    .unwrap()
            })
            .collect()
    }

    fn stored_options() -> FileOptions {
        FileOptions::default().compression_method(CompressionMethod::Stored)
    }

    fn build_ooxml_archive(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            writer
                .start_file("[Content_Types].xml", stored_options())
                .unwrap();
            writer
                .write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types></Types>"#)
                .unwrap();
            writer
                .add_directory("word/media", stored_options())
                .unwrap();
            writer
                .start_file("word/media/pixel.bin", stored_options())
                .unwrap();
            writer.write_all(b"pixel").unwrap();
            for (name, xml) in entries {
                writer.start_file(*name, stored_options()).unwrap();
                writer.write_all(xml.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn read_zip_entry(bytes: &[u8], path: &str) -> String {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut file = archive.by_name(path).unwrap();
        let mut out = String::new();
        file.read_to_string(&mut out).unwrap();
        out
    }

    fn read_zip_binary_entry(bytes: &[u8], path: &str) -> Vec<u8> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut file = archive.by_name(path).unwrap();
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        out
    }

    fn make_resolved_finding(pointer: &str, text: &str, matched: &str) -> ResolvedFinding {
        let start = text.find(matched).unwrap();
        let end = start + matched.len();
        ResolvedFinding {
            label: "email".into(),
            rule_name: "email".into(),
            action: DecisionAction::Redact,
            effective_action: DecisionAction::Redact,
            pointer: pointer.to_string(),
            severity: Severity::Medium,
            masking: MaskingStrategy::PartialEmail,
            matched_sha256: "hash".into(),
            matched_len: matched.len(),
            start,
            end,
            matched: matched.to_string(),
        }
    }

    #[test]
    fn detects_multipart_form() {
        assert!(is_multipart_form(Some(
            "multipart/form-data; boundary=abc123"
        )));
        assert!(!is_multipart_form(Some("application/json")));
    }

    #[test]
    fn extracts_text_file_from_multipart() {
        let boundary = "demo";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\n邮箱 admin@example.com\r\n--{boundary}--\r\n"
        );
        let attachments = collect_request_attachments_for_test(
            &Bytes::from(body),
            Some(&format!("multipart/form-data; boundary={boundary}")),
        );
        assert_eq!(attachments.len(), 1);
        assert!(attachments[0].contains("admin@example.com"));
    }

    #[test]
    fn extracts_docx_xml_text() {
        let bytes = build_ooxml_archive(&[(
            "word/document.xml",
            "<w:document xmlns:w=\"urn:x\"><w:body><w:p><w:r><w:t>手机号13812341234</w:t></w:r></w:p></w:body></w:document>",
        )]);

        let boundary = "docx";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let attachments = collect_request_attachments_for_test(
            &Bytes::from(body),
            Some(&format!("multipart/form-data; boundary={boundary}")),
        );
        assert_eq!(attachments.len(), 1);
        assert!(attachments[0].contains("13812341234"));
    }

    #[test]
    fn falls_back_to_file_extension_for_generic_attachment_content_type() {
        let boundary = "fallback";
        let cases = [
            (
                "secret.docx",
                "application/octet-stream",
                build_ooxml_archive(&[(
                    "word/document.xml",
                    "<w:document xmlns:w=\"urn:x\"><w:body><w:p><w:r><w:t>邮箱 admin@example.com</w:t></w:r></w:p></w:body></w:document>",
                )]),
                "admin@example.com",
            ),
            (
                "secret.xlsx",
                "application/octet-stream",
                build_ooxml_archive(&[(
                    "xl/sharedStrings.xml",
                    "<sst xmlns=\"urn:x\"><si><t>邮箱 admin@example.com</t></si></sst>",
                )]),
                "admin@example.com",
            ),
            (
                "secret.pptx",
                "application/octet-stream",
                build_ooxml_archive(&[(
                    "ppt/slides/slide1.xml",
                    "<p:sld xmlns:p=\"urn:p\" xmlns:a=\"urn:a\"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>邮箱 admin@example.com</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>",
                )]),
                "admin@example.com",
            ),
            (
                "secret.pdf",
                "application/octet-stream",
                super::build_pdf_bytes_for_test("邮箱 admin@example.com"),
                "admin@example.com",
            ),
        ];

        for (file_name, content_type, bytes, needle) in cases {
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: {content_type}\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(&bytes);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

            let attachments = collect_request_attachments_for_test(
                &Bytes::from(body),
                Some(&format!("multipart/form-data; boundary={boundary}")),
            );
            assert_eq!(
                attachments.len(),
                1,
                "attachment count mismatch for {file_name}"
            );
            assert!(
                attachments[0].contains(needle),
                "extension fallback extraction failed for {file_name}: {}",
                attachments[0]
            );
        }
    }

    #[test]
    fn extracts_pdf_text_and_rewrites_simple_text_stream() {
        let bytes = super::build_pdf_bytes_for_test("邮箱 admin@example.com");
        let extracted =
            super::extract_attachment_text(&bytes, "application/pdf", Some("secret.pdf")).unwrap();
        assert!(extracted.contains("admin@example.com"));

        let document = super::extract_pdf_document(&bytes, "/attachments/file").unwrap();
        assert_eq!(document.pages.len(), 1);
        let page = &document.pages[0];
        let rewritten = document
            .rewrite(
                &[make_resolved_finding(
                    &page.pointer,
                    &page.text,
                    "admin@example.com",
                )],
                None,
            )
            .unwrap()
            .unwrap();
        let parsed = LopdfDocument::load_mem(&rewritten).unwrap();
        let text = parsed.extract_text(&[1]).unwrap();
        assert!(text.contains("a***@example.com"));
        assert!(!text.contains("admin@example.com"));
    }

    #[test]
    fn rewrites_docx_xml_text_nodes_and_preserves_binary_entries() {
        let bytes = build_ooxml_archive(&[(
            "word/document.xml",
            "<w:document xmlns:w=\"urn:x\"><w:body><w:p><w:r><w:t>邮箱 admin@example.com</w:t></w:r></w:p></w:body></w:document>",
        )]);
        let document = extract_ooxml_document(&bytes, "/attachments/file").unwrap();
        let node = &document.entries[0].nodes[0];
        let findings = vec![make_resolved_finding(
            &node.pointer,
            &node.text,
            "admin@example.com",
        )];

        let rewritten = document.rewrite(&findings, None).unwrap().unwrap();
        let xml = read_zip_entry(&rewritten, "word/document.xml");
        assert!(xml.contains("a***@example.com"));
        assert!(!xml.contains("admin@example.com"));
        assert_eq!(
            read_zip_binary_entry(&rewritten, "word/media/pixel.bin"),
            b"pixel"
        );
    }

    #[test]
    fn rewrites_xlsx_and_pptx_text_nodes() {
        let xlsx = build_ooxml_archive(&[(
            "xl/sharedStrings.xml",
            "<sst xmlns=\"urn:x\"><si><t>邮箱 admin@example.com</t></si></sst>",
        )]);
        let xlsx_doc = extract_ooxml_document(&xlsx, "/attachments/sheet").unwrap();
        let xlsx_node = &xlsx_doc.entries[0].nodes[0];
        let xlsx_rewritten = xlsx_doc
            .rewrite(
                &[make_resolved_finding(
                    &xlsx_node.pointer,
                    &xlsx_node.text,
                    "admin@example.com",
                )],
                None,
            )
            .unwrap()
            .unwrap();
        assert!(
            read_zip_entry(&xlsx_rewritten, "xl/sharedStrings.xml").contains("a***@example.com")
        );

        let pptx = build_ooxml_archive(&[(
            "ppt/slides/slide1.xml",
            "<p:sld xmlns:p=\"urn:p\" xmlns:a=\"urn:a\"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>邮箱 admin@example.com</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>",
        )]);
        let pptx_doc = extract_ooxml_document(&pptx, "/attachments/slides").unwrap();
        let pptx_node = &pptx_doc.entries[0].nodes[0];
        let pptx_rewritten = pptx_doc
            .rewrite(
                &[make_resolved_finding(
                    &pptx_node.pointer,
                    &pptx_node.text,
                    "admin@example.com",
                )],
                None,
            )
            .unwrap()
            .unwrap();
        assert!(
            read_zip_entry(&pptx_rewritten, "ppt/slides/slide1.xml").contains("a***@example.com")
        );
    }
}
