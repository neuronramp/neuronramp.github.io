#!/usr/bin/env python3
"""
clinical_quick_read.py
======================
Clinical Data Quick Read — Local Machine Version
A privacy screening tool for clinical datasets.

PRIVACY NOTE: All processing happens entirely on your local machine.
No data is transmitted anywhere. This tool reads your file, analyzes it,
and writes output files — all locally. It is as private as your machine.

DISCLAIMER: This tool is a screening aid. It is NOT a substitute for HIPAA
Expert Determination, IRB review, or formal de-identification by a qualified
privacy officer. It performs pattern-based detection of direct identifiers,
quasi-identifiers, and free-text PHI. It will catch common cases. It can miss
edge cases. Use the output as a first pass, not the last word.

USAGE:
    python clinical_quick_read.py <input_file> [options]

OPTIONS:
    -o, --output        Output file path (default: <input>_screened.<ext>)
    -r, --report        Report file path (default: <input>_screening_report.txt)
    -m, --mode          Sanitization mode: interactive (default), auto-safe, auto-strip
    -f, --format        Output format: same (default), csv, xlsx
    --no-report         Skip writing screening report

EXAMPLES:
    python clinical_quick_read.py my_data.csv
    python clinical_quick_read.py my_data.xlsx --mode auto-safe
    python clinical_quick_read.py trial_data.csv --output cleaned.csv --mode interactive

INSTALLATION:
    pip install pandas openpyxl xlrd rich

    Or if you use a virtual environment:
    python -m venv venv
    source venv/bin/activate   (Mac/Linux)
    venv\\Scripts\\activate      (Windows)
    pip install pandas openpyxl xlrd rich
"""

import sys
import os
import re
import json
import csv
import hashlib
import random
import argparse
import datetime
from pathlib import Path
from typing import Optional

# ============================================================
# Dependency check
# ============================================================

MISSING = []
try:
    import pandas as pd
except ImportError:
    MISSING.append('pandas')

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
    HAS_RICH = True
except ImportError:
    MISSING.append('rich')
    HAS_RICH = False

if MISSING:
    print(f"\nMissing required packages: {', '.join(MISSING)}")
    print("Install with: pip install pandas openpyxl xlrd rich")
    sys.exit(1)

console = Console()

# ============================================================
# Pattern library
# ============================================================

PATTERNS = {
    'ssn':    {'regex': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),                             'label': 'SSN',           'kind': 'direct'},
    'phone':  {'regex': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), 'label': 'Phone',    'kind': 'direct'},
    'email':  {'regex': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), 'label': 'Email',         'kind': 'direct'},
    'mrn':    {'regex': re.compile(r'\b(MRN|MR#?|Medical\s+Record)[\s:#-]*\d{4,}\b', re.I), 'label': 'MRN',          'kind': 'direct'},
    'url':    {'regex': re.compile(r'\bhttps?://\S+'),                                       'label': 'URL',           'kind': 'direct'},
    'ipv4':   {'regex': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),                         'label': 'IP address',    'kind': 'direct'},
    'zip':    {'regex': re.compile(r'\b\d{5}(-\d{4})?\b'),                                  'label': 'ZIP code',      'kind': 'quasi'},
    'date_mdy': {'regex': re.compile(r'\b(0?[1-9]|1[0-2])[/\-](0?[1-9]|[12]\d|3[01])[/\-](19|20)?\d{2}\b'), 'label': 'Date (M/D/Y)', 'kind': 'quasi'},
    'date_ymd': {'regex': re.compile(r'\b(19|20)\d{2}[/\-](0?[1-9]|1[0-2])[/\-](0?[1-9]|[12]\d|3[01])\b'), 'label': 'Date (Y/M/D)', 'kind': 'quasi'},
    'age90':  {'regex': re.compile(r'\b9[0-9]\b'),                                          'label': 'Age >89',       'kind': 'quasi'},
}

DIRECT_COL_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'name', r'^first$', r'^last$', r'full.?name', r'patient.id', r'subject.id',
        r'mrn', r'medical.?record', r'ssn', r'social.?security', r'^email', r'e.?mail',
        r'phone', r'tel', r'mobile', r'address', r'street', r'^city$', r'zip', r'postal',
        r'dob', r'birth', r'signature', r'license', r'vehicle', r'url', r'website',
        r'ip.address', r'fax', r'account.?(number|num|#)', r'device.?id', r'serial',
        r'photo', r'image', r'biometric', r'next.of.kin', r'emergency.contact', r'guardian',
    ]
]

QUASI_COL_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'^age$', r'patient.age', r'^sex$', r'^gender$', r'^race$', r'^ethnic',
        r'diagnosis', r'icd', r'condition', r'^county$',
        r'admission', r'discharge', r'enrollment.date', r'visit.date', r'date.of',
        r'^year$',
    ]
]

# ============================================================
# Detection logic
# ============================================================

def detect_column(col_name: str, values: list) -> dict:
    """Detect PHI type for a single column."""
    result = {
        'col': col_name,
        'kind': 'ok',
        'reasons': [],
        'sample': str(values[0]) if values else '',
    }

    # Header-based
    for pat in DIRECT_COL_PATTERNS:
        if pat.search(col_name):
            result['kind'] = 'direct'
            result['reasons'].append(f'Header matches direct-identifier pattern')
            break

    if result['kind'] == 'ok':
        for pat in QUASI_COL_PATTERNS:
            if pat.search(col_name):
                result['kind'] = 'quasi'
                result['reasons'].append('Header suggests quasi-identifier')
                break

    # Content-based (sample up to 200 non-null values)
    sample_vals = [str(v) for v in values if v is not None and str(v).strip() != ''][:200]

    if sample_vals:
        for key, p in PATTERNS.items():
            hits = sum(1 for v in sample_vals if p['regex'].search(v))
            rate = hits / len(sample_vals) if sample_vals else 0
            if rate > 0.3:
                if p['kind'] == 'direct' and result['kind'] != 'direct':
                    result['kind'] = 'direct'
                    result['reasons'].append(f"Content matches {p['label']} ({round(rate*100)}% of values)")
                elif p['kind'] == 'quasi' and result['kind'] == 'ok':
                    result['kind'] = 'quasi'
                    result['reasons'].append(f"Content matches {p['label']} ({round(rate*100)}% of values)")
            elif rate > 0.05 and result['kind'] == 'ok':
                result['kind'] = 'quasi'
                result['reasons'].append(f"Some values match {p['label']} ({round(rate*100)}%)")

        # Free-text heuristic
        avg_len = sum(len(v) for v in sample_vals) / len(sample_vals) if sample_vals else 0
        if avg_len > 60 and result['kind'] == 'ok':
            result['kind'] = 'text'
            result['reasons'].append('Likely free-text field (avg character length > 60)')

    return result


def scan_free_text(df: pd.DataFrame, col_detects: list) -> list:
    """Scan free-text columns for embedded PHI patterns."""
    findings = []
    text_cols = [c for c in col_detects if c['kind'] == 'text']
    for tc in text_cols:
        col_name = tc['col']
        if col_name not in df.columns:
            continue
        col_findings = {}
        for val in df[col_name].dropna().astype(str):
            for key, p in PATTERNS.items():
                if p['regex'].search(val):
                    col_findings[p['label']] = col_findings.get(p['label'], 0) + 1
        for label, count in col_findings.items():
            findings.append({'col': col_name, 'label': label, 'count': count})
    return findings


# ============================================================
# Sanitization
# ============================================================

SALT = 'neuronramp-clinical-salt-' + str(random.randint(100000, 999999))
DATE_SHIFT = random.randint(-182, 182)


def pseudo_hash(value: str) -> str:
    h = hashlib.sha256((SALT + str(value)).encode()).hexdigest()
    return 'px_' + h[:12]


def shift_date(value: str) -> str:
    for fmt in ('%Y-%m-%d', '%m/%d/%Y', '%m-%d-%Y', '%m/%d/%y', '%d/%m/%Y'):
        try:
            d = datetime.datetime.strptime(str(value).strip(), fmt)
            d2 = d + datetime.timedelta(days=DATE_SHIFT)
            return d2.strftime(fmt)
        except ValueError:
            continue
    return value


def generalize_value(col_name: str, value: str) -> str:
    if re.search(r'age', col_name, re.I):
        try:
            n = int(float(value))
            if n >= 90:
                return '90+'
            return f"{(n // 10) * 10}s"
        except (ValueError, TypeError):
            return value
    if re.search(r'zip|postal', col_name, re.I):
        return str(value)[:3] + 'XX'
    return value


def redact_text(value: str) -> str:
    out = str(value)
    for key, p in PATTERNS.items():
        out = p['regex'].sub(f'[REDACTED:{p["label"]}]', out)
    return out


def sanitize_value(value, action: str, col_name: str) -> str:
    if pd.isna(value) or str(value).strip() == '':
        return ''
    v = str(value)
    if action == 'strip':
        return None  # signal to drop column
    elif action == 'pseudo':
        return pseudo_hash(v)
    elif action == 'shift':
        return shift_date(v)
    elif action == 'generalize':
        return generalize_value(col_name, v)
    elif action == 'redact-text':
        return redact_text(v)
    else:
        return v  # keep


# ============================================================
# Default actions
# ============================================================

def default_action(col_detect: dict) -> str:
    col = col_detect['col']
    kind = col_detect['kind']
    if kind == 'direct':
        return 'strip'
    elif kind == 'quasi':
        if re.search(r'age', col, re.I):
            return 'generalize'
        elif re.search(r'date|admission|discharge|visit|enroll', col, re.I):
            return 'shift'
        elif re.search(r'zip|postal', col, re.I):
            return 'generalize'
        else:
            return 'keep'
    elif kind == 'text':
        return 'redact-text'
    else:
        return 'keep'


# ============================================================
# Display
# ============================================================

KIND_COLORS = {
    'direct': 'bold red',
    'quasi':  'bold yellow',
    'text':   'bold cyan',
    'ok':     'bold green',
}

KIND_LABELS = {
    'direct': 'DIRECT PHI',
    'quasi':  'QUASI-ID',
    'text':   'FREE TEXT',
    'ok':     'CLEAN',
}

ACTION_OPTIONS = {
    'direct': ['strip', 'pseudo', 'keep'],
    'quasi':  ['keep', 'generalize', 'shift', 'strip', 'pseudo'],
    'text':   ['redact-text', 'strip', 'keep'],
    'ok':     ['keep', 'strip'],
}

ACTION_LABELS = {
    'strip':       'Strip column entirely',
    'pseudo':      'Pseudonymize (SHA-256 hash)',
    'shift':       'Date shift (consistent offset)',
    'generalize':  'Generalize (bin ages, truncate ZIP)',
    'redact-text': 'Redact identifiers in free text',
    'keep':        'Keep as-is (may retain risk)',
}


def print_header():
    console.print()
    console.print(Panel.fit(
        "[bold yellow]Clinical Data Quick Read[/bold yellow]\n"
        "[dim]Privacy screening for clinical datasets[/dim]\n\n"
        "[green]PRIVACY NOTE:[/green] All processing is local. Nothing leaves this machine.\n"
        "[red]DISCLAIMER:[/red] This is a screening aid, not formal HIPAA de-identification.",
        border_style="dim white",
    ))
    console.print()


def print_summary(col_detects: list, text_findings: list, row_count: int, filename: str):
    direct = sum(1 for c in col_detects if c['kind'] == 'direct')
    quasi  = sum(1 for c in col_detects if c['kind'] == 'quasi')
    text   = sum(1 for c in col_detects if c['kind'] == 'text')
    ok     = sum(1 for c in col_detects if c['kind'] == 'ok')
    text_hits = sum(f['count'] for f in text_findings)

    console.print(f"[dim]File:[/dim] {filename}  [dim]Rows:[/dim] {row_count:,}  [dim]Columns:[/dim] {len(col_detects)}")
    console.print()

    if direct > 0:
        verdict_color = 'red'
        verdict_label = '[bold red]⚠  NOT DE-IDENTIFIED[/bold red]'
        verdict_body  = f'Found {direct} direct identifier column(s) and {text_hits} free-text hit(s). Do not share or paste into an LLM without sanitization.'
    elif quasi > 0 or text_hits > 0:
        verdict_color = 'yellow'
        verdict_label = '[bold yellow]◑  QUASI-IDENTIFIERS PRESENT[/bold yellow]'
        verdict_body  = f'No direct identifiers detected. Found {quasi} quasi-identifier column(s) and {text_hits} free-text hit(s). Re-identification via linkage remains possible.'
    else:
        verdict_color = 'green'
        verdict_label = '[bold green]✓  NO IDENTIFIERS DETECTED[/bold green]'
        verdict_body  = 'Pattern-based screening found no identifiers. Manual review still recommended before any external sharing.'

    console.print(Panel(
        f"{verdict_label}\n[dim]{verdict_body}[/dim]",
        border_style=verdict_color,
    ))
    console.print()

    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style='bold dim')
    t.add_column('Category', style='bold')
    t.add_column('Count', justify='right')
    t.add_column('Default action')
    t.add_row('[red]Direct identifiers[/red]', str(direct), 'strip')
    t.add_row('[yellow]Quasi-identifiers[/yellow]', str(quasi), 'generalize / shift / keep')
    t.add_row('[cyan]Free-text columns[/cyan]', str(text), 'redact in text')
    t.add_row('[green]Clean columns[/green]', str(ok), 'keep')
    if text_hits:
        t.add_row('[cyan]Free-text PHI hits[/cyan]', str(text_hits), '—')
    console.print(t)


def print_column_table(col_detects: list):
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style='bold dim', expand=True)
    t.add_column('#', style='dim', width=4)
    t.add_column('Column')
    t.add_column('Detection', width=14)
    t.add_column('Sample value')
    t.add_column('Reason', style='dim')

    for i, c in enumerate(col_detects, 1):
        color = KIND_COLORS.get(c['kind'], 'white')
        label = KIND_LABELS.get(c['kind'], c['kind'])
        sample = (c['sample'] or '')[:50]
        reason = c['reasons'][0] if c['reasons'] else ''
        t.add_row(
            str(i),
            c['col'],
            f'[{color}]{label}[/{color}]',
            sample,
            reason,
        )
    console.print(t)


# ============================================================
# Interactive mode
# ============================================================

def interactive_review(col_detects: list) -> dict:
    """Ask user to confirm or change action per flagged column."""
    actions = {}
    for c in col_detects:
        actions[c['col']] = default_action(c)

    flagged = [c for c in col_detects if c['kind'] != 'ok']
    if not flagged:
        console.print("[green]No flagged columns. All columns will be kept.[/green]")
        return actions

    console.print(f"\n[bold]Review {len(flagged)} flagged column(s).[/bold] Press Enter to accept default, or type a number to choose.\n")

    for c in flagged:
        col   = c['col']
        kind  = c['kind']
        color = KIND_COLORS.get(kind, 'white')
        default = actions[col]
        opts  = ACTION_OPTIONS.get(kind, ['keep', 'strip'])

        console.print(f"  [{color}]{KIND_LABELS[kind]}[/{color}]  [bold]{col}[/bold]")
        if c['sample']:
            console.print(f"    Sample: [dim]{c['sample'][:60]}[/dim]")

        for i, opt in enumerate(opts, 1):
            marker = '[bold yellow]>[/bold yellow]' if opt == default else ' '
            console.print(f"    {marker} {i}. {ACTION_LABELS[opt]}")

        choice = Prompt.ask(f"    Choice (default: {default})", default='')
        if choice.strip():
            try:
                idx = int(choice.strip()) - 1
                if 0 <= idx < len(opts):
                    actions[col] = opts[idx]
                    console.print(f"    [dim]→ {opts[idx]}[/dim]")
            except ValueError:
                pass
        console.print()

    return actions


def auto_safe_actions(col_detects: list) -> dict:
    """Apply safe defaults without asking."""
    return {c['col']: default_action(c) for c in col_detects}


def auto_strip_actions(col_detects: list) -> dict:
    """Strip all flagged columns."""
    actions = {}
    for c in col_detects:
        if c['kind'] in ('direct', 'quasi', 'text'):
            actions[c['col']] = 'strip'
        else:
            actions[c['col']] = 'keep'
    return actions


# ============================================================
# File I/O
# ============================================================

def load_file(path: Path) -> pd.DataFrame:
    ext = path.suffix.lower()
    if ext == '.csv':
        return pd.read_csv(path, dtype=str, keep_default_na=False)
    elif ext == '.tsv':
        return pd.read_csv(path, sep='\t', dtype=str, keep_default_na=False)
    elif ext in ('.xlsx', '.xls'):
        return pd.read_excel(path, dtype=str, keep_default_na=False)
    elif ext == '.json':
        return pd.read_json(path, dtype=str)
    elif ext == '.txt':
        # Treat as single text column
        text = path.read_text()
        return pd.DataFrame({'text': [text]})
    else:
        raise ValueError(f"Unsupported file format: {ext}")


def save_file(df: pd.DataFrame, path: Path):
    ext = path.suffix.lower()
    if ext == '.csv':
        df.to_csv(path, index=False)
    elif ext in ('.xlsx', '.xls'):
        df.to_excel(path, index=False)
    elif ext == '.json':
        df.to_json(path, orient='records', indent=2)
    else:
        df.to_csv(path, index=False)


def apply_sanitization(df: pd.DataFrame, col_detects: list, actions: dict) -> pd.DataFrame:
    result = df.copy()
    cols_to_drop = []

    for c in col_detects:
        col = c['col']
        action = actions.get(col, 'keep')
        if action == 'strip':
            cols_to_drop.append(col)
        elif action != 'keep':
            result[col] = result[col].apply(
                lambda v: sanitize_value(v, action, col)
            )

    if cols_to_drop:
        result = result.drop(columns=cols_to_drop)

    return result


# ============================================================
# Report
# ============================================================

LICENSE_TEXT = (
    "This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike\n"
    "4.0 International License (CC BY-NC-SA 4.0). You are free to share and adapt this\n"
    "material for non-commercial purposes, provided you give appropriate credit to\n"
    "Sharena Rice, indicate if changes were made, and distribute your contributions\n"
    "under the same license.\n"
    "Full license terms: creativecommons.org/licenses/by-nc-sa/4.0\n"
    "© 2026 Sharena Rice. All rights reserved under the above license."
)

PRECAUTIONS = [
    "This sanitized file is suitable for general analytical exploration. It is NOT authorization for any specific downstream use.",
    "Do not share outside your organization without explicit IRB or DUA authorization.",
    "Do not paste into an LLM unless your organization has a Business Associate Agreement with the model provider, or you have confirmed HIPAA-scope exclusion.",
    "Re-identification risk increases with quasi-identifiers retained. Consider further generalization before any external sharing.",
    "Small datasets (<500 records) with rare conditions can be re-identifiable even after sanitization via linkage attacks.",
    "Keep the original source file under PHI-appropriate access controls until the sanitized output has been reviewed by someone with formal privacy training.",
    "This tool performs pattern-based detection. It is NOT a formal HIPAA Expert Determination. Have a qualified privacy officer review before any regulated use.",
]


def write_report(
    input_path: Path,
    output_path: Path,
    report_path: Path,
    col_detects: list,
    text_findings: list,
    actions: dict,
    row_count: int,
    stripped_cols: list,
):
    lines = []
    lines.append("CLINICAL DATA QUICK READ — SCREENING REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}")
    lines.append(f"Source file: {input_path}")
    lines.append(f"Sanitized output: {output_path}")
    lines.append(f"Rows processed: {row_count:,}")
    lines.append(f"Columns analyzed: {len(col_detects)}")
    lines.append("")
    lines.append("IMPORTANT DISCLAIMER")
    lines.append("-" * 60)
    lines.append("This screening is pattern-based. It is NOT HIPAA Expert")
    lines.append("Determination, IRB review, or qualified privacy officer review.")
    lines.append("Use the sanitized output as a first pass, not the last word.")
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 60)
    direct = sum(1 for c in col_detects if c['kind'] == 'direct')
    quasi  = sum(1 for c in col_detects if c['kind'] == 'quasi')
    text   = sum(1 for c in col_detects if c['kind'] == 'text')
    text_hits = sum(f['count'] for f in text_findings)
    lines.append(f"Direct identifier columns:   {direct}")
    lines.append(f"Quasi-identifier columns:    {quasi}")
    lines.append(f"Free-text columns:           {text}")
    lines.append(f"Free-text identifier hits:   {text_hits}")
    lines.append(f"Columns stripped:            {len(stripped_cols)}")
    if stripped_cols:
        lines.append(f"  Stripped: {', '.join(stripped_cols)}")
    lines.append(f"Date shift applied:          {DATE_SHIFT:+d} days (consistent across dataset)")
    lines.append("")
    lines.append("PER-COLUMN FINDINGS AND ACTIONS")
    lines.append("-" * 60)
    for c in col_detects:
        action = actions.get(c['col'], 'keep')
        lines.append(f"[{c['kind'].upper()}] {c['col']}")
        if c['reasons']:
            lines.append(f"  Detection: {'; '.join(c['reasons'])}")
        lines.append(f"  Action applied: {action} — {ACTION_LABELS.get(action, action)}")
        lines.append("")
    if text_findings:
        lines.append("FREE-TEXT FINDINGS")
        lines.append("-" * 60)
        for f in text_findings:
            lines.append(f"  {f['col']} → {f['label']}: {f['count']} match(es)")
        lines.append("")
    lines.append("USE PRECAUTIONS FOR SANITIZED OUTPUT")
    lines.append("-" * 60)
    for i, p in enumerate(PRECAUTIONS, 1):
        lines.append(f"{i}. {p}")
    report_path.write_text('\n'.join(lines))


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Clinical Data Quick Read — Privacy screening tool for clinical datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('input', help='Input file (CSV, TSV, XLSX, XLS, JSON, TXT)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-r', '--report', help='Report file path')
    parser.add_argument('-m', '--mode', choices=['interactive', 'auto-safe', 'auto-strip'],
                        default='interactive', help='Sanitization mode')
    parser.add_argument('-f', '--format', choices=['same', 'csv', 'xlsx'],
                        default='same', help='Output format')
    parser.add_argument('--no-report', action='store_true', help='Skip writing report')
    args = parser.parse_args()

    print_header()

    input_path = Path(args.input)
    if not input_path.exists():
        console.print(f"[bold red]File not found:[/bold red] {input_path}")
        sys.exit(1)

    # Determine output path
    ext = input_path.suffix.lower()
    out_ext = f".{args.format}" if args.format != 'same' else ext
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_stem(input_path.stem + '_screened').with_suffix(out_ext)

    if args.report:
        report_path = Path(args.report)
    else:
        report_path = input_path.with_stem(input_path.stem + '_screening_report').with_suffix('.txt')

    # Load
    console.print(f"Loading [bold]{input_path.name}[/bold]...")
    try:
        df = load_file(input_path)
    except Exception as e:
        console.print(f"[bold red]Error loading file:[/bold red] {e}")
        sys.exit(1)

    console.print(f"Loaded {len(df):,} rows × {len(df.columns)} columns.\n")

    # Detect
    console.print("Scanning for identifiers...\n")
    col_detects = []
    for col in df.columns:
        vals = df[col].dropna().tolist()
        col_detects.append(detect_column(str(col), vals))

    text_findings = scan_free_text(df, col_detects)

    # Summary
    print_summary(col_detects, text_findings, len(df), input_path.name)
    console.print("[bold]Per-column detection:[/bold]")
    print_column_table(col_detects)
    console.print()

    if text_findings:
        console.print("[bold]Free-text PHI findings:[/bold]")
        for f in text_findings:
            console.print(f"  [cyan]{f['col']}[/cyan] → {f['label']}: [bold]{f['count']}[/bold] match(es)")
        console.print()

    # Actions
    if args.mode == 'interactive':
        actions = interactive_review(col_detects)
    elif args.mode == 'auto-safe':
        actions = auto_safe_actions(col_detects)
        console.print("[dim]Auto-safe mode: applying default actions.[/dim]\n")
    else:
        actions = auto_strip_actions(col_detects)
        console.print("[dim]Auto-strip mode: stripping all flagged columns.[/dim]\n")

    # Sanitize
    console.print("Sanitizing...\n")
    stripped_cols = [col for col, action in actions.items() if action == 'strip']
    sanitized_df = apply_sanitization(df, col_detects, actions)

    # Save
    try:
        save_file(sanitized_df, output_path)
        console.print(f"[bold green]✓[/bold green] Sanitized file written to: [bold]{output_path}[/bold]")
        console.print(f"  Columns retained: {len(sanitized_df.columns)} / {len(df.columns)}")
        if stripped_cols:
            console.print(f"  Columns stripped: {', '.join(stripped_cols)}")
    except Exception as e:
        console.print(f"[bold red]Error writing output:[/bold red] {e}")
        sys.exit(1)

    # Report
    if not args.no_report:
        write_report(input_path, output_path, report_path, col_detects,
                     text_findings, actions, len(df), stripped_cols)
        console.print(f"[bold green]✓[/bold green] Screening report written to: [bold]{report_path}[/bold]")

    # Precautions
    console.print()
    console.print(Panel(
        "\n".join(f"[dim]{i}.[/dim] {p}" for i, p in enumerate(PRECAUTIONS[:4], 1)),
        title="[bold yellow]Use precautions for the sanitized output[/bold yellow]",
        border_style="yellow",
    ))
    console.print()
    console.print(Panel(LICENSE_TEXT, title="[dim]License · CC BY-NC-SA 4.0[/dim]", border_style="dim"))
    console.print()


if __name__ == '__main__':
    main()
