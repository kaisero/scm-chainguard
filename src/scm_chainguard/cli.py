"""CLI entry point using typer."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from scm_chainguard import __version__
from scm_chainguard.config import ConfigError, load_config
from scm_chainguard.logging_setup import configure_logging

app = typer.Typer(
    name="scm-chainguard",
    help="Manage Chrome-trusted CA certificates in Palo Alto Strata Cloud Manager.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"scm-chainguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to YAML config file.",
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file",
        help="Write logs to file.",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """scm-chainguard: Chrome-trusted CA certificate management for SCM."""
    configure_logging(debug=debug, log_file=log_file)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["debug"] = debug


def _get_config(ctx: typer.Context) -> "ScmConfig":  # noqa: F821
    try:
        return load_config(ctx.obj.get("config_path"))
    except ConfigError as e:
        typer.echo(f"Configuration error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def fetch(
    ctx: typer.Context,
    include_intermediates: bool = typer.Option(
        False,
        "--include-intermediates",
        "-i",
        help="Also fetch intermediate certificates (default: roots only).",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Override output directory.",
    ),
) -> None:
    """Download Chrome-trusted CA certificates from CCADB."""
    from scm_chainguard.pipeline import run_fetch
    from dataclasses import replace

    config = _get_config(ctx)
    if output_dir:
        config = replace(config, output_dir=str(output_dir))

    result = run_fetch(config, include_intermediates)
    typer.echo(f"Root certificates saved to: {result['roots']}")
    if "intermediates" in result:
        typer.echo(f"Intermediate certificates saved to: {result['intermediates']}")


@app.command()
def compare(
    ctx: typer.Context,
    include_intermediates: bool = typer.Option(
        False,
        "--include-intermediates",
        "-i",
        help="Also compare intermediate certificates.",
    ),
) -> None:
    """Compare local certificates against SCM certificate stores."""
    from scm_chainguard.pipeline import run_compare

    config = _get_config(ctx)
    results = run_compare(config, include_intermediates)

    for label, comp in results.items():
        typer.echo(f"\n{'=' * 60}")
        typer.echo(
            f"{label.upper()}: {len(comp.present)} present, "
            f"{len(comp.missing)} missing (of {comp.total_local})"
        )
        typer.echo(f"{'=' * 60}")

        for cert, scm_name in sorted(comp.present, key=lambda x: x[0].common_name):
            typer.echo(f"  [OK]      {cert.common_name:<50s} (SCM: {scm_name})")

        for cert in sorted(comp.missing, key=lambda c: c.common_name)[:50]:
            typer.echo(f"  [MISSING] {cert.common_name:<50s} ({cert.filename})")
        if len(comp.missing) > 50:
            typer.echo(f"  ... and {len(comp.missing) - 50} more")


@app.command()
def sync(
    ctx: typer.Context,
    include_intermediates: bool = typer.Option(
        False,
        "--include-intermediates",
        "-i",
        help="Also sync intermediate certificates.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "-n",
        help="Show what would be done without making changes.",
    ),
) -> None:
    """Import missing certificates into SCM and add as trusted roots."""
    from scm_chainguard.pipeline import run_sync

    config = _get_config(ctx)
    results = run_sync(config, include_intermediates, dry_run)

    for label, sr in results.items():
        prefix = "[DRY-RUN] " if sr.dry_run else ""
        typer.echo(
            f"\n{label.upper()} sync: "
            f"{prefix}{len(sr.imported)} imported, "
            f"{len(sr.skipped)} skipped, "
            f"{len(sr.failed)} failed"
        )
        if sr.trusted_roots_added:
            typer.echo(
                f"  {prefix}{len(sr.trusted_roots_added)} added to trusted root CA list"
            )
        for name, error in sr.failed:
            typer.echo(f"  FAILED: {name} — {error}", err=True)

    total_failed = sum(len(sr.failed) for sr in results.values())
    if total_failed:
        raise typer.Exit(1)


@app.command()
def cleanup(
    ctx: typer.Context,
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "-n",
        help="Show what would be removed without making changes.",
    ),
) -> None:
    """Remove expired CG_-managed certificates from SCM trusted roots and delete them."""
    from scm_chainguard.pipeline import run_cleanup

    config = _get_config(ctx)
    result = run_cleanup(config, dry_run)

    prefix = "[DRY-RUN] " if result.dry_run else ""
    if not result.deleted and not result.failed:
        typer.echo("No expired CG_-managed certificates found.")
        return

    typer.echo(
        f"\n{prefix}Cleanup: "
        f"{len(result.deleted)} deleted, "
        f"{len(result.removed_from_trusted)} removed from trusted root CA list, "
        f"{len(result.failed)} failed"
    )
    for name in result.deleted:
        typer.echo(f"  {prefix}DELETED: {name}")
    for name, error in result.failed:
        typer.echo(f"  FAILED: {name} — {error}", err=True)

    if result.failed:
        raise typer.Exit(1)


@app.command()
def run(
    ctx: typer.Context,
    include_intermediates: bool = typer.Option(
        False,
        "--include-intermediates",
        "-i",
        help="Include intermediate certificates in all stages.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "-n",
        help="Dry-run the sync stage.",
    ),
) -> None:
    """Full pipeline: fetch -> compare -> sync."""
    from scm_chainguard.pipeline import run_full_pipeline

    config = _get_config(ctx)
    result = run_full_pipeline(config, include_intermediates, dry_run)

    sync_results = result.get("sync", {})
    for label, sr in sync_results.items():
        prefix = "[DRY-RUN] " if sr.dry_run else ""
        typer.echo(
            f"\n{label.upper()}: "
            f"{prefix}{len(sr.imported)} imported, "
            f"{len(sr.skipped)} skipped, "
            f"{len(sr.failed)} failed"
        )

    total_failed = sum(len(sr.failed) for sr in sync_results.values())
    if total_failed:
        raise typer.Exit(1)
    typer.echo("\nPipeline complete.")
