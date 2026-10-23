"""
TREMOR — FastAPI application factory with lifespan management.

Entry point: `uvicorn app.main:create_app --factory`
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from app.clock import SystemClock
from app.config import settings
from app.core.engine import DetectionEngine
from app.core.templates import TemplateMiner
from app.db.repository import AlertRepository, Database
from app.ingest.parser import parse_line
from app.ingest.tailer import Tailer
from app.sinks.base import SinkWorker
from app.sinks.ws import ws_manager


def _configure_logging() -> None:
    """Configure structlog for JSON output."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
            if settings.log_level == "DEBUG"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _build_sinks() -> list[SinkWorker]:
    """Build the sink workers based on configuration."""
    workers: list[SinkWorker] = []

    if settings.dry_run:
        from app.sinks.dryrun import DryRunSink
        workers.append(SinkWorker(DryRunSink()))
    else:
        if settings.sns_topic_arn:
            from app.sinks.sns import SNSSink
            workers.append(SinkWorker(SNSSink(
                topic_arn=settings.sns_topic_arn,
                endpoint_url=settings.aws_endpoint_url or None,
            )))
        if settings.cw_log_group:
            from app.sinks.cloudwatch import CloudWatchSink
            workers.append(SinkWorker(CloudWatchSink(
                log_group=settings.cw_log_group,
                log_stream=settings.cw_log_stream,
                namespace=settings.cw_namespace,
                endpoint_url=settings.aws_endpoint_url or None,
            )))

    return workers


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Startup: initialize DB, sinks, template miner, detection engine, tailer.
    Shutdown: stop tailer, flush sinks, persist state.
    """
    log = structlog.get_logger()
    await log.ainfo("tremor.starting", version="0.1.0", demo_mode=settings.demo_mode)

    clock = SystemClock()

    # 1. Database
    db = Database(settings.database_url)
    await db.init()
    alert_repo = AlertRepository(db)
    app.state.db = db
    app.state.alert_repo = alert_repo
    await log.ainfo("tremor.db.ready", url=settings.database_url)

    # 2. Template Miner
    miner = TemplateMiner(clock, warmup_seconds=settings.warmup_seconds)
    app.state.miner = miner

    # 3. Detection Engines (one per service, created dynamically)
    engines: dict[str, DetectionEngine] = {}
    app.state.engines = engines

    # 4. Sink workers
    sink_workers = _build_sinks()
    for w in sink_workers:
        await w.run()
    app.state.sink_workers = sink_workers
    await log.ainfo("tremor.sinks.ready", count=len(sink_workers))

    # 5. WebSocket manager
    await ws_manager.start()
    app.state.ws_manager = ws_manager

    # 6. Ingestion queue & pipeline task
    raw_queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue(maxsize=10_000)

    # Start tailers (one per configured log path)
    tailers: list[Tailer] = []
    for path in settings.log_file_paths:
        service = path.rsplit("/", 1)[-1].replace(".log", "").replace(".json", "")
        tailer = Tailer(
            path=path,
            service=service,
            queue=raw_queue,
            clock=clock,
            start_pos=settings.tail_start,
            poll_ms=settings.poll_interval_ms,
        )
        await tailer.run()
        tailers.append(tailer)
    app.state.tailers = tailers
    await log.ainfo("tremor.tailers.ready", paths=settings.log_file_paths)

    # 7. Pipeline consumer task: reads from queue, parses, mines, detects, sinks
    async def pipeline_consumer() -> None:
        """The core async loop that wires Tailer → Parser → Miner → Engine → Sinks."""
        next_tick = clock.now() + 1.0

        while True:
            try:
                # Process lines from the queue (non-blocking with timeout)
                try:
                    service, raw_line = await asyncio.wait_for(raw_queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    # No lines available — check if a tick is due
                    now = clock.now()
                    if now >= next_tick:
                        await _run_tick(engines, next_tick, sink_workers, alert_repo)
                        next_tick += 1.0
                    continue

                now = clock.now()

                # Run any pending ticks before processing this line
                while now >= next_tick:
                    await _run_tick(engines, next_tick, sink_workers, alert_repo)
                    next_tick += 1.0

                # Parse
                event = parse_line(raw_line, default_service=service)
                if event is None:
                    continue

                svc = event.service

                # Mine template
                tid = miner.add_message(event.message, service=svc, ts=event.ts)
                is_new = miner.is_new(tid)

                # Get or create engine for this service
                if svc not in engines:
                    engines[svc] = DetectionEngine(settings, service=svc)
                engines[svc].observe(event, now, template_id=tid, is_new_template=is_new)

            except asyncio.CancelledError:
                break
            except Exception as e:
                await log.aerror("pipeline.error", error=str(e))

    pipeline_task = asyncio.create_task(pipeline_consumer())
    app.state.pipeline_task = pipeline_task
    await log.ainfo("tremor.pipeline.started")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────
    await log.ainfo("tremor.shutting_down")

    # Stop pipeline
    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        pass

    # Stop tailers
    for tailer in tailers:
        await tailer.stop()

    # Stop WebSocket manager
    await ws_manager.stop()

    # Stop sinks (with flush deadline)
    for w in sink_workers:
        await w.stop()

    # Close database
    await db.close()

    await log.ainfo("tremor.stopped")


async def _run_tick(
    engines: dict[str, DetectionEngine],
    now: float,
    sink_workers: list[SinkWorker],
    alert_repo: AlertRepository,
) -> None:
    """Run a tick on all engines, broadcast results, and push alerts to sinks."""
    for svc, engine in engines.items():
        result = engine.tick(now)

        # Broadcast tick data to WebSocket clients
        await ws_manager.broadcast_tick(result.tick.to_dict())

        # Process any alerts
        for alert in result.alerts:
            alert_dict = alert.to_dict()

            # Broadcast to WebSocket
            await ws_manager.broadcast_alert(alert_dict)

            # Persist to database
            try:
                await alert_repo.save(alert)
            except Exception:
                pass  # Don't crash the pipeline on DB errors

            # Push to AWS sinks
            for w in sink_workers:
                await w.enqueue(alert_dict)


def create_app() -> FastAPI:
    """Application factory."""
    _configure_logging()

    app = FastAPI(
        title="TREMOR",
        description="Trend-aware Real-time Event Monitoring & Outlier Response",
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Prometheus metrics ────────────────────────────────────────────
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # ── Routers ──────────────────────────────────────────────────────
    from app.api.routes import router as api_router

    app.include_router(api_router)

    return app
