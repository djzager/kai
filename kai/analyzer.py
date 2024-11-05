import subprocess  # trunk-ignore(bandit/B404)
import threading
from io import BufferedReader, BufferedWriter
from pathlib import Path
from typing import IO, cast

from kai.jsonrpc.core import JsonRpcServer
from kai.jsonrpc.models import JsonRpcError, JsonRpcResponse
from kai.jsonrpc.streams import BareJsonStream
from kai.logging.logging import get_logger

logger = get_logger(__name__)


def log_stderr(stderr: IO[bytes]) -> None:
    for line in iter(stderr.readline, b""):
        logger.info("analyzer_lsp rpc: " + line.decode("utf-8"))


class AnalyzerLSP:
    def __init__(
        self,
        analyzer_lsp_server_binary: Path,
        repo_directory: Path,
        rules_directory: Path,
        analyzer_lsp_path: Path,
        analyzer_java_bundle_path: Path,
        dep_open_source_labels_path: Path,
    ) -> None:
        """This will start and analyzer-lsp jsonrpc server"""
        # trunk-ignore-begin(bandit/B603)
        args: list[str] = [
            str(analyzer_lsp_server_binary),
            "-source-directory",
            str(repo_directory),
            "-rules-directory",
            str(rules_directory),
            "-lspServerPath",
            str(analyzer_lsp_path),
            "-bundles",
            str(analyzer_java_bundle_path),
            "-log-file",
            "./kai-analyzer.log",
        ]
        if dep_open_source_labels_path is not None:
            args.append("-depOpenSourceLabelsFile")
            args.append(str(dep_open_source_labels_path))
        rpc_server = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # trunk-ignore-end(bandit/B603)

        self.stderr_logging_thread = threading.Thread(
            target=log_stderr, args=(rpc_server.stderr,)
        )
        self.stderr_logging_thread.start()

        self.rpc = JsonRpcServer(
            json_rpc_stream=BareJsonStream(
                cast(BufferedReader, rpc_server.stdout),
                cast(BufferedWriter, rpc_server.stdin),
            ),
            request_timeout=4 * 60,
        )
        self.rpc.start()

    def run_analyzer_lsp(
        self, label_selector: str, included_paths: list[str], incident_selector: str
    ) -> JsonRpcResponse | JsonRpcError | None:
        request_params = {
            "label_selector": label_selector,
            "included_paths": included_paths,
            "incident_selector": incident_selector,
        }

        if label_selector is not None:
            request_params["label_selector"] = label_selector

        if included_paths is not None:
            request_params["included_paths"] = included_paths

        if incident_selector is not None:
            request_params["incident_selector"] = incident_selector

        logger.debug("Sending request to analyzer-lsp")
        logger.debug("Request params: %s", request_params)

        return self.rpc.send_request(
            "analysis_engine.Analyze",
            params=[request_params],
        )

    def stop(self) -> None:
        self.stderr_logging_thread.join()
        self.rpc.stop()
