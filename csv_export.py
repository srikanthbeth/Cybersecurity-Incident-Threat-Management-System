import csv
import io
import json
from datetime import date, datetime
from enum import Enum
from typing import Any

from fastapi.responses import StreamingResponse


def _csv_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)

    return value


def report_to_csv(report: dict, filename: str) -> StreamingResponse:
    items = report.get("items")

    if isinstance(items, list):
        rows = items
    else:
        rows = [
            {"metric": key, "value": value}
            for key, value in report.items()
        ]

    buffer = io.StringIO(newline="")

    if rows:
        fieldnames = list(
            dict.fromkeys(
                key
                for row in rows
                if isinstance(row, dict)
                for key in row.keys()
            )
        )

        if not fieldnames:
            fieldnames = ["value"]

        writer = csv.DictWriter(
            buffer,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()

        for row in rows:
            if isinstance(row, dict):
                writer.writerow(
                    {key: _csv_value(value) for key, value in row.items()}
                )
            else:
                writer.writerow({"value": _csv_value(row)})
    else:
        writer = csv.writer(buffer)
        writer.writerow(["message"])
        writer.writerow(["No report records found"])

    buffer.seek(0)

    safe_filename = "".join(
        char for char in filename if char.isalnum() or char in "-_."
    )

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}.csv"'
        },
    )
