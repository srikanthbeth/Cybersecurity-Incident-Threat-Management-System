from datetime import date
from pydantic import BaseModel, ConfigDict, model_validator


class ReportDateRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_date: date
    end_date: date

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.start_date > self.end_date:
            raise ValueError("start_date must be on or before end_date")

        if (self.end_date - self.start_date).days > 366:
            raise ValueError("Report date range cannot exceed 366 days")

        return self
