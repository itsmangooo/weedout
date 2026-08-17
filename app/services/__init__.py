"""Application services: the layer between HTTP handlers and the database.

Route handlers stay thin — validate input, call a service, render a template.
Business rules live here so the scheduled jobs can reuse them unchanged.
"""
