"""Конфігурація та константи Варіанта 11."""

VARIANT_NUMBER = 11
DOMAIN_TITLE = "Облік завантаження каналів зв'язку"
DOMAIN_DESCRIPTION = (
    "Сервіс обліку вимірювань завантаження каналів зв'язку. "
    "Категорія визначає канал (internet, vpn, backup_link), "
    "value — частку використання його пропускної здатності у відсотках (0..100%), "
    "status — стан перевірки вимірювання."
)
UNIT = "percent"
THRESHOLD = 70.0
MIN_VALUE = 0.0
MAX_VALUE = 100.0
ALLOWED_STATUSES = ("new", "in_progress", "done")
