"""Командний інтерфейс локального та мережевого аналізу NVD."""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER


class _ArgumentParser(argparse.ArgumentParser):
    """Спрямувати помилки аргументів у stderr українською мовою."""

    def error(self, message: str) -> None:
        self.exit(
            2,
            "Помилка аргументів: потрібен --cve у форматі CVE-РРРР-НННН; "
            "дозволено необов'язковий --input ШЛЯХ. Довідка: --help.\n",
        )

    def format_help(self) -> str:
        return super().format_help().replace("usage:", "Використання:", 1)


def _cve_argument(value: str) -> str:
    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value) is None:
        raise argparse.ArgumentTypeError("Некоректний формат CVE.")
    return value


def load_response(path: str | Path) -> object:
    """Прочитати локальну UTF-8 JSON-відповідь без мережевих операцій."""
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv: list[str] | None = None) -> int:
    """Обробити аргументи, вивести один JSON-звіт або безпечну помилку."""
    parser = _ArgumentParser(
        description="Аналіз запису NVD за індивідуальним правилом CVSS v3.1.",
        add_help=False,
        allow_abbrev=False,
    )
    arguments = parser.add_argument_group("Параметри")
    arguments.add_argument("-h", "--help", action="help", help="показати довідку")
    arguments.add_argument(
        "--cve",
        required=True,
        type=_cve_argument,
        metavar="CVE",
        help="ідентифікатор CVE",
    )
    arguments.add_argument(
        "--input", type=Path, metavar="ШЛЯХ", help="локальна UTF-8 JSON-відповідь"
    )
    args = parser.parse_args(argv)
    try:
        analysis.validate_variant(VARIANT_NUMBER)
    except ValueError:
        print(
            "Помилка: номер варіанта має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    try:
        payload = (
            load_response(args.input)
            if args.input is not None
            else api_client.fetch_response(args.cve)
        )
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except requests.exceptions.JSONDecodeError:
        message = "NVD повернув некоректний JSON."
    except requests.Timeout:
        message = "Перевищено час очікування відповіді NVD."
    except requests.ConnectionError:
        message = "Не вдалося встановити захищене з'єднання з NVD."
    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None
        message = f"Неочікуваний HTTP-статус NVD: {status}."
    except requests.RequestException:
        message = "Не вдалося отримати відповідь NVD."
    except json.JSONDecodeError:
        message = "Локальний файл містить некоректний JSON."
    except UnicodeError:
        message = "Локальний файл має бути закодований у UTF-8."
    except OSError:
        message = "Не вдалося прочитати локальний файл."
    except ValueError:
        message = "Структура або значення даних не відповідають вимогам NVD чи запитаному CVE."
    else:
        print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
        return 0
    print(f"Помилка: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
