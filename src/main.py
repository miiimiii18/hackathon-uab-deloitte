"""Punto de entrada del proyecto."""
import os

from dotenv import load_dotenv

load_dotenv()


def main() -> None:
    data_path = os.getenv("DATA_PATH", "data/")
    print(f"🚀 Proyecto en marcha. Datos en: {data_path}")


if __name__ == "__main__":
    main()
