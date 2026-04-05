#!/usr/bin/env bash

# Остановка скрипта при ошибках
set -e

# Убедимся, что мы в корневой папке проекта
cd "$(dirname "$0")"

echo "============================================"
echo "🔄 Обновление списков блокировок (Re-filter)"
echo "============================================"
if [ -d "Re-filter-lists/.git" ]; then
    cd Re-filter-lists
    git pull origin master || git pull origin main
    cd ..
else
    echo "⚠️ Папка Re-filter-lists не является git-репозиторием. Пропуск обновления."
fi

echo ""
echo "=========================================================="
echo "🔄 Обновление базы сообщества (domain-list-community)"
echo "=========================================================="
if [ -d "domain-list-community/.git" ]; then
    cd domain-list-community
    git pull origin master || git pull origin main
    cd ..
else
    echo "⚠️ Папка domain-list-community не является git-репозиторием. Пропуск обновления."
fi

echo ""
echo "============================================"
echo "⚙️  Сборка пересечений и генерация правил SRS"
echo "============================================"
# Очищаем старый кеш скрипта, так как git мог принести новые списки
rm -f cache/intersected_cache.json

# Запускаем скрипты для генерации CIDR (чтобы потом их подхватил сборщик SRS)
python3 scripts/fetch_tg_discord.py
python3 scripts/fetch_asn_cidrs.py

# Запускаем основной компилятор (теперь он соберёт и домены, и CIDR в SRS)
python3 scripts/compile_intersected.py

echo ""
echo "✅ Конвейер успешно завершен! Результаты лежат в папке output/"