# w-releases

Репозиторий собирает поставки в ZIP и устанавливает их общим релизом. Имена и
состав выбирает команда: это могут быть сервисы, статика или другие готовые файлы.
Один релиз содержит один или несколько ZIP; версии у поставок могут различаться.

Сначала настрой проект через соседний [w-tooling](../w-tooling/README.md).
В Codex вызови `$integrate-distribution` и укажи репозиторий, способ сборки
и установки. Агент подготовит скрипт поставки и проверит его.

## Выпустить файловую поставку

Пример для репозитория `search-worker` с готовой сборкой в `dist/`.
Команды выполняются из `w-releases`. В `--source` укажи полный путь к сборке:

```sh
./release init search-worker
./release pack search-worker --source /absolute/path/search-worker/dist --version 1.0.0 \
  --commit "$(git -C ../search-worker rev-parse HEAD)" --set rollout-1
./release release rollout-1 --preflight-only
./release release rollout-1 --yes
```

`init` нужен один раз. Он создаёт `distributions/search-worker/` со скриптом
установки. `pack` собирает `rollout-1/search-worker.zip`; туда же можно упаковать
другие поставки. `preflight-only` проверяет готовность, `--yes` запускает установку.
Для следующего выпуска задай новую версию и новый `--set`.

Готовый скрипт копирует файлы в `.runtime/search-worker/versions/` и переключает
ссылку `current`. Запуск приложения, Docker или внешний деплой добавляются
в собственный `deploy.sh`. Скилл помогает с этой частью;
[контракт поставки](docs/distribution-contract.md) описывает четыре нужные фазы.

## Проверить результат

```sh
./release inspect RUN_ID
```

Команда установки печатает `RUN_ID`. После начала установки отчёт и подробности
лежат в `.state/runs/RUN_ID/`. При ошибке скрипт релиза вызывает откат начатых
поставок в обратном порядке. Поставки, которых нет в наборе, сохраняют свои версии.

Пути и таймауты задаются в `config/project.json`. Проверка самого инструмента:
`bash tests/run-release.test.sh`. Свой `deploy.sh` проверь в окружении команды.
