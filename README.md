# Что это?
Invaders Must Die - это ~~альбом группы Prodigy 2009 года выпуска~~ ещё одна IDS для Linux, которая позволяет Вам замониторить потенциально нелегитимные события в сетевом трафике на интерфейсе при помощи YARA правил.

Внутри есть три компонента [invaders-must-die](#invaders-must-die), [stand-up](#stand-up), [omen](#omen).
[invaders-must-die](#invaders-must-die) - Сенсор, который слушает трафик на заданном сетевом интерфейсе и анализирует его при помощи YARA правил. 
[stand-up](#stand-up) - Сервис, отвечающий за приём и передачу событий безопасности от сенсора.
[Omen](#Omen) - Веб приложение, которое отображает нелегитимные события, принимая их от [Stand Up](#Stand Up).

# Преднастройка

Скопируйте репозиторий:

```bash
git clone https://github.com/Argendo/invaders_must_die.git
```

Перейдите в папку проекта и установите gRPC:

```bash
$ export MY_INSTALL_DIR=$HOME/.local
export PATH="$MY_INSTALL_DIR/bin:$PATH"
sudo apt install -y build-essential autoconf libtool pkg-config cmake
git clone --recurse-submodules -b v1.60.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
sh
cd grpc
mkdir -p cmake/build
pushd cmake/build
cmake -DgRPC_INSTALL=ON \
      -DgRPC_BUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
      ../..
make -j 4
make install
popd
```

В файле *common.cmake* измените строку:

```bash
add_subdirectory(third-party/grpc ${CMAKE_CURRENT_BINARY_DIR}/grpc EXCLUDE_FROM_ALL)
```

на:

```bash
add_subdirectory(полный_путь_к_папке_проекта/grpc ${CMAKE_CURRENT_BINARY_DIR}/grpc EXCLUDE_FROM_ALL)
```

сохраните файл.
# Запуск
## invaders-must-die

### Сборка

Устанавливаем необходимые библиотеки:

```bash
libpcap-dev libsystemd-dev libyara-dev libpcap-dev libgrpc-dev
```

Создаём директорию для сборки и конфигурируем `Cmake`:

```bash
mkdir build
cd build
cmake ..
```

Собираем проект:

```bash
make
```

Пример использования сенсора с указанием интерфейса, файла с правилами и адреса сервиса для отправки событий:

```bash
./libpcap-demo -i ens33 -r example.yar -h localhost:50051
```

## stand-up

### Запуск

#### Локально
Для начала необходимо указать параметры подключения к базе данных, при помощи файла *config.py*.

Далее необходимо скомпилировать файлы описания протокола protobuf в классы Python при помощи:

```bash
python -m grpc_tools.protoc -I=proto --python_out=. --pyi_out=. --grpc_python_out=. proto/alert.proto
```

Запуск сервиса:

```bash
python3 app.py
```

После чего сервис станет доступен по порту `50051`.

#### или с помощью Docker

Для запуска сервиса необходимо сконфигурировать настройки подключения к БД в файле [config.py](config.py), после чего запустить Docker-образы с помощью команды:

```bash
sudo docker-compose up -d
```

После чего сервис станет доступен по порту `50051`.

## omen

### Запуск

#### Локально

Для начала необходимо проинициализировать sqlite3 БД с помощью команды:

```bash
python3 init_db.py
```

Компилируем protobuf файлы в классы Python:

```bash
python -m grpc_tools.protoc -I=proto --python_out=. --pyi_out=. --grpc_python_out=. proto/alert.proto
```

В приложении используется переменная окружения GRPC_HOST, поэтому необходимо её обозначить:

```bash
export GRPC_HOST="ip_машины_на_которой_развернут_invaders_mush_die:50051"
```

Запускаем приложение:

```bash
python3 app.py
```

После чего приложение будет доступно по адресу `localhost:5000`.

#### или с помощью Docker

Перед запуском в файле *compose.yml* необходимо задать переменной GRPC_HOST значение вида: `ip_машины_на_которой_развернут_invaders_mush_die:50051`

Запуск с помощью `docker-compose`:

```bash
sudo docker-compose up -d
```

После чего приложение будет доступно по адресу `localhost:5000`.
