# Файл tests/Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Moscow

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    valgrind \
    libc6-dbg

RUN apt-get install -y libpcap-dev

# Рабочая директория
WORKDIR /app

# Копируем только необходимые файлы
COPY cmake/ /app/cmake/
COPY third_party/ /app/third_party/
COPY src/ /app/src/
COPY include/ /app/include/
COPY tests/ /app/tests/
COPY CMakeLists.txt /app/

# Собираем проект
RUN cmake . -DCMAKE_BUILD_TYPE=Debug && cmake --build . -- -j$(nproc)

# Переходим в каталог с тестами
WORKDIR /app/tests
# Запускаем тесты с valgrind
CMD ["valgrind", "--leak-check=full", "--show-leak-kinds=all", "--track-origins=yes", "./runTests"]
# CMD ["tail", "-f", "CMakeLists.txt"]
