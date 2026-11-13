# portscan — Go TCP Connect Scanner

Высокопроизводительный пакет для конкурентного сканирования TCP-портов.

# Установка
go get github.com/vizual4/portscan

# Быстрый старт
Ниже приведен базовый пример использования сканера для проверки списка портов на хосте:
```Go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/example/portscan"
)

func main() {
	// 1. Создаем сканер с настройками (конкурентность 100, таймаут 500мс)
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	// 2. Формируем спецификацию портов (например, веб-порты)
	spec, err := portscan.Ports(22, 80, 443, 8080)
	if err != nil {
		panic(err)
	}

	// 3. Задаем контекст с общим таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 4. Запускаем сканирование хостов
	results, err := scanner.Scan(ctx, []string{"127.0.0.1", "example.com"}, spec)
	if err != nil {
		panic(err)
	}

	// 5. Читаем результаты из канала по мере их поступления
	for res := range results {
		fmt.Printf("Host: %-12s | Port: %-5d | State: %-10s | Duration: %v\n",
			res.Host, res.Port, res.State, res.Duration)
	}
}
```
## Устройство публичного API

<Scanner> - Главный управляющий объект. Потокобезопасен, допускает многократное использование.

<Result> - Структура, содержащая детальный результат проверки конкретного порта (Host, IP, Port, State, Duration, Err).

<State> - Типизированное состояние порта.

<PortSpec> - Неизменяемая спецификация набора уникальных портов для сканирования.

<Option> - Функция-модификатор для конфигурации сканера.

<Resolver> - Интерфейс, абстрагирующий DNS-резолвер.


*Конструктор и опции*
<func New(opts ...Option) (*Scanner, error)>

Доступные функциональные опции:

<WithConcurrency(n int)> — ограничивает максимальное число параллельных TCP-соединений (по умолчанию: 100).

<WithConnectTimeout(d time.Duration)> — задает таймаут для каждой индивидуальной попытки подключения (по умолчанию: 2s).

<WithResolver(r Resolver)> — позволяет передать кастомный DNS-резолвер.

*Запуск сканирования*
<func (s *Scanner) Scan(ctx context.Context, hosts []string, spec PortSpec) (<-chan Result, error)>
Принимает контекст (для отмены), список хостов (IP или доменные имена) и спецификацию портов.

Возвращает неблокирующий канал результатов (<-chan Result), который автоматически закрывается по завершении сканирования.

*Управление портами*
Пакет поддерживает три гибких способа задания портов с автоматической дедупликацией и сортировкой:

1. Список отдельных портов: <portscan.Ports(80, 443, 8080)>

2. Диапазон портов (включая авторазворот обратных диапазонов): <portscan.PortRange(1, 1024)>

3. Объединение наборов: <portscan.Merge(spec1, spec2)>

## Запуск тестов (с проверкой состояния гонок)
```bash
go test -v -race ./...