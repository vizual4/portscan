package portscan

import (
	"fmt"
	"sort"
)

// PortSpec описывает неизменяемый набор уникальных портoв для сканирования.
type PortSpec struct {
	ports []uint16
}

// Ports создает PortSpec из произвольного набора отдельных портов.
func Ports(ports ...uint16) (PortSpec, error) {
	seen := make(map[uint16]struct{}, len(ports))
	result := make([]uint16, 0, len(ports))

	for _, p := range ports {
		if p == 0 {
			return PortSpec{}, fmt.Errorf("portscan: port 0 is not valid")
		}
		if _, ok := seen[p]; ok {
			continue // Исключаем дубликаты
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}

	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return PortSpec{ports: result}, nil
}

// PortRange создает PortSpec из инклюзивного диапазона [from, to].
func PortRange(from, to uint16) (PortSpec, error) {
	if from == 0 || to == 0 {
		return PortSpec{}, fmt.Errorf("portscan: port 0 is not valid")
	}

	if from > to {
		from, to = to, from
	}

	ports := make([]uint16, 0, int(to-from)+1)
	for p := from; p <= to; p++ {
		ports = append(ports, p)
	}

	return PortSpec{ports: ports}, nil
}

// Merge объединяет несколько PortSpec в единую коллекцию с удалением дубликатов.
func Merge(specs ...PortSpec) PortSpec {
	seen := make(map[uint16]struct{})
	var result []uint16

	for _, spec := range specs {
		for _, p := range spec.ports {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				result = append(result, p)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return PortSpec{ports: result}
}

// Len возвращает количество уникальных портов.
func (ps PortSpec) Len() int {
	return len(ps.ports)
}

// Ports возвращает копию среза портов для инкапсуляции внутреннего состояния.
func (ps PortSpec) Ports() []uint16 {
	out := make([]uint16, len(ps.ports))
	copy(out, ps.ports)
	return out
}
