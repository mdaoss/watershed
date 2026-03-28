// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

const maxUint32Val = 4_294_967_295

// noOverflowConvEndpointIDoSecurityID -  предотваращает переполнение uint32 при конвертации int64 в uint32
// Функция getIdentityLabels ищет метки (labels) безопасности по идентификатору (ID).
// Если значение endpoint.Identity.ID отрицательное или превышает максимальное значение для uint32 (которое равно 4 294 967 295),
// произойдет переполнение, что может привести к сбоям в работе или нарушению сетевой политики.
// т.к  типы принадлежат сторонним библиотекам,  добавляем механизм предотвращени переполнения
func noOverflowConvEndpointIDoSecurityID(id int64) uint32 {
	if id < 0 || id > maxUint32Val {
		panic("unpredicted behaviour: uint32 overflow due to endpoint ID to securityuID conversion")
	}
	return uint32(id)
}
