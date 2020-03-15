#pragma once

template<class T, class S>
inline
T force_cast(S op) {
	return reinterpret_cast<T>(op);
}