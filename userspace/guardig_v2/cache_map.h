
#ifndef USERSPACE_GUARDIG_V2_CACHE_MAP_H_
#define USERSPACE_GUARDIG_V2_CACHE_MAP_H_

#include <unordered_map>
#include <functional>
#include <utility>
#include "trace.h"

using namespace std;

template <class Key, class Value, class Hash = hash<Key>>
class cache_map {
public:
	cache_map(uint32_t max_size);

	Value *get(Key key);
	Value *add(Key &key, Value &val);
	void remove(Key key);
	void reset_cache();
	size_t size();

	typename unordered_map<Key, Value, Hash>::iterator begin();
	typename unordered_map<Key, Value, Hash>::iterator end();
	typename unordered_map<Key, Value, Hash>::iterator erase(const typename unordered_map<Key, Value, Hash>::iterator position);

	uint32_t m_max_table_size;
	unordered_map<Key, Value, Hash> m_map;

	bool m_cache_valid;
	Key m_last_accessed_key;
	Value *m_last_accessed_value;
};

#include "cache_map.tpp"

#endif /* USERSPACE_GUARDIG_V2_CACHE_MAP_H_ */
