
template <class Key, class Value, class Hash>
cache_map<Key,Value,Hash>::cache_map(uint32_t max_size)
{
	m_max_table_size = max_size;
	m_cache_valid = false;
}


template <class Key, class Value, class Hash>
Value *cache_map<Key,Value,Hash>::add(Key &key, Value &val)
{
	auto it = m_map.find(key);

	if(it == m_map.end())
	{
		if (m_map.size() >= m_max_table_size)
		{
			TRACE_DEBUG("table is full");
			return NULL;
		}

		//threadinfo.compute_program_hash();

		return &(m_map.emplace(key, val).first->second);
	}
	else
	{
		it->second = val;
		return &(it->second);
	}
}


template <class Key, class Value, class Hash>
Value *cache_map<Key,Value,Hash>::get(Key key)
{
	//
	// Try looking up in our simple cache
	//
	if(m_cache_valid && key == m_last_accessed_key)
	{
		return m_last_accessed_value;
	}

	auto it = m_map.find(key);
	if (it != m_map.end())
	{
		m_last_accessed_key = key;
		m_last_accessed_value = &(it->second);
		m_cache_valid = true;
		return &(it->second);
	}
	else
	{
		return NULL;
	}
}


template <class Key, class Value, class Hash>
void cache_map<Key,Value,Hash>::remove(Key key)
{
	if(key == m_last_accessed_key)
	{
		m_cache_valid = false;
	}

	auto it = m_map.find(key);
	if (it != m_map.end())
	{
		m_map.erase(it);
	}
	else
	{
		return;
	}
}


template <class Key, class Value, class Hash>
void cache_map<Key,Value,Hash>::reset_cache()
{
	m_cache_valid = false;
}


template <class Key, class Value, class Hash>
typename unordered_map<Key, Value, Hash>::iterator cache_map<Key,Value,Hash>::begin()
{
	return m_map.begin();
}


template <class Key, class Value, class Hash>
typename unordered_map<Key, Value, Hash>::iterator cache_map<Key,Value,Hash>::end()
{
	return m_map.end();
}

